# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
RISC-V flash loader binary adapter.

Adapts pre-compiled flash loader binary blobs for use with pyOCD's Flash
base class, translating pyOCD's Flash interface to RISC-V calling
conventions:

    a0-a3 (x10-x13)  -- args / return value
    ra (x1)           -- return address -> ebreak
    ebreak            -- return detection (hart enters debug mode)

Supports two init conventions driven by algo dict keys:
    init_params: RAM-pointer-based (new) -- a0=flash_base, a1=params_ptr
    init_args:   Register-passed (legacy) -- a0-aN from list

Memory layout in working RAM (derived from working_ram_start/size):
    +0:           [algo blob .text]     <- p_filesz bytes
    +p_filesz:    [.bss zeros]         <- bss_size bytes (if present)
    +p_memsz:     ebreak (0x00100073)  <- ra points here
    +p_memsz+4:   [init_params]        <- if present
    +aligned:     [page buffer]        <- for flash program data
    ...
    +ram_size:    stack top            <- begin_stack

Algo dict keys:
    Required:
        working_ram_start  - Start of executable RAM for blob loading
        working_ram_size   - Size of working RAM
        instructions       - Blob binary (list of 32-bit words)
        pc_init            - flash_init offset (relative to blob start)
        pc_erase_sector    - flash_erase offset
        pc_program_page    - flash_program offset
        pc_unInit          - flash_deinit offset
        page_size          - Flash page size in bytes
        sector_size        - Flash sector size in bytes

    Convention keys (optional, drive calling convention translation):
        flash_base         - Enables offset-based erase/program (a0=base)
        init_params        - List of uint32 to write to RAM, pass ptr in a1
        init_args          - Legacy: list of values for flash_init (a0-aN)
        bss_size           - .bss size in bytes (adapter zeros this region)
        init_timeout       - Override timeout for flash_init (seconds)
"""

import logging
from typing import Dict, List, Optional, Sequence, Tuple

from ...core import exceptions
from ...core.target import Target
from ...flash.builder import FlashBuilder, FlashProgramFailure, _stub_progress
from ...flash.flash import Flash
from ...utility.mask import align_up
from ...utility.timeout import Timeout
from ..dm.registers import Command, RiscvRegno
from ..instructions import RiscvInstr

LOG = logging.getLogger(__name__)


# Register-load scratch area: [a0][a1][a2][a3][ra][dpc] = 6 GPR/DPC slots.
_REG_SCRATCH_BYTES = 6 * 4
# RISC-V LW/SW natural alignment for buffer placement.
_WORD_ALIGN = 16
# Default stack guard between the batch buffer and begin_stack. Flash algo
# stack depth is not encoded in the algo dict; this guard reserves space
# for typical compiler-generated call chains so the stack cannot overrun
# into the batch buffer. Targets may override via algo dict key
# 'stack_guard_bytes'.
_STACK_GUARD_BYTES_DEFAULT = 1024


class RiscvFlashAdapter(Flash):
    """RISC-V flash loader binary adapter.

    Adapts pre-compiled flash loader blobs to pyOCD's Flash interface.
    Convention translation is driven by algo dict keys (init_params,
    init_args, flash_base, bss_size) so targets only provide blob + params.
    """

    def __init__(self, target: Target, flash_algo: Dict) -> None:
        """Initialize RISC-V flash algorithm.

        Derives memory layout from working_ram_start/working_ram_size:
            load_address     = working_ram_start
            page_buffers[0]  = working_ram_start + align_up(blob+ebreak, 16)
            begin_stack      = working_ram_start + working_ram_size

        Converts pc_* from blob-relative offsets to absolute addresses.
        Appends ebreak footer after blob for return detection.

        Args:
            target: RISCVTarget instance
            flash_algo: Algorithm dict with working_ram_start/size, instructions,
                pc_* offsets, page_size, sector_size, and optional convention keys.
        """
        algo = dict(flash_algo)

        ram_start = algo['working_ram_start']
        ram_size = algo['working_ram_size']

        # Set defaults
        algo.setdefault('static_base', 0)
        algo.setdefault('analyzer_supported', False)
        algo.setdefault('end_stack', None)
        algo.setdefault('min_program_length', 4)

        # Compute load address from working RAM start
        algo['load_address'] = ram_start

        # Convert pc_* from offsets to absolute addresses
        for pc_key in ('pc_init', 'pc_erase_sector', 'pc_program_page',
                       'pc_eraseAll', 'pc_unInit'):
            if pc_key in algo:
                algo[pc_key] = ram_start + algo[pc_key]

        # Build final instructions: [.text] [.bss zeros] [ebreak] [init_params]
        blob_instructions = list(algo['instructions'])
        blob_size_bytes = len(blob_instructions) * 4
        bss_size = algo.get('bss_size', 0)
        bss_words = bss_size // 4

        # BSS block is exactly bss_size — no extension for params.
        # Params go after ebreak in the target's working RAM.
        bss_block = [0] * bss_words
        init_params = algo.get('init_params')
        params_words = list(init_params) if init_params else []

        padded = blob_instructions + bss_block + [RiscvInstr.ebreak()] + params_words

        # ebreak sits at p_memsz (p_filesz + bss_size)
        ebreak_addr = ram_start + blob_size_bytes + bss_size
        # params sit right after ebreak
        params_addr = ebreak_addr + 4 if params_words else 0

        algo['instructions'] = padded
        algo['ebreak_footer_addr'] = ebreak_addr
        algo['init_params_addr'] = params_addr

        # Derive page buffer and stack from working RAM.
        # Must account for init_params: pc_init writes params to RAM after ebreak,
        # which would corrupt page buffer if they overlap.
        params_size = len(params_words) * 4
        total_written = blob_size_bytes + bss_size + 4 + params_size
        page_size = algo.get('page_size', 256)

        # When page_buffer_ram_start is set, page buffers live in a separate
        # RAM region from the algo body. Some SoCs need this for cache
        # coherency: the flash controller DMAs page data over the system bus,
        # and if the buffers sit in a CPU-local memory whose dirty cache lines
        # the bus cannot write back, the DMA reads stale data and programming
        # silently fails. A cache-coherent system RAM avoids this. Each target
        # declares whether it needs _PAGE_BUF_RAM_START; the algo layer just
        # consumes it.
        page_buf_ram = algo.get('page_buffer_ram_start')
        if page_buf_ram is not None:
            # Page buffers live in a separate region from the algo body, so
            # they cannot overlap the blob/bss/params layout. The
            # total_written offset only made sense when buffers shared
            # ram_start; here it is meaningless (adds an algo-region byte
            # count into the page-buffer region) and skews placement. Start
            # at the region base, 16-aligned.
            buf0 = align_up(page_buf_ram, 16)
        else:
            buf0 = ram_start + align_up(total_written, 16)
        buf1 = buf0 + page_size
        algo.setdefault('page_buffers', [buf0, buf1])
        algo.setdefault('begin_stack', ram_start + ram_size)

        # Scratch area for register load optimization (after page buffers).
        # Layout: [a0][a1][a2][a3][ra][dpc] = 6 words = 24 bytes.
        # SBA batch writes values here, progbuf LW loads them to registers.
        # Ultra-fast path also loads DPC via CSRW, eliminating abstract cmds.
        self._reg_scratch_addr = align_up(buf1 + page_size, 16)

        super().__init__(target, algo)

        # Disable Arm CRC32 analyzer (compiled Arm machine code)
        self.use_analyzer = False

        # Erase tracking: when flash is pre-erased (e.g., via GDB 'mon erase'),
        # the builder can skip VERIFY scan and redundant sector erases.
        self._flash_pre_erased = False

        # Batch mode: when True, op transitions (e.g., ERASE→PROGRAM) within a
        # single RiscvFlashBuilder.program() call skip pc_init and pc_unInit.
        # Saves one full flash-controller re-init cycle per program() invocation.
        # Flash-controller state persists across flash op transitions on this target.
        self._batch_mode = False
        self._init_diag_done = False

    def _pre_call_hook(self, init: bool) -> None:
        """Run before a flash-algo function call. `init` is True when the
        call is the algo init routine. Default: no-op."""

    def _post_op_cache_sync(self) -> None:
        """Cache maintenance after a flash op that may leave cached copies
        stale for host reads. Runs when no operation is active. Default: no-op."""

    def _post_init_diagnostics(self) -> None:
        """Optional first-init diagnostics (state inspection). Runs only when
        no operation is active. Default: no-op."""

    def get_flash_builder(self):
        """Return an optimized FlashBuilder for RISC-V.

        Uses RiscvFlashBuilder which skips VERIFY scan and sector erases
        when the flash is known to be pre-erased (after erase_all or
        erase_sector calls).
        """
        return RiscvFlashBuilder(self)

    def erase_all(self):
        """Erase entire flash and mark as pre-erased."""
        super().erase_all()
        self._flash_pre_erased = True

    def erase_sector(self, address):
        """Erase a sector and mark as pre-erased."""
        super().erase_sector(address)
        self._flash_pre_erased = True


    def _execute_fence_i(self) -> None:
        """Execute FENCE.I via program buffer to synchronize I/D cache.

        FENCE.I ensures instruction and data cache coherence after writing
        code or data to memory. Uses the Debug Module's program buffer to
        execute the instruction while the hart is halted.

        Must be called:
        - After loading algo blob to RAM, before resume() -- ensures CPU
          fetches the freshly-written algo instructions
        - After flash programming completes -- ensures CPU reads updated
          flash data instead of stale cache values
        """
        core = self.target.selected_core
        dm = core.riscv_dm
        progbuf = dm._progbuf
        if progbuf.available:
            progbuf.write_program([RiscvInstr.fence_i()])
            cmd = Command.build_postexec_only()
            dm._abstract.execute(cmd)
            LOG.debug("FENCE.I executed via program buffer")
        else:
            LOG.warning("Program buffer not available, skipping FENCE.I")

    def _ultra_fast_register_load(self, gpr_values: List[Tuple[int, int]],
                                  dpc_value: int) -> bool:
        """Load GPRs + DPC via SBA batch + progbuf, zero abstract commands.

        Builds the scratch address in progbuf (LUI+ADDI) instead of an
        abstract command, and writes DPC via CSRW in progbuf instead of
        an abstract command. Minimizes USB round-trips per flash call.

        Uses t0 (x5) as scratch base and t1 (x6) for DPC value.
        Both are caller-saved temporaries not used as flash algo inputs.

        Requires progbufsize >= 10 (9 instructions + optional impebreak).
        Falls back to _fast_register_load if progbuf too small.

        Args:
            gpr_values: List of (register_number, value) tuples for GPRs.
                Supported: a0(10), a1(11), a2(12), a3(13), ra(1)
            dpc_value: Value to write to DPC register.

        Returns:
            True if ultra-fast path succeeded, False if fallback needed.
        """
        core = self.target.selected_core
        dm = core.riscv_dm
        progbuf = dm._progbuf
        sba = dm._sysbus

        if not (progbuf.available and sba.available):
            return False

        scratch_addr = self._reg_scratch_addr

        # Determine address construction mode based on progbuf capacity.
        # Mode 1 (compact, 8 insns): ADDI t0, x0, addr  — for addr < 2048
        # Mode 2 (full, 9 insns):     LUI t0, upper; ADDI t0, t0, lower
        # With impebreak: need insns <= progbuf.size
        # Without impebreak: need insns + 1 <= progbuf.size
        addr_fits_imm12 = -2048 <= scratch_addr < 2048
        base_insn_count = 8 if addr_fits_imm12 else 9
        min_progbuf = base_insn_count if progbuf.has_impebreak else base_insn_count + 1
        if progbuf.size < min_progbuf:
            return False

        # Map register numbers to scratch offsets
        REG_SLOTS = {
            10: 0,   # a0 -> scratch+0
            11: 4,   # a1 -> scratch+4
            12: 8,   # a2 -> scratch+8
            13: 12,  # a3 -> scratch+12
            1:  16,  # ra -> scratch+16
        }

        # Build scratch area values (6 words: a0, a1, a2, a3, ra, DPC)
        scratch_values = [0] * 6
        scratch_used = [False] * 5
        for reg_num, value in gpr_values:
            if reg_num not in REG_SLOTS:
                return False
            idx = REG_SLOTS[reg_num] // 4
            scratch_values[idx] = value
            scratch_used[idx] = True

        scratch_values[5] = dpc_value  # DPC at scratch+20

        # SBA batch write 6 scratch values
        sba.write_memory_batch(scratch_addr, scratch_values)

        # Build progbuf instructions
        # Compact mode (8 insns, addr < 2048):
        #   ADDI t0, x0, addr
        #   LW a0-a3, ra
        #   LW t1, 20(t0); CSRW dpc, t1
        #
        # Full mode (9 insns, any 32-bit addr):
        #   LUI t0, upper; ADDI t0, t0, lower
        #   LW a0-a3, ra
        #   LW t1, 20(t0); CSRW dpc, t1
        program = []
        if addr_fits_imm12:
            program.append(RiscvInstr.addi(5, 0, scratch_addr))
        else:
            upper = (scratch_addr >> 12) & 0xFFFFF
            lower = scratch_addr & 0xFFF
            if lower >= 0x800:
                upper = (upper + 1) & 0xFFFFF
                lower = lower - 0x1000
            program.append(RiscvInstr.lui(5, upper))
            program.append(RiscvInstr.addi(5, 5, lower))

        # GPR loads (a0-a3, ra)
        for i, used in enumerate(scratch_used):
            if used:
                reg = [10, 11, 12, 13, 1][i]
                program.append(RiscvInstr.lw(reg, 5, i * 4))
            else:
                program.append(RiscvInstr.nop())

        # DPC write via progbuf (eliminates abstract command)
        program.append(RiscvInstr.lw(6, 5, 20))      # LW t1, 20(t0) -- DPC value
        program.append(RiscvInstr.csrw(0x7B1, 6))    # CSRW dpc, t1

        progbuf.write_program(program)
        cmd = Command.build_postexec_only()
        dm._abstract.execute_batched(cmd)

        LOG.debug("Ultra-fast register load: %d GPRs + DPC via SBA+progbuf(t0), 0 ACs",
                  sum(scratch_used))
        return True

    def _fast_register_load(self, gpr_values: List[Tuple[int, int]],
                            dpc_value: int) -> bool:
        """Load GPRs via SBA batch write + progbuf, DPC via abstract cmd.

        Replaces individual abstract command register writes with a batched
        scratch-write + progbuf LW sequence. Writes the scratch base (s1)
        via one abstract command, fills scratch via one SBA batch, loads
        GPRs via progbuf, then writes DPC via one abstract command.

        Uses s1 (x9) as scratch base, NOT s0 (x8):
        flash_program reserves s0 as its global data base. Overwriting s0
        would corrupt flash_program's data access and cause MIS-MATCHED sections.

        Args:
            gpr_values: List of (register_number, value) tuples for GPRs.
                Supported: a0(10), a1(11), a2(12), a3(13), ra(1)
            dpc_value: Value to write to DPC register.

        Returns:
            True if fast path succeeded, False if fallback needed.
        """
        core = self.target.selected_core
        dm = core.riscv_dm
        progbuf = dm._progbuf
        sba = dm._sysbus
        abstract = dm._abstract

        if not (progbuf.available and sba.available):
            return False

        # Need 5 progbuf slots: 4 LW (a0-a3) + 1 LW (ra) + impebreak
        min_progbuf = 5 if progbuf.has_impebreak else 6
        if progbuf.size < min_progbuf:
            return False

        scratch_addr = self._reg_scratch_addr

        # Map register numbers to scratch offsets
        REG_SLOTS = {
            10: 0,   # a0 -> scratch+0
            11: 4,   # a1 -> scratch+4
            12: 8,   # a2 -> scratch+8
            13: 12,  # a3 -> scratch+12
            1:  16,  # ra -> scratch+16
        }

        # Build scratch area values (5 words)
        scratch_values = [0] * 5
        scratch_used = [False] * 5
        for reg_num, value in gpr_values:
            if reg_num not in REG_SLOTS:
                return False
            idx = REG_SLOTS[reg_num] // 4
            scratch_values[idx] = value
            scratch_used[idx] = True

        # Write s1 (x9) = scratch_addr via abstract command.
        # IMPORTANT: use s1, NOT s0 -- s0 is flash_program's data base (0x2B4).
        abstract.write_register_batched(RiscvRegno.X9, scratch_addr)

        # SBA batch write scratch values
        sba.write_memory_batch(scratch_addr, scratch_values)

        # Build and execute progbuf instructions
        program = []
        for i in range(4):
            if scratch_used[i]:
                program.append(RiscvInstr.lw(10 + i, 9, i * 4))
            else:
                program.append(RiscvInstr.nop())
        if scratch_used[4]:
            program.append(RiscvInstr.lw(1, 9, 16))
        else:
            program.append(RiscvInstr.nop())

        progbuf.write_program(program)
        cmd = Command.build_postexec_only()
        abstract.execute_batched(cmd)

        # Write DPC via abstract command
        abstract.write_register_batched(RiscvRegno.DPC, dpc_value)

        LOG.debug("Fast register load: %d GPRs via SBA+progbuf(s1), DPC via AC",
                  sum(scratch_used))
        return True

    def _try_fast_register_load(self, reg_list: List[str],
                                data_list: List[int]) -> bool:
        """Attempt fast register load from reg_list/data_list format.

        Translates register name/value pairs into the format expected
        by _fast_register_load. DPC (from 'pc') is written separately
        via abstract command.

        Args:
            reg_list: List of register names (e.g., ['a0', 'a1', 'pc', 'ra'])
            data_list: List of register values corresponding to reg_list

        Returns:
            True if fast path succeeded, False if fallback needed.
        """
        NAME_TO_NUM = {
            'a0': 10, 'a1': 11, 'a2': 12, 'a3': 13,
            'ra': 1,
        }
        FAST_REGS = set(NAME_TO_NUM.keys())

        pc_val = None
        gpr_entries = []
        for reg, val in zip(reg_list, data_list):
            if reg == 'pc':
                pc_val = val
            elif reg in FAST_REGS:
                gpr_entries.append((NAME_TO_NUM[reg], val))
            else:
                # Unsupported register (gp, sp, etc.) -- use fallback
                return False

        if pc_val is None:
            return False

        # Try ultra-fast first (LUI+ADDI progbuf, zero abstract cmds).
        # Falls through to fast path if progbuf too small.
        if self._ultra_fast_register_load(gpr_entries, pc_val):
            return True

        return self._fast_register_load(gpr_entries, pc_val)

    def init(self, operation: Flash.Operation, address: Optional[int] = None,
             clock: int = 0, reset: bool = False) -> None:
        """Initialize flash algorithm.

        Supports parameterized behavior via algo dict keys:
            init_timeout: Override timeout for flash_init (e.g., controller auto-init)

        In batch mode (set by RiscvFlashBuilder.program()), op transitions
        skip pc_init and controller re-configuration. The controller state from
        the first init persists across erase/program/verify operations since
        they share the same physical hardware.
        """
        # Batch mode: short-circuit op transitions without pc_init.
        # First init still goes through super().init() to set up algo.
        #
        # Assumption: skip is safe because (a) controller state persists
        # across erase/program/verify ops (same physical hardware), and
        # (b) batch mode also skips pc_unInit, so the BSS/params region is
        # not corrupted between ops. If a future blob's erase/program ops
        # write to the BSS/params region, this short-circuit must be
        # revisited (would need pc_init to re-repair params).
        if self._batch_mode and self._active_operation is not None:
            if self._active_operation != operation:
                LOG.debug("Batch mode: op %s→%s without pc_init (state preserved)",
                          self._active_operation.name, operation.name)
                self._active_operation = operation
            return

        algo = self.flash_algo

        # Set init timeout if specified
        timeout = algo.get('init_timeout')
        if timeout:
            self.target.session.options.set('flash.timeout.init', timeout)
            LOG.debug("%s init: calling flash_init (timeout=%ss)", operation.name, timeout)

        super().init(operation, address, clock, reset)

    def uninit(self) -> None:
        """Uninitialize flash algorithm.

        In batch mode (during RiscvFlashBuilder.program()), skips entirely
        to preserve flash-controller state across op transitions. The final
        uninit happens when batch mode exits.
        """
        if self._batch_mode:
            LOG.debug("Batch mode: skip uninit (preserve _active_operation=%s)",
                      self._active_operation.name if self._active_operation else None)
            return

        super().uninit()

    def _call_function(self, pc: int, r0: Optional[int] = None,
                       r1: Optional[int] = None, r2: Optional[int] = None,
                       r3: Optional[int] = None, init: bool = False) -> None:
        """Set up registers and resume to call a flash algo function.

        Convention is driven by algo dict keys:
            init_args: Override init call args (a0-aN from list, replaces r0-r3)
            flash_base: Enable offset-based erase/program (a0=base, a1=offset, ...)
        Falls back to standard passthrough (a0=r0, a1=r1, ...) if neither is set.
        """
        reg_list = []
        data_list = []

        if self.flash_algo_debug:
            self._flash_algo_debug_setup()

        algo = self.flash_algo

        self._pre_call_hook(init)

        # Verify blob code integrity before first init call only.
        # Blob code in RAM does not change between init cycles; skip the
        # verify read after the first init to avoid redundant SBA reads.
        if init and self._active_operation is None and not getattr(self, '_blob_verified', False):
            try:
                ld = algo['load_address']
                # Full flash_core_init code verification (first 0x50 instructions)
                actual = self.target.read_memory_block32(ld, 0x50)
                expected = algo['instructions'][:0x50]
                mismatches = [(i, actual[i], expected[i])
                              for i in range(min(len(actual), len(expected)))
                              if actual[i] != expected[i]]
                if mismatches:
                    LOG.warning("blob CODE MISMATCH: %d instructions differ!",
                                len(mismatches))
                    for idx, a, e in mismatches[:8]:
                        LOG.warning("  [0x%x] expected=0x%08x actual=0x%08x",
                                    idx * 4, e, a)
                else:
                    LOG.info("blob verify: first %d instructions match", len(actual))
                self._blob_verified = True
            except Exception:
                pass

        if init and 'init_params' in algo:
            # init_params are placed after ebreak in target's working RAM.
            # The blob reads params via CPU data loads from a1-relative offsets.
            params_addr = algo.get('init_params_addr', algo['ebreak_footer_addr'] + 4)
            flash_base = algo.get('flash_base', 0)

            # Clear entire .bss region so flash_init always re-initializes.
            # Only clearing the initialized flag is insufficient: the CPU may
            # have cached stale BSS values from a prior run, and SBA writes
            # are not guaranteed to be cache-coherent with CPU data loads.
            bss_size = algo.get('bss_total_size', 0)
            if bss_size == 0:
                bss_size = algo.get('bss_size', 0)
            if bss_size == 0:
                p_filesz = algo.get('p_filesz', 0)
                p_memsz = algo.get('p_memsz', 0)
                if p_memsz > p_filesz:
                    bss_size = p_memsz - p_filesz

            if bss_size > 0:
                bss_addr = algo['load_address'] + algo.get('p_filesz', 0)
                bss_words = bss_size // 4
                self.target.write_memory_block32(bss_addr, [0] * bss_words)
                LOG.info("Cleared BSS at 0x%08x (%d bytes, %d words)",
                         bss_addr, bss_size, bss_words)

                # Verify BSS is actually zeroed (SBA readback)
                bss_check = self.target.read_memory_block32(bss_addr, min(8, bss_words))
                if any(v != 0 for v in bss_check):
                    LOG.warning("BSS NOT zeroed! First 8 words: %s",
                                " ".join(f"0x{v:08x}" for v in bss_check))
                else:
                    LOG.info("BSS verified zero (first %d words)", len(bss_check))

            # Verify and repair params in RAM (after blob load).
            # Blob's unInit may corrupt params area (BSS overflow),
            # so always re-write params before init.
            expected = list(algo['init_params'])
            actual = self.target.read_memory_block32(params_addr, len(expected))
            if actual != expected:
                LOG.warning("params MISMATCH at 0x%08x: expected %s, got %s — repairing",
                            params_addr,
                            [f"0x{v:08x}" for v in expected],
                            [f"0x{v:08x}" for v in actual])
                self.target.write_memory_block32(params_addr, expected)

            LOG.info("init_params: using embedded params at 0x%08x, a0=0x%08x, a1=0x%08x",
                     params_addr, flash_base, params_addr)
            reg_list.extend(['a0', 'a1', 'gp', 'sp'])
            data_list.extend([flash_base, params_addr, self.static_base, self.begin_stack])
        elif init and 'init_args' in algo:
            # Legacy init_args: pass values in registers a0-aN
            args = algo['init_args']
            arg_regs = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7']
            for i, arg in enumerate(args):
                reg_list.append(arg_regs[i])
                data_list.append(arg)
            reg_list.extend(['gp', 'sp'])
            data_list.extend([self.static_base, self.begin_stack])
        elif not init and 'flash_base' in algo:
            flash_base = algo['flash_base']
            if r1 is not None and r2 is not None:
                # flash_program(flash_base, offset, buf, size)
                reg_list.extend(['a0', 'a1', 'a2', 'a3'])
                data_list.extend([
                    flash_base,           # a0 = flash_base
                    r0 - flash_base,      # a1 = offset
                    r2,                   # a2 = buf pointer
                    r1,                   # a3 = len
                ])
            elif r0 is None or r0 >= flash_base:
                # flash_erase(flash_base, offset, sector_size)
                # r0=None: erase_all (offset=0); r0>=flash_base: erase_sector
                erase_offset = (r0 - flash_base) if r0 else 0
                erase_sz = algo['sector_size']
                LOG.info("flash_erase: a0=0x%08x (flash_base), a1=0x%x (offset), a2=0x%x (sector_size), r0=0x%08x",
                         flash_base, erase_offset, erase_sz, r0 or 0)
                reg_list.extend(['a0', 'a1', 'a2'])
                data_list.extend([
                    flash_base,                          # a0 = flash_base
                    erase_offset,                        # a1 = offset (0 for erase_all)
                    erase_sz,                            # a2 = sector_size
                ])
            else:
                # r0 < flash_base: not a flash address, use passthrough
                # (e.g., unInit passes r0=operation_value)
                reg_list.append('a0')
                data_list.append(r0)
                reg_list.append('sp')
                data_list.append(self.begin_stack)
        else:
            # Standard passthrough: a0=r0, a1=r1, a2=r2, a3=r3
            if r0 is not None:
                reg_list.append('a0')
                data_list.append(r0)
            if r1 is not None:
                reg_list.append('a1')
                data_list.append(r1)
            if r2 is not None:
                reg_list.append('a2')
                data_list.append(r2)
            if r3 is not None:
                reg_list.append('a3')
                data_list.append(r3)
            if init:
                reg_list.append('gp')
                data_list.append(self.static_base)
            reg_list.append('sp')
            data_list.append(self.begin_stack)

        # Set PC and RA for all calls
        # ra points to ebreak footer at end of blob
        reg_list.extend(['pc', 'ra'])
        data_list.extend([pc, algo['ebreak_footer_addr']])
        LOG.info("flash_func call: pc=0x%08x, ra=0x%08x, init=%s, regs=%s, vals=%s",
                 pc, algo['ebreak_footer_addr'], init, reg_list,
                 [f"0x{v:08x}" for v in data_list])

        # Save DPC (GDB's view of PC) before resume. _call_function writes PC
        # to the algo entry point and resumes; on ebreak halt DPC = algo RA.
        # Without restoring DPC, GDB's cached PC becomes stale (GDB thinks PC
        # is flash entry but DPC is algo RA). This causes flash-debug
        # continue to resume from algo RA instead of flash entry, hitting the
        # algo's ebreak immediately instead of the user's breakpoint at main.
        self._saved_dpc = self.target.read_core_register('dpc')

        # For non-init calls, try fast register load via SBA + progbuf.
        # Uses s1 (not s0) as scratch base to avoid clobbering
        # flash_program's global data pointer (s0=0x2B4).
        fast_ok = False
        if not init and not self.flash_algo_debug:
            fast_ok = self._try_fast_register_load(reg_list, data_list)

        if not fast_ok:
            self.target.write_core_registers_raw(reg_list, data_list)

        # Cache coherency before EVERY resume: FENCE.I invalidates the
        # I-cache (no-op when IC_EN=0) so the algo is fetched from physical
        # local memory, not stale I-cache. Needed when boot code enabled the
        # I-cache before halt.
        try:
            self._execute_fence_i()
        except exceptions.TransferError as e:
            LOG.warning("FENCE.I before resume failed (transport): %s", e)
        self.target.resume()

    def wait_for_completion(self, timeout: Optional[float] = None) -> int:
        """Wait until the ebreak is hit after flash algo execution.

        Polls target state until halted. On halt, reads return value
        from a0 (RISC-V equivalent of Arm r0).
        """
        state = Target.State.RUNNING
        with Timeout(timeout) as time_out:
            while time_out.check():
                try:
                    state = self.target.get_state()
                    if state != Target.State.RUNNING:
                        break
                except exceptions.TransferTimeoutError:
                    LOG.debug("target.get_state probe timeout")
                except exceptions.TransferFaultError:
                    LOG.debug("target.get_state probe fault")
            else:
                # Operation timed out.
                self.target.halt()
                try:
                    pc_val = self.target.read_core_register('pc')
                    ra_val = self.target.read_core_register('a0')
                    sp_val = self.target.read_core_register('sp')
                    LOG.warning("flash operation timed out: pc=0x%08x a0=0x%08x sp=0x%08x",
                                pc_val, ra_val, sp_val)
                except Exception:
                    LOG.debug("flash operation timed out (could not read registers)")
                self._restore_dpc_after_op()
                return self.TIMEOUT_ERROR

        if self.flash_algo_debug:
            self._flash_algo_debug_check()

        if state != Target.State.HALTED:
            self.target.halt()
            self._restore_dpc_after_op()
            raise exceptions.FlashFailure(
                "target was not halted as expected after calling "
                "flash algorithm routine")

        # FENCE.I for VERIFY: ensures CPU reads updated flash data (not stale
        # icache) after algo wrote it. Algo code icache sync is already done
        # before resume via _execute_fence_i() (init=True only).
        if self._active_operation == self.Operation.VERIFY:
            try:
                self._execute_fence_i()
            except exceptions.TransferError as e:
                LOG.warning("FENCE.I for VERIFY failed (transport): %s", e)

        # Canary check: skip for PROGRAM (128KB local memory >> blob+buffer+stack,
        # overflow impossible). Keep for VERIFY and debug mode for safety.
        if self.end_stack is not None and (
                self._active_operation != self.Operation.PROGRAM
                or self.flash_algo_debug):
            canary = self.target.read32(self.end_stack)
            if canary != self._STACK_CANARY:
                self._restore_dpc_after_op()
                raise exceptions.FlashFailure(
                    f"flash algorithm overflowed stack "
                    f"({self.begin_stack - self.end_stack} bytes)")

        # Return value in a0 (RISC-V equivalent of Arm r0).
        # PC read is skipped for PROGRAM and ERASE: it is purely diagnostic
        # logging, and a PC read is an extra abstract command.
        result = self.target.read_core_register('a0')
        if self._active_operation in (self.Operation.PROGRAM, self.Operation.ERASE):
            LOG.debug("flash op completed: a0=0x%08x, op=%s", result, self._active_operation)
        else:
            pc_val = self.target.read_core_register('pc')
            LOG.info("flash op completed: a0=0x%08x, op=%s, pc=0x%08x", result, self._active_operation, pc_val)

        # Restore DPC (success path). The other exit paths (timeout return,
        # not-halted raise, canary-overflow raise) restore via the same
        # helper at their exit points; see _restore_dpc_after_op.
        self._restore_dpc_after_op()

        self._post_op_cache_sync()

        self._post_init_diagnostics()

        return result

    def program_batch_from_buffer(self, big_buf_addr: int, batch_data: bytes,
                                  page_addrs: List[int], page_size: int,
                                  timeout: Optional[float] = None) -> None:
        """Write batch_data to big_buf in one transfer, then program each
        page from big_buf + i*page_size via pc_program_page.

        Amortizes the per-page batch-write setup across len(page_addrs)
        pages. Relies on the algo contract that program_page reads its buf
        argument from any RAM address. The caller must guarantee
        len(batch_data) == len(page_addrs) * page_size and that every
        page's data is full page_size (no short pages).

        Raises FlashProgramFailure(address=<page>, result_code=<result>) on
        any per-page algo timeout or non-zero return.
        """
        core = self.target.selected_core
        LOG.info("program_batch: pages=%d bytes=%d big_buf=0x%x",
                 len(page_addrs), len(batch_data), big_buf_addr)
        core.write_memory_block8(big_buf_addr, batch_data)
        pc_program_page = self.flash_algo['pc_program_page']
        for i, page_addr in enumerate(page_addrs):
            result = self._call_function_and_wait(
                pc_program_page, page_addr, page_size,
                big_buf_addr + i * page_size, timeout=timeout)
            if result == self.TIMEOUT_ERROR:
                raise FlashProgramFailure(
                    'flash program page timeout',
                    address=page_addr, result_code=result)
            elif result != 0:
                raise FlashProgramFailure(
                    'flash program page failure',
                    address=page_addr, result_code=result)

    def _compute_batch_buffer_layout(self, page_size: int) -> Tuple[int, int]:
        """Compute (big_buf_start, max_pages_per_batch) for the multi-page
        batch buffer.

        big_buf sits in the same RAM region as page_buffers (the flash-
        controller DMA reads page data from it, so it shares the page
        buffers' reachability/coherency contract). The region end bounds
        capacity; when begin_stack shares this region (the default working-
        RAM layout), a stack guard is reserved below it. When page buffers
        live in a separate region (page_buffer_ram_start set), no stack is
        present there and the full region tail is available.

        Raises RuntimeError if the capacity is below one page.
        """
        # big_buf alignment: a flash controller whose DMA has cache-line
        # granularity requires the source buffer base aligned to that line,
        # otherwise the DMA fetches wrong data and silently corrupts the
        # programmed image (CPU readback stays correct, masking the failure).
        # The algo dict declares the requirement via 'dma_cacheline_bytes';
        # absent that, natural word alignment suffices.
        dma_alignment = self.flash_algo.get('dma_cacheline_bytes') or _WORD_ALIGN
        # The batch loop reads page i from big_buf + i*page_size, so page_size
        # must be a multiple of the DMA alignment; otherwise every page after
        # the first is misaligned and the DMA fetches wrong data.
        assert page_size % dma_alignment == 0, (
            "batch page_size %d not a multiple of dma_alignment %d"
            % (page_size, dma_alignment))
        big_buf_start = align_up(
            self._reg_scratch_addr + _REG_SCRATCH_BYTES, dma_alignment)
        region = self.target.memory_map.get_region_for_address(self.page_buffers[0])
        region_end = region.start + region.length
        stack_guard = self.flash_algo.get(
            'stack_guard_bytes', _STACK_GUARD_BYTES_DEFAULT)
        if region.start <= self.begin_stack <= region_end:
            big_buf_end = self.begin_stack - stack_guard
        else:
            big_buf_end = region_end
        capacity = big_buf_end - big_buf_start
        max_pages = capacity // page_size
        if max_pages < 1:
            raise RuntimeError(
                "working RAM too small for multi-page batch buffer on "
                "target %s: big_buf_start=0x%x capacity=%d page_size=%d"
                % (self.target.session.board.name, big_buf_start,
                   capacity, page_size))
        return big_buf_start, max_pages

    def _restore_dpc_after_op(self) -> None:
        """Restore DPC to its pre-algo-call value.

        _call_function saved _saved_dpc before resume; on every
        wait_for_completion exit path the caller (GDB or internal)
        expects DPC to reflect the user-visible PC, not the algo's
        ebreak return address. Without this, a timeout/raise leaks
        DPC = algo RA and the next GDB continue resumes from the
        wrong PC (flash-debug continue bug). MUST be called from
        EVERY return/raise in wait_for_completion (success, timeout,
        canary overflow, not-halted). The getattr guard makes a
        direct wait_for_completion call (no preceding _call_function)
        safe instead of raising AttributeError on _saved_dpc.
        """
        saved_dpc = getattr(self, '_saved_dpc', None)
        if saved_dpc is not None:
            try:
                self.target.write_core_register_raw('dpc', saved_dpc)
            except Exception as e:
                LOG.debug("DPC restore after flash op failed: %s", e)

    def _flash_algo_debug_setup(self) -> None:
        """No-op for RISC-V.

        Arm uses vector catch for debug; RISC-V uses DCSR.ebreakm
        which is already enabled during target init.
        """
        pass

    def _flash_algo_debug_check(self) -> None:
        """Verify register state after flash algo execution.

        Checks sp, pc unconditionally. GP is only checked when init_args
        path was used (GP is not set in init_params path).
        """
        algo = self.flash_algo
        expected_sp = algo['begin_stack']
        expected_pc = algo['ebreak_footer_addr']
        final_sp = self.target.read_core_register('sp')
        final_pc = self.target.read_core_register('pc')

        error = False
        # GP check only for init_args path (init_params path blobs call ROM
        # functions that may modify GP as part of normal operation).
        if 'init_args' in algo and 'init_params' not in algo:
            expected_gp = algo['static_base']
        else:
            expected_gp = 0
        if expected_gp != 0:
            final_gp = self.target.read_core_register('gp')
            if final_gp != expected_gp:
                LOG.error("gp should be 0x%x but is 0x%x", expected_gp, final_gp)
                error = True
        if final_sp != expected_sp:
            LOG.error("sp should be 0x%x but is 0x%x", expected_sp, final_sp)
            error = True
        if final_pc != expected_pc:
            LOG.error("pc should be 0x%x but is 0x%x", expected_pc, final_pc)
            error = True
        assert not error

    def compute_crcs(self, sectors: Sequence) -> None:
        """Not supported on RISC-V.

        The CRC32 analyzer is compiled Arm machine code.
        """
        raise NotImplementedError("CRC32 analyzer not available for RISC-V")


class RiscvFlashBuilder(FlashBuilder):
    """FlashBuilder optimized for RISC-V external XIP flash.

    When the flash is known to be pre-erased (after erase_all/erase_sector),
    skips the VERIFY scan and redundant sector erases.
    """

    def _analyze_pages_with_partial_read(self):
        # If flash was pre-erased (e.g., via mon erase), skip reading flash
        # contents. After mon erase, cleanup() calls pc_unInit which resets
        # the flash controller; reading flash without the controller configured
        # causes SBA/progbuf bad-address errors (the flash-read FAIL root
        # cause). Pre-erased flash is all-0xFF which never matches data,
        # so mark all pages as 'not same' without reading.
        if getattr(self.flash, '_flash_pre_erased', False):
            LOG.debug("RiscvFlashBuilder: skipping _analyze (flash pre-erased)")
            for page in self.page_list:
                if page.same is None:
                    page.same = False
            return
        return super()._analyze_pages_with_partial_read()

    def _scan_pages_for_same(self, progress_cb=None):
        # If flash was pre-erased, skip reading flash contents entirely.
        # All pages will be marked as 'not same' since erased flash (0xFF)
        # never matches actual data we want to program.
        if getattr(self.flash, '_flash_pre_erased', False):
            LOG.debug("RiscvFlashBuilder: skipping VERIFY scan (flash pre-erased)")
            for page in self.page_list:
                if page.same is None:
                    page.same = False
            return 0
        return super()._scan_pages_for_same(progress_cb)

    def _program_double_buffer(self, progress_cb=_stub_progress):
        # FlashBuilder.program dispatches here when double buffering is
        # supported. Route the pre-erased case (flash erased out-of-band,
        # e.g. via 'mon erase') to the multi-page batch fast path; otherwise
        # fall back to the base per-page double-buffer loop.
        if getattr(self.flash, '_flash_pre_erased', False):
            return self._pre_erased_program(progress_cb)
        return super()._program_double_buffer(progress_cb)

    def _pre_erased_program(self, progress_cb):
        """Program with a multi-page batch buffer when flash is already erased.

        Batches K pages into a contiguous buffer in one write transfer
        (amortizing the progbuf-autoexec setup), then programs each page
        from buffer + i*page_size. Replaces the legacy
        load_page_buffer/start_program_page_with_buffer double-buffer loop.
        """
        progress = 0
        if progress_cb:
            progress_cb(0.0)
        program_timeout = self.flash.target.session.options.get('flash.timeout.program')

        # Mark all pages as needing programming (skip VERIFY scan).
        for page in self.page_list:
            page.same = False

        if not self.page_list:
            if progress_cb:
                progress_cb(1.0)
            self.flash._flash_pre_erased = False
            return FlashBuilder.FLASH_SECTOR_ERASE

        page_size = self.flash.get_page_info(self.page_list[0].addr).size
        # Short-page defense: the batch path requires full-page data so the
        # big_buf + i*page_size offset arithmetic stays correct. Builder page
        # data is normally page-aligned; an upstream invariant break surfaces
        # here as an explicit failure rather than silent offset corruption.
        for page in self.page_list:
            assert len(page.data) == page_size, (
                "multi-page batch requires full-page data; got %d bytes for "
                "page @0x%x" % (len(page.data), page.addr))

        big_buf_start, max_pages = self.flash._compute_batch_buffer_layout(page_size)
        LOG.info("multi-page: n_pages=%d max_pages_per_batch=%d big_buf=0x%x",
                 len(self.page_list), max_pages, big_buf_start)

        self.flash.init(self.flash.Operation.PROGRAM)
        try:
            i = 0
            n_pages = len(self.page_list)
            while i < n_pages:
                k = min(max_pages, n_pages - i)
                batch_pages = self.page_list[i:i + k]
                batch_data = b"".join(bytes(p.data) for p in batch_pages)
                page_addrs = [p.addr for p in batch_pages]
                self.flash.program_batch_from_buffer(
                    big_buf_start, batch_data, page_addrs, page_size,
                    timeout=program_timeout)
                for p in batch_pages:
                    progress += p.get_program_weight()
                if self.sector_erase_weight > 0 and progress_cb:
                    progress_cb(float(progress) / float(self.sector_erase_weight))
                i += k
        finally:
            self.flash.uninit()
            self.flash._flash_pre_erased = False

        if progress_cb:
            progress_cb(1.0)
        return FlashBuilder.FLASH_SECTOR_ERASE

    def program(self, chip_erase=None, progress_cb=None, smart_flash=True,
                fast_verify=False, keep_unwritten=True, no_reset=False):
        """Override program to enable batch mode across erase/program/verify
        op transitions within this call. chip_erase is resolved by the erase
        phase; no_reset is accepted for caller compatibility. Neither is
        forwarded — upstream FlashBuilder.program dropped both kwargs."""
        if self.flash._batch_mode:
            raise RuntimeError(
                "Nested RiscvFlashBuilder.program() calls are not supported "
                "(batch mode already active from outer call)"
            )

        self.flash._batch_mode = True
        LOG.debug("RiscvFlashBuilder.program: batch_mode=True")
        try:
            result = super().program(
                progress_cb=progress_cb,
                smart_flash=smart_flash, fast_verify=fast_verify,
                keep_unwritten=keep_unwritten)
        except BaseException:
            # Force-clear _active_operation so a failed program does not leak
            # state into the next one. Do not attempt pc_unInit here -- target
            # state is unknown and the call could hang, masking the original
            # error.
            self.flash._active_operation = None
            raise
        else:
            self.flash._active_operation = None
            # Reset after flash program so the boot path runs and the hart
            # reaches the flash entry (upstream FlashBuilder.program no longer
            # resets on its own; without this the hart stays at the algo ebreak).
            if no_reset is not True:
                self.flash.target.reset_and_halt()
            return result
        finally:
            self.flash._batch_mode = False
