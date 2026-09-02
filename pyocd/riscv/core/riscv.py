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
RISC-V CPU core implementation for pyOCD.

Bridges pyOCD's CoreTarget interface to our DebugModule API.
This is the RISC-V equivalent of CortexM.

Architecture mapping:
    CortexM → RISCVCore
    DCRSR/DCRDR (memory-mapped) → DebugModule abstract commands / program buffer
    DHCSR (halt control) → DebugModule dmcontrol
    FPB (breakpoints) → Trigger module (deferred)
"""

import logging
import struct
import time
from typing import (Callable, List, Optional, Sequence, Set, Union)

from ...core.core_registers import (
    CoreRegisterInfo,
    CoreRegistersIndex,
    CoreRegisterNameOrNumberType,
    CoreRegisterValueType,
)
from ...core.core_target import CoreTarget
from ...core.target import Target
from ...core.memory_map import MemoryMap, MemoryType
from ...core.architecture import CoreArchitecture
from ...debug.breakpoints.manager import BreakpointManager
from ..debug.riscv_software import RiscvSoftwareBreakpointProvider
from ...core import exceptions
from ...utility import cmdline, conversion

from .core_registers import RiscvCoreRegisterInfo
from .debug_context import RiscvDebugContext
from ..dm.debug_module import DebugModule
from ..dm.registers import Command, DMReg, DMStatus, DMControl, RiscvRegno
from ..instructions import RiscvInstr

LOG = logging.getLogger(__name__)


class RISCVCore(CoreTarget):
    """RISC-V CPU core for pyOCD.

    Delegates all register/memory/run-control operations to DebugModule.
    Follows the same pattern as CortexM but uses RISC-V debug infrastructure.

    Usage:
        Created by RISCVTarget._create_cores() during init sequence.
        Not instantiated directly.
    """

    def __init__(self, session, dm: DebugModule, hart_id: int,
                 memory_map: Optional[MemoryMap] = None,
                 target=None):
        """Initialize RISC-V core.

        Args:
            session: pyOCD Session instance
            dm: Shared DebugModule instance
            hart_id: Hart index for this core
            memory_map: Memory map for this core
            target: Parent RISCVTarget for lazy per-hart memory map
        """
        self._shared_memory_map = None
        self._hart_memory_map = None
        self._target = None

        super().__init__(session, memory_map)

        self._dm = dm
        self._hart_id = hart_id
        self._core_number = hart_id
        self._target = target
        self._run_token = 0
        self._target_context = None
        self._elf = None
        self._state = Target.State.RUNNING

        # Register definitions
        self._core_registers = CoreRegistersIndex()
        self._build_registers()

        # Register cache: cached while halted, invalidated on any state change
        self._reg_cache: dict = {}  # regno (int) -> value (int)
        self._reg_cache_valid: bool = False

        # Breakpoint support
        self.sw_bp = RiscvSoftwareBreakpointProvider(self)
        self.bp_manager = BreakpointManager(self)
        self.bp_manager.add_provider(self.sw_bp)

        # Hardware trigger module (initialized in init())
        self._trigger_module = None

        # Supported reset types. HARDWARE/NSRST route to the SRST prelude (when the
        # probe advertises Capability.RESET_ASSERT) and re-sample the boot strap.
        # DEFAULT/SYSTEM/CORE are accepted (for option/Cortex-M-muscle-memory
        # compatibility) but have NO distinct RISC-V semantics — unlike Cortex-M's
        # SYSRESETREQ vs VECTRESET, all three alias to the same global ndmreset
        # (the RISC-V debug-module reset, which does not re-sample the strap).
        # See _get_actual_reset_type + _fire_srst_if_eligible + reset().
        self._supported_reset_types: Set[Target.ResetType] = {
            Target.ResetType.DEFAULT,
            Target.ResetType.HARDWARE,
            Target.ResetType.NSRST,
            Target.ResetType.SYSTEM,
            Target.ResetType.CORE,
        }
        # Core-default reset type. Targets override to HARDWARE so their
        # `mon reset halt` re-samples the boot strap via SRST.
        self._default_reset_type: Target.ResetType = Target.ResetType.DEFAULT

        # Post-reset hooks for SoC-specific secondary core release.
        # Some SoCs hold secondary cores in reset after reset
        # and require a register write to release them.
        # Target subclasses register hooks here via register_post_reset_hook().
        self._post_reset_hooks = []


    # ---- Lazy per-hart memory map ----

    @property
    def memory_map(self):
        """Memory map for this hart, lazily computed from target.

        Returns hart-local map if target overrides get_hart_memory_map(),
        otherwise returns the shared SoC memory map.
        """
        if self._hart_memory_map is not None:
            return self._hart_memory_map
        if self._target is not None:
            hart_map = self._target.get_hart_memory_map(self._hart_id)
            if hart_map is not self._shared_memory_map:
                self._hart_memory_map = hart_map
                return self._hart_memory_map
        return self._shared_memory_map

    @memory_map.setter
    def memory_map(self, value):
        self._shared_memory_map = value
        self._hart_memory_map = None

    # ---- Properties ----

    @property
    def name(self) -> str:
        return "RISC-V"

    @property
    def core_number(self) -> int:
        return self._core_number

    @property
    def ap(self):
        """Access Port for this core.

        RISC-V does not use ARM DAP/AP architecture.
        Returns None for pyOCD command context compatibility.
        """
        return None

    @property
    def elf(self):
        return self._elf

    @elf.setter
    def elf(self, value):
        self._elf = value

    @property
    def supported_reset_types(self) -> Set[Target.ResetType]:
        return self._supported_reset_types

    @property
    def default_reset_type(self) -> Target.ResetType:
        return self._default_reset_type

    @default_reset_type.setter
    def default_reset_type(self, reset_type: Target.ResetType) -> None:
        assert isinstance(reset_type, Target.ResetType)
        if reset_type not in self._supported_reset_types:
            raise ValueError(f"{reset_type.name} reset type not supported")
        self._default_reset_type = reset_type

    def _get_actual_reset_type(self, reset_type: Optional[Target.ResetType]) -> Target.ResetType:
        """Resolve the reset type: param > session 'reset_type' option > default_reset_type.

        Mirrors CortexM._get_actual_reset_type (cortex_m.py:875)."""
        if reset_type is None:
            option_reset_type = self.session.options.get('reset_type')
            if option_reset_type == 'default':
                reset_type = self.default_reset_type
            else:
                try:
                    reset_type = cmdline.convert_reset_type(option_reset_type)
                except ValueError:
                    LOG.warning("invalid reset type '%s' in options; falling back to default",
                                option_reset_type)
                    reset_type = self.default_reset_type
        if reset_type not in self._supported_reset_types:
            LOG.warning("%s reset type not supported; falling back to default", reset_type.name)
            reset_type = self.default_reset_type
        return reset_type

    @property
    def architecture(self) -> CoreArchitecture:
        """RISC-V architecture identifier."""
        return CoreArchitecture.RISCV32

    @property
    def architecture_version(self) -> tuple:
        """Architecture version tuple (major, minor).

        RISC-V doesn't have version sub-profiles like ARMv8.x,
        so we return (1, 0) as a placeholder.
        """
        return (1, 0)

    @property
    def extensions(self) -> set:
        """Extensions set.

        RISC-V doesn't use CortexMExtension. Returns empty set.
        """
        return set()

    @property
    def has_fpu(self) -> bool:
        """Whether the core has floating-point support.

        Determined from misa.F (single-precision) or misa.D (double-precision).
        """
        try:
            misa = self._dm.read_register(RiscvRegno.MISA)
            # Bit 5 = F extension, Bit 3 = D extension
            return bool(misa & ((1 << 5) | (1 << 3)))
        except Exception:
            return False

    @property
    def supported_security_states(self) -> Sequence:
        """Supported security states.

        RISC-V doesn't have ARM TrustZone-style security states.
        Always returns NONSECURE for pyOCD compatibility.
        """
        return [Target.SecurityState.NONSECURE]

    @property
    def core_registers(self) -> CoreRegistersIndex:
        return self._core_registers

    @property
    def riscv_dm(self) -> DebugModule:
        """Direct access to the DebugModule."""
        return self._dm

    # ---- CoreTarget abstract methods ----

    def set_reset_catch(self, reset_type: Target.ResetType) -> None:
        """Configure core to halt on reset.

        If DM supports hasresethaltreq, uses the sticky halt-on-reset bit.
        Otherwise falls back to haltreq.
        """
        LOG.debug("set_reset_catch core %d, type=%s", self.core_number, reset_type)
        self._dm.lock()
        try:
            self._select_hart()
            if self._dm.hasresethaltreq:
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.build_setresethaltreq(dmcontrol)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
            else:
                dmcontrol = DMControl.build_dmactive()
                dmcontrol |= (1 << DMControl.HALTREQ_BIT)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
        finally:
            self._dm.unlock()

    def clear_reset_catch(self, reset_type: Target.ResetType) -> None:
        """Disable halt on reset."""
        LOG.debug("clear_reset_catch core %d, type=%s", self.core_number, reset_type)
        self._dm.lock()
        try:
            self._select_hart()
            if self._dm.hasresethaltreq:
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.build_clrresethaltreq(dmcontrol)
                self._dm._write_dmcontrol(dmcontrol)
            else:
                dmcontrol = DMControl.clear_haltreq(DMControl.build_dmactive())
                self._dm._write_dmcontrol(dmcontrol)
        finally:
            self._dm.unlock()

    def set_target_context(self, context) -> None:
        """Set the debug context."""
        self._target_context = context

    def create_semihost_agent(self, context, io_handler=None, console=None):
        from ..debug.riscv_semihost import RiscvSemihostAgent
        return RiscvSemihostAgent(context, self, io_handler=io_handler,
                                  console=console)

    def get_target_context(self, core=None):
        """Get the debug context."""
        return self._target_context

    def exception_number_to_name(self, exc_num: int) -> Optional[str]:
        """Convert exception number to name."""
        # RISC-V interrupt/exception codes
        _EXCEPTION_NAMES = {
            0: 'Instruction address misaligned',
            1: 'Instruction access fault',
            2: 'Illegal instruction',
            3: 'Breakpoint',
            4: 'Load address misaligned',
            5: 'Load access fault',
            6: 'Store address misaligned',
            7: 'Store access fault',
            8: 'ECALL from U-mode',
            9: 'ECALL from S-mode',
            11: 'ECALL from M-mode',
        }
        return _EXCEPTION_NAMES.get(exc_num)

    # ---- Register building ----

    def _build_registers(self) -> None:
        """Build the register index from RiscvCoreRegisterInfo.

        Groups registers by gdb_feature for CoreRegistersIndex.add_group().
        Deduplicates by index since aliases (e.g. 'zero' and 'x0') share the same index.

        Standard RISC-V CSRs are already loaded at module level in
        core_registers.py. This method adds vendor custom CSRs from
        the target's CSR_CONFIGS and builds the CoreRegistersIndex.
        """
        from .csr import load_csr_configs

        # Collect all already-registered registers (GPR/PC/ABI + standard CSR).
        # Deduplicate by (index, gdb_regnum) pair so the same hardware register
        # can appear in multiple GDB features (e.g. pc in cpu, dpc in csr).
        seen = set()
        unique_regs = []
        for info in RiscvCoreRegisterInfo._NAME_MAP.values():
            key = (info.index, info.gdb_regnum)
            if key not in seen:
                seen.add(key)
                unique_regs.append(info)

        # Vendor custom CSRs (unconditional sections only)
        target = getattr(self, '_target', None)
        vendor_configs = getattr(target, 'CSR_CONFIGS', []) if target else []
        if vendor_configs:
            vendor_csrs = load_csr_configs(vendor_configs, phase=1)
            for info in vendor_csrs:
                key = (info.index, info.gdb_regnum)
                if key not in seen:
                    seen.add(key)
                    unique_regs.append(info)
            RiscvCoreRegisterInfo.add_to_map(vendor_csrs)

        self._core_registers.add_group(unique_regs)

    # ---- Hart selection ----

    def load_conditional_csrs(self) -> None:
        """Load conditional CSR registers based on hardware detection.

        Called after misa is readable. Loads:
        - Standard FPU CSRs (fflags, frm, fcsr) if has_fpu
        - Vendor supervisor custom CSRs if target config includes them
        """
        from .csr import load_csr_configs

        conditional_regs = []

        # Standard conditional CSRs (FPU)
        standard_csrs = load_csr_configs(
            ["riscv_standard_csr.yaml"], phase=2, has_fpu=self.has_fpu,
        )
        conditional_regs.extend(standard_csrs)

        # Vendor conditional CSRs (supervisor custom, etc.)
        target = getattr(self, '_target', None)
        vendor_configs = getattr(target, 'CSR_CONFIGS', []) if target else []
        if vendor_configs:
            vendor_csrs = load_csr_configs(
                vendor_configs, phase=2, has_fpu=self.has_fpu,
            )
            conditional_regs.extend(vendor_csrs)

        if conditional_regs:
            self._core_registers.add_group(conditional_regs)
            RiscvCoreRegisterInfo.add_to_map(conditional_regs)

    def _select_hart(self) -> None:
        """Ensure correct hart is selected in DebugModule."""
        self._dm.select_hart(self._hart_id)

    # ---- Memory access ----

    def write_memory(self, addr: int, data: int, transfer_size: int = 32) -> None:
        self._dm.lock()
        try:
            self._select_hart()
            self._dm.write_memory(addr, data, transfer_size)
        finally:
            self._dm.unlock()

    def read_memory(self, addr: int, transfer_size: int = 32,
                    now: bool = True) -> Union[int, Callable[[], int]]:
        self._dm.lock()
        try:
            self._select_hart()
            value = self._dm.read_memory(addr, transfer_size)
            if now:
                return value
            return value
        finally:
            self._dm.unlock()

    def read_memory_block8(self, addr: int, size: int) -> Sequence[int]:
        """Read block of bytes with optimized aligned word reads.

        Mirrors write_memory_block8: a leading unaligned head is read by a
        single partial-word read; the aligned middle is fetched as 32-bit
        words via the SBA deferred loop (N reads in N/8 USB transfers
        instead of N*3); a trailing unaligned tail is read by another
        partial-word read.
        """
        self._dm.lock()
        try:
            self._select_hart()
            if size <= 0:
                return []
            result: list = []
            offset = 0

            # Leading unaligned bytes (partial first word)
            align = addr % 4
            if align:
                word = self._dm.read_memory(addr - align, 32)
                n_lead = min(4 - align, size)
                for i in range(n_lead):
                    result.append((word >> ((align + i) * 8)) & 0xFF)
                offset = n_lead

            # Aligned 32-bit words (batch read)
            remaining = size - offset
            n_words = remaining // 4
            if n_words > 0:
                words = self._dm.read_memory_batch(addr + offset, n_words, 32)
                for word in words:
                    result.append(word & 0xFF)
                    result.append((word >> 8) & 0xFF)
                    result.append((word >> 16) & 0xFF)
                    result.append((word >> 24) & 0xFF)
            offset += n_words * 4

            # Trailing unaligned bytes (partial last word)
            remaining = size - offset
            if remaining:
                word = self._dm.read_memory(addr + offset, 32)
                for i in range(remaining):
                    result.append((word >> (i * 8)) & 0xFF)

            return result
        finally:
            self._dm.unlock()

    def write_memory_block8(self, addr: int, data: Sequence[int]) -> None:
        """Write block of bytes with optimized aligned word writes.

        Leading and trailing unaligned bytes go through read-modify-write;
        the aligned 32-bit middle is written directly without a prior read,
        avoiding one DMI round-trip per word. For a typical GDB load section
        of 2048 aligned bytes this drops 4096 DMI ops to 512.
        """
        self._dm.lock()
        try:
            self._select_hart()
            if not data:
                return
            offset = 0

            # Leading unaligned bytes (read-modify-write)
            align = addr % 4
            if align:
                n_lead = min(4 - align, len(data))
                word_addr = addr & ~3
                word = self._dm.read_memory(word_addr, 32)
                for i in range(n_lead):
                    shift = (align + i) * 8
                    word = (word & ~(0xFF << shift)) | ((data[i] & 0xFF) << shift)
                self._dm.write_memory(word_addr, word, 32)
                offset = n_lead

            # Aligned 32-bit words (batch write for throughput)
            remaining = len(data) - offset
            n_words = remaining // 4
            if n_words > 0:
                if isinstance(data, (bytes, bytearray, memoryview)):
                    words = list(struct.unpack_from('<' + 'I' * n_words,
                                                  data, offset))
                else:
                    # Sequence[int] fallback (e.g. list of byte values)
                    words = [
                        int.from_bytes(data[offset + i * 4: offset + i * 4 + 4],
                                       'little')
                        for i in range(n_words)
                    ]
                self._dm.write_memory_batch(addr + offset, words, 32)
                offset += n_words * 4

            # Trailing unaligned bytes (read-modify-write)
            remaining = len(data) - offset
            if remaining:
                word_addr = addr + offset
                word = self._dm.read_memory(word_addr, 32)
                for i in range(remaining):
                    shift = i * 8
                    word = (word & ~(0xFF << shift)) | ((data[offset + i] & 0xFF) << shift)
                self._dm.write_memory(word_addr, word, 32)
        finally:
            self._dm.unlock()

    def read_memory_block32(self, addr: int, size: int) -> Sequence[int]:
        """Read aligned block of 32-bit words via batch (aligned with write)."""
        self._dm.lock()
        try:
            self._select_hart()
            if size == 1:
                return [self._dm.read_memory(addr, 32)]
            return self._dm.read_memory_batch(addr, size, 32)
        finally:
            self._dm.unlock()

    def write_memory_block32(self, addr: int, data: Sequence[int]) -> None:
        """Write aligned block of 32-bit words via batch."""
        self._dm.lock()
        try:
            self._select_hart()
            self._dm.write_memory_batch(addr, list(data), 32)
        finally:
            self._dm.unlock()

    # ---- Register access ----

    def read_core_register(self, reg: CoreRegisterNameOrNumberType) -> CoreRegisterValueType:
        """Read register with type conversion."""
        reg_info = RiscvCoreRegisterInfo.get(reg)
        raw = self.read_core_register_raw(reg_info.index)
        return reg_info.from_raw(raw)

    def read_core_register_raw(self, reg: CoreRegisterNameOrNumberType) -> int:
        """Read register as raw integer."""
        vals = self.read_core_registers_raw([reg])
        return vals[0]

    def read_core_registers_raw(self, reg_list: Sequence[CoreRegisterNameOrNumberType]) -> List[int]:
        """Read multiple registers as raw integers.

        Uses register cache to avoid redundant DMI transactions.
        Cache is valid while halted and invalidated on resume/step/reset.
        """
        self._dm.lock()
        try:
            self._select_hart()
            results: list = [None] * len(reg_list)
            uncached: list = []  # (index_in_results, reg_info)

            for i, reg in enumerate(reg_list):
                reg_info = RiscvCoreRegisterInfo.get(reg)
                if self._reg_cache_valid and reg_info.index in self._reg_cache:
                    results[i] = self._reg_cache[reg_info.index]
                else:
                    uncached.append((i, reg_info))

            # Read uncached registers from hardware.
            # By this point, DebugModule.read_register() has already attempted
            # progbuf fallback for NOT_SUPPORTED/EXCEPTION errors. If the error
            # still propagates, the CSR is genuinely inaccessible (unimplemented
            # or privilege violation). Return 0 to keep the g-packet intact.
            from ..dm.abstract_commands import AbstractCommandError
            for idx, reg_info in uncached:
                try:
                    value = self._dm.read_register(reg_info.index)
                    results[idx] = value
                    self._reg_cache[reg_info.index] = value
                except AbstractCommandError as e:
                    LOG.warning(
                        "CSR read failed: %s (0x%04x) cmderr=%s, progbuf_preferred=%s",
                        reg_info.name, reg_info.index, e.cmderr,
                        reg_info.index in self._dm._progbuf_preferred,
                    )
                    results[idx] = 0

            self._reg_cache_valid = True
            return results
        finally:
            self._dm.unlock()

    def write_core_register(self, reg: CoreRegisterNameOrNumberType,
                            data: CoreRegisterValueType) -> None:
        """Write register with type conversion."""
        reg_info = RiscvCoreRegisterInfo.get(reg)
        self.write_core_register_raw(reg_info.index, reg_info.to_raw(data))

    def write_core_register_raw(self, reg: CoreRegisterNameOrNumberType, data: int) -> None:
        """Write register as raw integer."""
        self.write_core_registers_raw([reg], [data])

    def write_core_registers_raw(self, reg_list: Sequence[CoreRegisterNameOrNumberType],
                                 data_list: Sequence[int]) -> None:
        """Write multiple registers as raw integers.

        Uses batched abstract commands when writing 2+ registers, reducing
        USB transfers from 4 to 2 per register (50% reduction). Single
        register writes use the standard path with support cache fallback.
        """
        self._dm.lock()
        try:
            self._select_hart()
            if len(reg_list) >= 2:
                # Batch path: 2 USB transfers per register instead of 4
                pairs = []
                for reg, data in zip(reg_list, data_list):
                    reg_info = RiscvCoreRegisterInfo.get(reg)
                    pairs.append((reg_info.index, data))
                self._dm.write_registers_batch(pairs)
                if self._reg_cache_valid:
                    for reg_info_idx, data in pairs:
                        self._reg_cache[reg_info_idx] = data
            else:
                # Single register: use standard path with progbuf fallback
                for reg, data in zip(reg_list, data_list):
                    reg_info = RiscvCoreRegisterInfo.get(reg)
                    self._dm.write_register(reg_info.index, data)
                    if self._reg_cache_valid:
                        self._reg_cache[reg_info.index] = data
        finally:
            self._dm.unlock()

    # ---- Register cache management ----

    def _invalidate_reg_cache(self) -> None:
        """Invalidate register cache.

        Must be called whenever core state changes (resume, step, reset)
        so the next read fetches fresh values from the hart rather than
        returning stale cached data.
        """
        self._reg_cache.clear()
        self._reg_cache_valid = False

    # ---- Run control ----

    def halt(self) -> None:
        """Halt the core."""
        LOG.debug("halting core %d", self.core_number)
        self.session.notify(Target.Event.PRE_HALT, self, Target.HaltReason.USER)
        self._dm.lock()
        try:
            self._select_hart()
            self._dm.halt_hart()
            self._state = Target.State.HALTED
        finally:
            self._dm.unlock()
        self.session.notify(Target.Event.POST_HALT, self, Target.HaltReason.USER)

    def resume(self) -> None:
        """Resume the core."""
        LOG.debug("resuming core %d", self.core_number)
        if self.get_state() != Target.State.HALTED:
            return
        self.session.notify(Target.Event.PRE_RUN, self, Target.RunType.RESUME)
        self._invalidate_reg_cache()
        self._dm.lock()
        try:
            self._select_hart()
            self._dm.resume_hart()
            self._state = Target.State.RUNNING
            self._run_token += 1
        finally:
            self._dm.unlock()
        self.session.notify(Target.Event.POST_RUN, self, Target.RunType.RESUME)

    def step(self, disable_interrupts: bool = True, start: int = 0, end: int = 0,
             hook_cb: Optional[Callable[[], bool]] = None) -> None:
        """Single step the core.

        Uses DCSR.step bit: set step=1, resume, wait for halt.
        Keeps resumereq asserted until the hart halts after one instruction,
        then clears resumereq. Holding resumereq through the step prevents
        the Debug Module from dropping the request mid-step on multi-hart
        systems.

        Handles both software and hardware breakpoints: temporarily removes
        the breakpoint at PC before stepping, then re-inserts it after.
        For hardware breakpoints (read-only memory), flushes the BreakpointManager
        to ensure trigger registers are cleared before resume -- otherwise
        the hart re-halts instantly due to the still-active trigger.
        """
        if not self.is_halted():
            raise exceptions.DebugError("Core not halted, cannot step")

        self._dm.lock()
        try:
            self._select_hart()

            # Check if PC is at a breakpoint (software or hardware).
            pc = self._dm.read_register(RiscvRegno.DPC)
            bp_at_pc = self.bp_manager.find_breakpoint(pc)
            if bp_at_pc is not None:
                self.bp_manager.remove_breakpoint(pc)
            self.bp_manager.flush(is_step=True)

            # Write DCSR with step bit
            dcsr = self._dm.read_register(RiscvRegno.DCSR)
            dcsr_new = dcsr | (1 << 2)
            self._dm.abstract.write_register_batched(
                RiscvRegno.DCSR, dcsr_new)

            # Resume, keeping resumereq asserted until the step completes.
            # Write resumereq=1 and poll for resumeack AND allhalted before
            # clearing resumereq. This ensures the DM does not interfere
            # with the step mechanism on multi-hart systems.
            self._invalidate_reg_cache()
            dmi = self._dm._dmi
            dmcontrol_rr = DMControl.build_resumereq(self._dm._current_dmcontrol)
            dmi.write(DMReg.DMCONTROL, dmcontrol_rr)

            deadline = time.monotonic() + 2.0
            dmstatus = 0
            while time.monotonic() < deadline:
                dmstatus = dmi.read(DMReg.DMSTATUS)
                if (DMStatus.parse_allresumeack(dmstatus)
                        and DMStatus.parse_allhalted(dmstatus)):
                    break
                time.sleep(0.00001)
            else:
                LOG.warning("step hart %d: re-halt timeout, dmstatus=0x%08x",
                            self._hart_id, dmstatus)

            # Clear resumereq (only after halt confirmed for step)
            dmcontrol_clr = DMControl.clear_resumereq(dmcontrol_rr)
            dmi.write(DMReg.DMCONTROL, dmcontrol_clr)
            self._dm._current_dmcontrol = dmcontrol_clr

            # Clear step bit
            self._dm.abstract.write_register_batched(
                RiscvRegno.DCSR, dcsr & ~(1 << 2))

            if bp_at_pc is not None:
                self.bp_manager.set_breakpoint(bp_at_pc.addr)

            self._state = Target.State.HALTED
        finally:
            self._dm.unlock()

    def _fire_srst_if_eligible(self, reset_type: Optional[Target.ResetType]) -> None:
        """Fire the hardware SRST prelude for a direct core.reset() call when the
        SoC layer did not already pulse SRST (``_srst_pulsed`` flag set by
        RISCVTarget). Shared by reset() and reset_and_halt().

        Logs a warning when HARDWARE/NSRST was resolved but the probe cannot
        deliver SRST (cJTAG, or no Capability.RESET_ASSERT such as FTDI)
        so the silent degrade to ndmreset is visible to the operator —
        otherwise 'mon reset halt' on an FTDI/cJTAG board reports
        effective=HARDWARE while actually doing ndmreset.
        """
        actual = self._get_actual_reset_type(reset_type)
        if actual not in (Target.ResetType.HARDWARE, Target.ResetType.NSRST):
            return
        if not self._dm.srst_eligible():
            LOG.warning("%s reset resolved but probe is not SRST-eligible "
                        "(cJTAG link or probe lacks Capability.RESET_ASSERT); "
                        "degrading to ndmreset — boot strap will NOT re-sample",
                        actual.name)
            return
        if not self._dm._srst_pulsed:
            self._dm.perform_srst_prelude()
            self._dm._srst_pulsed = True

    def reset(self, reset_type: Optional[Target.ResetType] = None) -> None:
        """Reset the core using ndmreset.

        ndmreset resets ALL harts (global), so this method acknowledges
        havereset for every enabled hart, not just the calling core's hart.
        Per RISC-V Debug Spec v0.13 §3.4, the sequence arms ndmreset in
        dmcontrol, lets reset propagate, drops ndmreset, waits for
        allhavereset, then acknowledges havereset for every enabled hart.
        """
        import time
        self._invalidate_reg_cache()
        self.bp_manager.remove_all_breakpoints()

        # Hardware SRST prelude: fire ONLY when the SoC layer did not already
        # pulse SRST for this reset (self._dm._srst_pulsed is True). Covers the
        # direct core.reset() path that bypasses RISCVTarget.reset(). The SoC
        # path owns the flag and clears it in its finally.
        self._fire_srst_if_eligible(reset_type)

        self._dm.lock()
        try:
            caps = self._dm.capabilities
            num_harts = caps['num_harts']

            # Set ndmreset (resets ALL harts globally)
            dmcontrol = DMControl.build_dmactive()
            dmcontrol |= (1 << DMControl.NDMRESET_BIT)
            self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
            time.sleep(0.05)
            # Clear ndmreset
            dmcontrol = DMControl.build_dmactive()
            self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
            # Run post-reset hooks (e.g., release secondary cores)
            for hook in self._post_reset_hooks:
                try:
                    hook()
                except Exception as e:
                    LOG.warning("Post-reset hook failed: %s", e)
            # Wait for allhavereset
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                dmstatus = self._dm._dmi.read(DMReg.DMSTATUS)
                if DMStatus.parse_allhavereset(dmstatus):
                    break
            # Acknowledge havereset for all enabled harts
            for hart in range(num_harts):
                if self._dm.hart_enabled(hart):
                    dmcontrol = DMControl.build_dmactive()
                    dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
                    dmcontrol |= (1 << DMControl.ACKHAVERESET_BIT)
                    self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
            # Clear ackhavereset, select hart 0 as default
            dmcontrol = DMControl.build_dmactive()
            self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
            # DMCONTROL writes above bypassed select_hart(), so invalidate the hart-selection cache before re-selecting
            self._dm._last_selected_hart = -1
            # Re-enable ebreak for this hart after ndmreset clears DCSR
            self._select_hart()
            self._enable_ebreak_debug()
            self._state = Target.State.RUNNING
        finally:
            # Clear the SRST-once guard so the next reset can pulse SRST again.
            # This covers the commander `mon reset halt` path (selected_core.reset,
            # bypasses RISCVTarget.reset's finally); without it _srst_pulsed stays
            # True and every reset after the first silently skips the SRST prelude.
            self._dm._srst_pulsed = False
            self._dm.unlock()
        self.session.notify(Target.Event.POST_RESET, self)

    def reset_and_halt(self, reset_type: Optional[Target.ResetType] = None) -> None:
        """Reset and halt the core.

        Uses two strategies based on DM capability. When hasresethaltreq is
        supported (spec-preferred), the debugger arms the halt-on-reset
        sticky bit via setresethaltreq, pulses ndmreset, then drops ndmreset
        so each hart halts on reset exit; allhalted is waited for,
        havereset acknowledged, and the sticky bit cleared via
        clrresethaltreq. Without hasresethaltreq the fallback pulses
        ndmreset, drops it together with haltreq in the same DMI write
        (haltreq is not in the mutually-exclusive bit group), arms haltreq
        on the remaining harts, waits for allhalted, acknowledges havereset,
        then clears haltreq.
        """
        import time
        self._invalidate_reg_cache()
        self.bp_manager.remove_all_breakpoints()

        # Hardware SRST prelude (see reset() for rationale): fire only when
        # the SoC layer did not already pulse SRST for this reset.
        self._fire_srst_if_eligible(reset_type)

        self._dm.lock()
        try:
            caps = self._dm.capabilities
            num_harts = caps['num_harts']

            if self._dm.hasresethaltreq:
                self._reset_and_halt_with_sticky(num_harts)
            else:
                self._reset_and_halt_with_haltreq(num_harts)

            # Invalidate hart selection cache — reset sequences write DMCONTROL
            # directly via _dmi, bypassing select_hart(), so _last_selected_hart
            # is stale. Without this, select_hart() short-circuits on core1 and
            # all subsequent register/step operations target the wrong hart.
            self._dm._last_selected_hart = -1
            self._select_hart()
            self._enable_ebreak_debug()
            self._state = Target.State.HALTED

            # Hardware reset invalidates flash controller state (address remap lost,
            # peripherals reset). Clear pyOCD-side flash flags so next flash
            # operation will reload blob and re-init. Do NOT call blob unInit
            # — the blob's BSS in RAM is stale and calling unInit on a reset
            # controller would hang.
            for region in self.memory_map.iter_matching_regions(type=MemoryType.FLASH):
                if region.flash is not None:
                    region.flash._did_prepare_target = False
                    region.flash._active_operation = None
        finally:
            # Clear the SRST-once guard (see reset() finally comment).
            self._dm._srst_pulsed = False
            self._dm.unlock()
        self.session.notify(Target.Event.POST_RESET, self)

    def _reset_and_halt_with_sticky(self, num_harts: int) -> None:
        """Reset halt using setresethaltreq sticky bit (spec-preferred).

        Per RISC-V Debug Spec §3.4 + Sdext §4.1, the debugger arms the
        halt-on-reset sticky bit via setresethaltreq on every hart (ndmreset
        does not reset DM, so this bit persists), pulses ndmreset, then
        drops ndmreset while raising haltreq so each hart halts on reset
        exit. Post-ndmreset hooks run once primary harts report halted
        (secondary cores are still held in reset and must be released before
        they appear in DMSTATUS). A second allhalted wait covers those
        newly-released harts. havereset is acknowledged together with
        haltreq (haltreq is independent of the mutually-exclusive bit
        group), and finally the sticky bit is cleared via clrresethaltreq.
        """
        import time

        # Arm halt-on-reset sticky bit on every enabled hart.
        for hart in range(num_harts):
            if self._dm.hart_enabled(hart):
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
                dmcontrol = DMControl.build_setresethaltreq(dmcontrol)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

        # Assert ndmreset (global reset for ALL harts).
        dmcontrol = DMControl.build_dmactive()
        dmcontrol |= (1 << DMControl.NDMRESET_BIT)
        self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
        time.sleep(0.05)

        # Deassert ndmreset and raise haltreq. The sticky bit forces an
        # immediate halt on reset exit (spec Sdext §4.1); haltreq covers
        # any silicon that does not honor the sticky bit.
        dmcontrol = DMControl.build_dmactive()
        dmcontrol |= (1 << DMControl.HALTREQ_BIT)
        self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

        # Wait for primary harts to halt before releasing secondary cores.
        deadline = time.monotonic() + 2.0
        dmstatus = 0
        while time.monotonic() < deadline:
            dmstatus = self._dm._dmi.read(DMReg.DMSTATUS)
            if DMStatus.parse_allhalted(dmstatus):
                break

        # Post-reset hooks (e.g., release secondary cores). Run after halt
        # confirmed — secondary cores must not start executing before the
        # debugger has acknowledged reset and taken control.
        for hook in self._post_reset_hooks:
            try:
                hook()
            except Exception as e:
                LOG.warning("Post-reset hook failed: %s", e)

        # Re-wait for allhalted once secondary cores are released. Before
        # release they are invisible to the DM (allunavail=1), so the first
        # wait only observed primary harts; once released, core1 appears in
        # DMSTATUS and halts via the armed sticky bit.
        deadline = time.monotonic() + 2.0
        dmstatus_5b = 0
        while time.monotonic() < deadline:
            dmstatus_5b = self._dm._dmi.read(DMReg.DMSTATUS)
            if DMStatus.parse_allhalted(dmstatus_5b):
                break
        else:
            LOG.warning("reset_and_halt step 5b: allhalted timeout after release, dmstatus=0x%08x",
                        dmstatus_5b)
        LOG.debug("reset_and_halt step 5b: dmstatus=0x%08x (allhalted=%d, allrunning=%d, "
                  "allhavereset=%d, anyunavail=%d)",
                  dmstatus_5b,
                  1 if DMStatus.parse_allhalted(dmstatus_5b) else 0,
                  1 if DMStatus.parse_allrunning(dmstatus_5b) else 0,
                  1 if DMStatus.parse_allhavereset(dmstatus_5b) else 0,
                  1 if DMStatus.parse_anyunavail(dmstatus_5b) else 0)

        # Acknowledge havereset together with haltreq on every hart. haltreq
        # is independent of the mutually-exclusive group
        # {resumereq, hartreset, ackhavereset, setresethaltreq, clrresethaltreq}.
        for hart in range(num_harts):
            if self._dm.hart_enabled(hart):
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
                dmcontrol |= (1 << DMControl.ACKHAVERESET_BIT)
                dmcontrol |= (1 << DMControl.HALTREQ_BIT)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
        # Verify havereset cleared
        dmstatus_6 = self._dm._dmi.read(DMReg.DMSTATUS)
        if DMStatus.parse_anyhavereset(dmstatus_6):
            LOG.warning("reset_and_halt step 6: havereset still set after ack, dmstatus=0x%08x", dmstatus_6)

        # Clear the sticky bit via clrresethaltreq. Per RISC-V Debug Spec §3.4
        # the sticky bit is what holds the hart in halt — clrresethaltreq
        # only clears the sticky bit, it does NOT un-halt. ackhavereset also
        # doesn't un-halt. So writing clrresethaltreq without haltreq is safe
        # per spec; the hart remains halted because it was already halted and
        # these bits don't change halt state.
        for hart in range(num_harts):
            if self._dm.hart_enabled(hart):
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
                dmcontrol = DMControl.build_clrresethaltreq(dmcontrol)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

        # Clean up: select hart 0
        dmcontrol = DMControl.build_dmactive()
        self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

    def _reset_and_halt_with_haltreq(self, num_harts: int) -> None:
        """Reset halt using haltreq in same write as ndmreset clear (fallback)."""
        import time

        # Assert ndmreset (global reset for ALL harts).
        dmcontrol = DMControl.build_dmactive()
        dmcontrol |= (1 << DMControl.NDMRESET_BIT)
        self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)
        time.sleep(0.05)

        # Drop ndmreset and raise haltreq on hart 0 in the same DMI write.
        # haltreq is WARL/WARZ and not in the mutually-exclusive bit group,
        # so it combines safely with ndmreset=0.
        dmcontrol = DMControl.build_dmactive()
        dmcontrol = DMControl.set_hartsel(dmcontrol, 0)
        dmcontrol |= (1 << DMControl.HALTREQ_BIT)
        self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

        # Arm haltreq on the remaining harts.
        for hart in range(1, num_harts):
            if self._dm.hart_enabled(hart):
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
                dmcontrol |= (1 << DMControl.HALTREQ_BIT)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

        # Post-reset hooks (e.g., release secondary cores).
        for hook in self._post_reset_hooks:
            try:
                hook()
            except Exception as e:
                LOG.warning("Post-reset hook failed: %s", e)

        # Wait for allhalted.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            dmstatus = self._dm._dmi.read(DMReg.DMSTATUS)
            if DMStatus.parse_allhalted(dmstatus):
                break

        # Acknowledge havereset on every enabled hart. ackhavereset only
        # clears the havereset status flag; it does not affect halt state.
        # The hart remains halted because haltreq was armed above and
        # persists across dmcontrol writes that don't target the selected
        # hart; for the selected hart haltreq is 0 in this write, but per
        # spec the hart remains halted until explicit resume.
        for hart in range(num_harts):
            if self._dm.hart_enabled(hart):
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
                dmcontrol |= (1 << DMControl.ACKHAVERESET_BIT)
                self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

        # Drop haltreq + ackhavereset and select hart 0.
        dmcontrol = DMControl.build_dmactive()
        self._dm._dmi.write(DMReg.DMCONTROL, dmcontrol)

    def get_state(self) -> Target.State:
        """Get current core state."""
        self._dm.lock()
        try:
            self._select_hart()
            dmstatus = self._dm._dmi.read(DMReg.DMSTATUS)
            if DMStatus.parse_allhalted(dmstatus):
                self._state = Target.State.HALTED
            elif DMStatus.parse_allrunning(dmstatus):
                self._state = Target.State.RUNNING
            return self._state
        finally:
            self._dm.unlock()

    def get_halt_reason(self) -> Optional[Target.HaltReason]:
        """Get reason why core halted."""
        if not self.is_halted():
            return None
        self._dm.lock()
        try:
            self._select_hart()
            dcsr = self._dm.read_register(RiscvRegno.DCSR)
            cause = (dcsr >> 6) & 0x7
            _CAUSE_MAP = {
                1: Target.HaltReason.BREAKPOINT,   # ebreak
                2: Target.HaltReason.BREAKPOINT,    # trigger
                3: Target.HaltReason.DEBUG,         # haltreq
                5: Target.HaltReason.BREAKPOINT,    # ebreak (single-step after)
            }
            return _CAUSE_MAP.get(cause, Target.HaltReason.DEBUG)
        finally:
            self._dm.unlock()

    def is_debug_trap(self) -> bool:
        """Check if halt was caused by debug request (haltreq or step).

        Uses DCSR.cause field:
        - cause=3: haltreq (debug halt request)
        - cause=4: single step completed
        """
        if not self.is_halted():
            return False
        self._dm.lock()
        try:
            self._select_hart()
            dcsr = self._dm.read_register(RiscvRegno.DCSR)
            cause = (dcsr >> 6) & 0x7
            return cause in (3, 4)  # haltreq or step
        finally:
            self._dm.unlock()

    def register_post_reset_hook(self, hook):
        """Register a callback to run after target reset.

        Some SoCs hold secondary cores in reset after reset
        and require a register write to release them. Target subclasses
        register these hooks during init to ensure secondary cores are
        released before haltreq is set.

        Args:
            hook: Callable with no arguments, called after reset completes
                  and before haltreq is set.
        """
        self._post_reset_hooks.append(hook)

    def _enable_ebreak_debug(self) -> None:
        """Enable EBREAK to enter debug mode (ebreakm/ebreaks bits in DCSR).

        Without this, EBREAK raises a standard M-mode breakpoint exception
        instead of halting into debug mode, making software breakpoints
        invisible to the debugger.

        DCSR bit layout (RISC-V Debug Spec v0.13, Table 4.3):
        - bit 15: ebreakm - EBREAK in M-mode enters debug mode
        - bit 13: ebreaks - EBREAK in S-mode enters debug mode
        - bit 12: ebreaku - EBREAK in U-mode enters debug mode
        """
        # Note: no lock here -- caller must hold lock (called from within
        # reset/reset_and_halt/init_triggers which already hold the lock)
        self._select_hart()
        dcsr = self._dm.read_register(RiscvRegno.DCSR)
        # Set ebreakm (bit 15), ebreaks (bit 13), ebreaku (bit 12)
        dcsr |= (1 << 15) | (1 << 13) | (1 << 12)
        self._dm.write_register(RiscvRegno.DCSR, dcsr)
        LOG.debug("DCSR ebreak enabled: 0x%08x", dcsr)

    def is_vector_catch(self) -> bool:
        """Check if halt was caused by vector catch.

        RISC-V does not have ARM-style vector catch. Always returns False.
        """
        return False

    def is_halted(self) -> bool:
        return self.get_state() == Target.State.HALTED

    def is_running(self) -> bool:
        return self.get_state() == Target.State.RUNNING

    # ---- Breakpoints ----

    def set_breakpoint(self, addr: int, type: Target.BreakpointType = Target.BreakpointType.AUTO) -> bool:
        return self.bp_manager.set_breakpoint(addr, type)

    def remove_breakpoint(self, addr: int) -> None:
        self.bp_manager.remove_breakpoint(addr)

    def find_breakpoint(self, addr: int):
        return self.bp_manager.find_breakpoint(addr)

    def get_breakpoint_type(self, addr: int):
        bp = self.bp_manager.find_breakpoint(addr)
        return bp.type if bp else None

    # ---- Watchpoints ----

    def set_watchpoint(self, addr: int, size: int, type: Target.WatchpointType) -> bool:
        """Set a watchpoint using mcontrol trigger.

        Delegates to RiscvTriggerModule if available.
        """
        if self._trigger_module is not None:
            return self._trigger_module.set_watchpoint(addr, size, type)
        LOG.debug("set_watchpoint core %d addr=0x%08X size=%d type=%s (no trigger module)",
                  self.core_number, addr, size, type)
        return False

    def remove_watchpoint(self, addr: int, size: Optional[int] = None,
                          type: Optional[Target.WatchpointType] = None) -> None:
        """Remove a watchpoint by disabling its trigger."""
        if self._trigger_module is not None:
            self._trigger_module.remove_watchpoint(addr, size, type)
            return
        LOG.debug("remove_watchpoint core %d addr=0x%08X (no trigger module)",
                  self.core_number, addr)

    # ---- Vector catch ----

    def set_vector_catch(self, enable_mask: int) -> None:
        """Set vector catch.

        ARM-specific concept (DEMCR register). RISC-V does not have an
        equivalent mechanism. Exception catching can be implemented via
        trigger module breakpoints at exception entry addresses.
        """
        LOG.debug("set_vector_catch core %d mask=0x%x (not applicable to RISC-V)",
                  self.core_number, enable_mask)

    def get_vector_catch(self) -> int:
        """Get current vector catch settings.

        Always returns 0 for RISC-V since vector catch is an ARM concept.
        """
        return 0

    # ---- Security state ----

    def get_security_state(self) -> Target.SecurityState:
        """Get security state.

        RISC-V does not have ARM TrustZone-style security states.
        Always returns NONSECURE for pyOCD compatibility.
        """
        return Target.SecurityState.NONSECURE

    # ---- Lifecycle ----

    def init(self) -> None:
        """Initialize core after discovery.

        Called during create_cores step (before hart is halted).
        Only initializes register definitions and SW breakpoints.
        Trigger discovery requires halted hart and is done in init_triggers().
        """
        self._build_registers()
        self.sw_bp.init()

    def init_triggers(self) -> None:
        """Discover and initialize hardware triggers (requires halted hart).

        Must be called after halt_on_connect. Trigger CSR access via abstract
        commands requires the hart to be halted; calling during init() would
        fail since the hart is still running at that point.
        """
        self._dm.lock()
        try:
            from ..debug.riscv_trigger import RiscvTriggerModule
            try:
                self._trigger_module = RiscvTriggerModule(self._dm)
                self._trigger_module.init()
                hw_bp = self._trigger_module.create_breakpoint_provider()
                self.bp_manager.add_provider(hw_bp)
                LOG.info("Trigger module: %d triggers discovered (%d execute, %d load/store)",
                         self._trigger_module.total_triggers,
                         self._trigger_module.hw_bp_count,
                         self._trigger_module.watchpoint_count)
            except Exception as e:
                LOG.warning("Trigger module init failed, HW breakpoints unavailable: %s", e)

            # Load conditional CSRs (FPU, supervisor custom) based on misa detection.
            # Must be after halt since has_fpu reads misa via abstract command.
            self.load_conditional_csrs()

            # Enable EBREAK to enter debug mode (required for software breakpoints
            # and RISC-V semihosting ebreak trap detection).
            self._enable_ebreak_debug()
        finally:
            self._dm.unlock()

    def disconnect(self, resume: bool = True) -> None:
        """Disconnect from core."""
        if resume and self.is_halted():
            self.resume()

    def flush(self) -> None:
        """Flush any pending operations."""
        if self.session.probe:
            self.session.probe.flush()

    def invalidate_instruction_cache(self, address: int = None) -> None:
        """Invalidate instruction cache.

        Executes FENCE.I via program buffer to ensure instruction and data
        cache coherence after writing code or data to memory. Required when
        the target has separate I/D caches that can become incoherent after
        memory writes (e.g., loading code to RAM, flash programming).

        If the program buffer is not available, logs a warning and skips.
        """
        self._dm.lock()
        try:
            self._select_hart()
            progbuf = self._dm._progbuf
            if progbuf.available:
                progbuf.write_program([RiscvInstr.fence_i()])
                cmd = Command.build_postexec_only()
                self._dm._abstract.execute(cmd)
                LOG.debug("FENCE.I executed via program buffer")
            else:
                LOG.warning("Program buffer not available, skipping FENCE.I")
        finally:
            self._dm.unlock()
