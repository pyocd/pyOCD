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
RISC-V Program Buffer management.

Implements the program buffer mechanism for executing custom RISC-V
instructions on the target hart, enabling CSR access and other
operations not supported by Abstract Commands alone.

Reference: RISC-V Debug Spec v0.13.2 §3.7 (Program Buffer)
"""

from typing import List, Optional
import logging

from ..dtm.jtag_dtm import RiscvError, DmiOperationStatus
from ..dmi.dmi import DMI
from .registers import (
    DMReg, AbstractAuto, AbstractCS, AbstractCmdErr, Command, DMStatus,
    RiscvRegno, RiscvInstr,
)
from .abstract_commands import AbstractCommands

# Maximum DMI operations per USB transfer.
# Limited by CMSIS-DAP DAP_JTAG_SEQUENCE packet size (~255 sequences,
# ~8-10 sequences per DMI op). Using 8 keeps each transfer well within
# limits while still providing significant USB transfer reduction.
BATCH_CHUNK_SIZE = 128
# Read batches use a smaller chunk than writes. A deferred batch of N DATA0
# reads fires N autoexec abstract commands back-to-back in one USB transfer;
# beyond a debug-module-dependent accumulation limit the next read returns
# stale DATA0 (silent: no DMI busy, no AC cmderr). Writes are immune: each
# DATA0 write overwrites the register regardless of whether the prior
# autoexec store finished. 32 keeps reads under the accumulation limit
# while still batching.
READ_BATCH_CHUNK_SIZE = 32

LOG = logging.getLogger(__name__)

# Extra idle cycles for autoexecdata batch loops.
# Each DATA0 read/write auto-triggers an abstract command (progbuf
# execution). In a batch USB transfer, DR scans are separated only by
# JTAG idle cycles (DTMCS.idle × TCK period). A plain DMI register
# access completes within the base idle budget, but auto-executed
# abstract commands run a RISC-V instruction (progbuf lw/addi + DM
# overhead) so the batch needs a larger idle budget per scan.
# Applied via batch_idle_override (not the shared idle_cycles, which
# DMI synchronous ops overwrite back to 7).
AUTOEXECDATA_IDLE_CYCLES = 60


class ProgramBuffer:
    """Program Buffer management with instruction caching.

    The program buffer allows execution of custom RISC-V instructions
    on the target hart. This is primarily used for CSR access when
    Abstract Commands don't support a particular register.

    Features:
    - Instruction caching to minimize DMI writes
    - Automatic ebreak handling (impebreak detection)
    - CSR read/write via s0 scratch register
    - Memory access via load/store instructions

    Reference: RISC-V Debug Spec v0.13.2 §3.7 (Program Buffer)
    """

    def __init__(self, dmi: DMI, abstract: AbstractCommands):
        """Initialize Program Buffer.

        Args:
            dmi: DMI instance for register access
            abstract: AbstractCommands instance for register read/write
        """
        self._dmi = dmi
        self._abstract = abstract
        self._size = 0
        self._has_impebreak = False
        self._progbuf_cache: List[int] = []
        # COMMAND value the autoexecdata loop re-triggers. Captured by
        # read/write_memory_batch when they arm the startup abstract
        # command, so busy recovery can re-arm COMMAND after reading s0
        # (access_register_read(X8) overwrites COMMAND).
        self._autoexec_command = 0
        # Learned autoexec-batch idle (instance-level, persists across
        # read/write_memory_batch calls so adaptive increase survives a
        # whole debug session). The ACTIVE value applied to _execute_batch
        # is dtm.state.batch_idle_override, set to this learned value only
        # while an autoexec loop runs (cleared in finally), so non-autoexec
        # DMI traffic (s0/s1 restore, status reads) keeps using the short
        # base idle. See fix for code-review finding #1 (override leak).
        self._learned_batch_idle: Optional[int] = None

    @property
    def available(self) -> bool:
        """Whether program buffer is available (progbufsize > 0)."""
        return self._size > 0

    @property
    def size(self) -> int:
        """Number of 32-bit words in program buffer."""
        return self._size

    @property
    def has_impebreak(self) -> bool:
        """Whether hardware adds implicit ebreak after program buffer."""
        return self._has_impebreak

    def detect_capabilities(self) -> None:
        """Detect program buffer capabilities from DM registers.

        Reads:
        - abstractcs.progbufsize (bits 28:24)
        - dmstatus.impebreak (bit 22)
        """
        abstractcs = self._dmi.read(DMReg.ABSTRACTCS)
        self._size = AbstractCS.parse_progbufsize(abstractcs)

        dmstatus = self._dmi.read(DMReg.DMSTATUS)
        self._has_impebreak = DMStatus.parse_impebreak(dmstatus)

        # Initialize cache to None (not 0!) to force writing all slots
        # on first write_program call. Hardware PROGBUF registers are
        # UNDEFINED after reset (RISC-V Debug Spec v0.13.2 Section 3.6).
        self._progbuf_cache: List[Optional[int]] = [None] * self._size

    def write_program(self, instructions: List[int]) -> None:
        """Write instructions to program buffer with caching.

        Only writes words that differ from the cache, minimizing
        DMI operations.

        Args:
            instructions: List of 32-bit RISC-V instruction words

        Raises:
            RiscvError: If program buffer not available or too small
        """
        if not self.available:
            raise RiscvError("Program buffer not available (progbufsize=0)")

        # Add ebreak if hardware doesn't provide implicit one
        if not self._has_impebreak:
            instructions = list(instructions) + [RiscvInstr.ebreak()]

        if len(instructions) > self._size:
            raise RiscvError(
                f"Program too large: {len(instructions)} instructions "
                f"exceed progbufsize={self._size}"
            )

        # Write only changed words; None in cache means "unknown" — always write
        for i, insn in enumerate(instructions):
            if (i < len(self._progbuf_cache)
                    and self._progbuf_cache[i] is not None
                    and insn == self._progbuf_cache[i]):
                continue
            self._dmi.write(DMReg.PROGBUF0 + i, insn)
            if i < len(self._progbuf_cache):
                self._progbuf_cache[i] = insn

        # Fill remaining words with NOP (0x00000013), NOT 0!
        # 0x00000000 has opcode 0x00 (bits[1:0]=00) which decodes as
        # a compressed or illegal instruction in RV32I, causing EXCEPTION.
        # Must use proper NOP (ADDI x0, x0, 0) for safe execution.
        for i in range(len(instructions), self._size):
            cached = self._progbuf_cache[i] if i < len(self._progbuf_cache) else None
            if cached is None or cached != RiscvInstr.nop():
                self._dmi.write(DMReg.PROGBUF0 + i, RiscvInstr.nop())
            self._progbuf_cache[i] = RiscvInstr.nop()

    def read_csr(self, csr_address: int) -> int:
        """Read CSR via program buffer.

        Saves s0, writes a CSRR s0, <csr> program to the progbuf, executes
        it with postexec via AccessRegister(read s0), reads back s0, and
        restores s0.

        Args:
            csr_address: 12-bit CSR address

        Returns:
            32-bit CSR value

        Raises:
            RiscvError: If program buffer not available
        """
        if not self.available:
            raise RiscvError(
                "Program buffer not available for CSR read (progbufsize=0)"
            )

        # Save s0
        s0_saved = self._abstract.read_register(RiscvRegno.X8)

        try:
            # Build CSRR s0, <csr> instruction
            csrr_insn = RiscvInstr.csrr(8, csr_address)
            self.write_program([csrr_insn])

            # Execute: read s0 + postexec=1
            # This reads s0 via abstract command, then executes progbuf
            cmd = Command.build_access_register_read(
                RiscvRegno.X8, postexec=True
            )
            self._abstract.execute(cmd)

            # s0 now holds the CSR value (progbuf executed CSRR s0, csr)
            # The abstract read already returned old s0, need to re-read
            result = self._abstract.read_register(RiscvRegno.X8)
            return result
        except Exception as e:
            LOG.debug("progbuf read_csr 0x%04x failed: %s", csr_address, e)
            raise
        finally:
            # Restore s0
            self._abstract.write_register(RiscvRegno.X8, s0_saved)

    def write_csr(self, csr_address: int, value: int) -> None:
        """Write CSR via program buffer.

        Saves s0, writes the value to s0 via an abstract command, writes a
        CSRW <csr>, s0 program to the progbuf, executes it via a
        postexec-only command, and restores s0.

        Args:
            csr_address: 12-bit CSR address
            value: 32-bit value to write

        Raises:
            RiscvError: If program buffer not available
        """
        if not self.available:
            raise RiscvError(
                "Program buffer not available for CSR write (progbufsize=0)"
            )

        # Save s0
        s0_saved = self._abstract.read_register(RiscvRegno.X8)

        try:
            # Write value to s0 first
            self._abstract.write_register(RiscvRegno.X8, value)

            # Build CSRW <csr>, s0 instruction
            csrw_insn = RiscvInstr.csrw(csr_address, 8)
            self.write_program([csrw_insn])

            # Execute progbuf only (no register transfer)
            cmd = Command.build_postexec_only()
            self._abstract.execute(cmd)
        finally:
            # Restore s0
            self._abstract.write_register(RiscvRegno.X8, s0_saved)

    # ========== Memory Access ==========

    def read_memory(self, address: int, size: int = 32) -> int:
        """Read hart-view memory via program buffer.

        Executes a load instruction on the target hart (LW/LHU/LBU selected
        by size), returning the zero-extended value at the hart-local
        address. Requires progbufsize >= 1 (impebreak) or >= 2.

        Args:
            address: Hart-view memory address to read from.
            size: Access size in bits; must be 8, 16, or 32.

        Returns:
            Zero-extended value read from memory.

        Raises:
            RiscvError: If program buffer not available, or size unsupported.
        """
        if not self.available:
            raise RiscvError(
                "Program buffer not available for memory read (progbufsize=0)"
            )
        if size not in (8, 16, 32):
            raise RiscvError(f"Program buffer unsupported read size {size}")
        load_insn = {
            32: RiscvInstr.lw(9, 8, 0),
            16: RiscvInstr.lhu(9, 8, 0),
            8: RiscvInstr.lbu(9, 8, 0),
        }[size]

        s0_saved = self._abstract.read_register(RiscvRegno.X8)
        s1_saved = self._abstract.read_register(RiscvRegno.X9)
        try:
            self._abstract.write_register(RiscvRegno.X8, address)
            self.write_program([load_insn])
            cmd = Command.build_postexec_only()
            self._abstract.execute(cmd)
            return self._abstract.read_register(RiscvRegno.X9)
        finally:
            self._abstract.write_register(RiscvRegno.X9, s1_saved)
            self._abstract.write_register(RiscvRegno.X8, s0_saved)

    def write_memory(self, address: int, value: int, size: int = 32) -> None:
        """Write hart-view memory via program buffer.

        Executes a store instruction on the target hart (SW/SH/SB selected by
        size). The value is masked to the access width before store. Requires
        progbufsize >= 1 (impebreak) or >= 2.

        Args:
            address: Hart-view memory address to write to.
            value: Value to write (masked to size bits).
            size: Access size in bits; must be 8, 16, or 32.

        Raises:
            RiscvError: If program buffer not available, or size unsupported.
        """
        if not self.available:
            raise RiscvError(
                "Program buffer not available for memory write (progbufsize=0)"
            )
        if size not in (8, 16, 32):
            raise RiscvError(f"Program buffer unsupported write size {size}")
        value &= (1 << size) - 1
        store_insn = {
            32: RiscvInstr.sw(9, 8, 0),
            16: RiscvInstr.sh(9, 8, 0),
            8: RiscvInstr.sb(9, 8, 0),
        }[size]

        s0_saved = self._abstract.read_register(RiscvRegno.X8)
        s1_saved = self._abstract.read_register(RiscvRegno.X9)
        try:
            self._abstract.write_register(RiscvRegno.X8, address)
            self._abstract.write_register(RiscvRegno.X9, value)
            self.write_program([store_insn])
            cmd = Command.build_postexec_only()
            self._abstract.execute(cmd)
        finally:
            self._abstract.write_register(RiscvRegno.X9, s1_saved)
            self._abstract.write_register(RiscvRegno.X8, s0_saved)

    # ========== Autoexecdata Busy Recovery ==========

    # Maximum retry attempts for DMI busy during autoexecdata loops.
    # Retry with increasing idle cycles until the autoexec window is large
    # enough for the target's abstract-command completion time.
    _MAX_BUSY_RETRIES = 20

    # CMSIS-DAP caps a single jtag_sequence at 64 TCK; keep batch idle
    # under that so the per-scan RTI idle stays one sequence (no split).
    # Cap > seed (AUTOEXECDATA_IDLE_CYCLES) so adaptive increase engages
    # (code-review fix #1: seed==cap made backoff a no-op).
    _BATCH_IDLE_MAX = 63

    def _increase_batch_idle(self) -> int:
        """Increase the learned autoexec-batch idle (adaptive backoff).

        On AC cmderr=BUSY the in-flight autoexec command did not finish
        within the current batch idle. Increase the learned value so the
        next batch's per-scan RTI idle is longer. Step = cur//10+1. Capped
        at _BATCH_IDLE_MAX.

        Updates BOTH the instance-level learned value (persists across
        calls) and the active dtm.state.batch_idle_override (applied while
        the autoexec loop runs).

        Returns:
            New learned idle value.
        """
        cur = self._learned_batch_idle or AUTOEXECDATA_IDLE_CYCLES
        step = max(cur // 10, 1) + 1
        new = min(cur + step, self._BATCH_IDLE_MAX)
        self._learned_batch_idle = new
        self._dmi.dtm.state.batch_idle_override = new
        return new

    def _poll_busy_safe(self) -> int:
        """Poll abstractcs.busy until clear, converting TimeoutError to RiscvError.

        _poll_busy raises builtin TimeoutError if abstractcs.busy never clears
        (e.g. a stuck/looping abstract command). Wrap it so callers receive
        RiscvError (the RISC-V layer's exception type) instead of a raw
        TimeoutError leaking through read/write_memory_batch (code-review
        fix #2). Returns the final abstractcs value.
        """
        try:
            return self._abstract._poll_busy()
        except TimeoutError as e:
            raise RiscvError(
                f"abstractcs.busy never cleared during autoexec batch: {e}"
            ) from e

    def _poll_busy_safe_after_read(self) -> int:
        """Priming read: read DATA0 (returns stale/garbage) + poll busy.

        The DATA0 read triggers one autoexec (under batch_idle_override);
        _poll_busy waits for it to complete. Returns the post-read abstractcs
        (for cmderr check). Used for startup priming and post-recovery
        re-priming (review R1+R3: must run under override + check cmderr).
        """
        self._dmi.read(DMReg.DATA0)
        return self._poll_busy_safe()

    def _reprime_read_pipeline(self, address: int) -> None:
        """Re-prime the read look-ahead pipeline after busy recovery.

        _recover_ac_busy re-arms COMMAND but leaves DATA0/x9 in a stale
        race state. This re-establishes the primed contract (DATA0=M[addr])
        by: (1) disable autoexec, (2) write x8=address, (3) run
        AccessRegisterWrite(X8) to set s0, (4) re-arm COMMAND (AccessRegister-
        Read X9 postexec) + run to reload x9=M[addr] via postexec lw,
        (5) re-enable autoexec, (6) priming DATA0 read to copy x9->DATA0 +
        prefetch next. Assumes progbuf program (lw x9,0(x8); addi x8,stride)
        is unchanged and _autoexec_command is set (read_memory_batch pre-sets).
        (review R2+R3 blocker: without re-prime, resumed batch first read
        returns stale -> silent corruption.)
        """
        self._dmi.write(DMReg.ABSTRACTAUTO, AbstractAuto.disable_all())
        self._dmi.write(DMReg.DATA0, address)
        cmd_addr = Command.build_access_register_write(RiscvRegno.X8)
        self._dmi.write(DMReg.COMMAND, cmd_addr)
        self._poll_busy_safe()
        # Re-arm COMMAND + run: AccessRegisterRead(X9,postexec) copies x9->
        # DATA0 then postexec lw reloads x9=M[address].
        self._dmi.write(DMReg.COMMAND, self._autoexec_command)
        self._poll_busy_safe()
        self._dmi.write(DMReg.ABSTRACTAUTO,
                        AbstractAuto.enable_autoexecdata(0))
        # Priming DATA0 read: drain garbage + load DATA0=M[address].
        priming_cs = self._poll_busy_safe_after_read()
        self._abstract._check_cmderr(priming_cs)

    def _determine_progress(self, base_address: int, expected: int,
                            stride: int, *, ac_busy: bool = False) -> int:
        """Read s0 to determine actual pipeline progress after busy.

        The autoexecdata loop increments s0 by stride for each word.
        If busy occurred, s0 may be behind the expected position.

        ac_busy selects the look-ahead correction for the recovery path.
        Abstract-command cmderr=BUSY has no batch scan index, so s0 must
        be read, and s0 leads the delivered-word count by 2 (startup and
        priming each ran the progbuf once before DATA0 held the first
        good word). Subtract 2 to get real progress. DMI
        REQUEST_IN_PROGRESS instead carries a precise batch scan index
        and does not call here.

        Returns:
            Actual number of successfully completed words.
        """
        try:
            actual_s0 = self._abstract.read_register(RiscvRegno.X8)
            actual = (actual_s0 - base_address) // stride
            if ac_busy:
                actual -= 2
            return max(0, min(expected, actual))
        except Exception:
            # Cannot determine progress. Conservatively report zero so
            # the caller restarts the batch from base_address. Returning
            # the full expected count would silently claim words were
            # transferred when (on AC-busy recovery) they may not have
            # been, causing silent data corruption.
            return 0

    def _recover_autoexec_busy(self, base_address: int, expected: int,
                                stride: int) -> int:
        """Recover from DMI REQUEST_IN_PROGRESS during autoexecdata loop.

        DMI busy is a batch-scan-level event: the index where busy hit
        (expected) is precise, so there is no s0 read and no look-ahead
        subtraction (the busy index IS the resume index). Only
        abstract-command cmderr=BUSY (_recover_ac_busy) reads s0 and
        subtracts the look-ahead 2.

        Sequence: disable autoexecdata, clear cmderr, re-arm COMMAND,
        increase idle, re-enable.

        Returns:
            The precise batch scan index (expected).
        """
        self._dmi.write(DMReg.ABSTRACTAUTO, AbstractAuto.disable_all())
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
        self._dmi.write(DMReg.COMMAND, self._autoexec_command)
        self._increase_batch_idle()
        self._dmi.write(DMReg.ABSTRACTAUTO,
                        AbstractAuto.enable_autoexecdata(0))
        return expected

    def _recover_ac_busy(self, base_address: int, expected: int,
                         stride: int) -> int:
        """Recover from abstract-command cmderr=BUSY (AC concurrency).

        Some targets return DMI op=SUCCESS but set ABSTRACTCS.cmderr=BUSY
        when a data/progbuf register access races the in-flight
        autoexec abstract command (spec dm_registers.adoc:1067-1070:
        busy-time data writes are discarded). This is distinct from DMI
        REQUEST_IN_PROGRESS (_recover_autoexec_busy).

        cmderr is only valid once busy=0 (spec), and reading s0 is
        itself an abstract command forbidden while busy=1. So poll busy
        to completion BEFORE clearing cmderr and reading s0. The spec
        guarantees the in-flight command finishes
        (debug_module.adoc:331-334), so _poll_busy returns.

        Recovery disables autoexecdata to stop auto re-execution, polls
        busy until the in-flight abstract command finishes, clears cmderr
        (W1C required before any new AC), reads s0 for actual progress
        (safe once busy=0), re-arms COMMAND (the s0 read clobbers it),
        increases idle cycles as best-effort DMI backoff, and re-enables
        autoexecdata.

        Returns:
            Actual number of successfully completed words.
        """
        self._dmi.write(DMReg.ABSTRACTAUTO, AbstractAuto.disable_all())
        self._poll_busy_safe()
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
        actual = self._determine_progress(base_address, expected, stride,
                                          ac_busy=True)
        self._dmi.write(DMReg.COMMAND, self._autoexec_command)
        # Wait for the re-armed AC to finish before re-enabling autoexec.
        # Enabling autoexecdata while an AC is still executing is the
        # cmderr=BUSY-prone window (spec; same hazard documented at the
        # startup pattern in read_memory_batch). Without this poll the
        # read-path _reprime_read_pipeline that follows would write a new
        # COMMAND while busy=1 (spec-forbidden: cmderr=BUSY or write dropped).
        self._poll_busy_safe()
        self._increase_batch_idle()
        self._dmi.write(DMReg.ABSTRACTAUTO,
                        AbstractAuto.enable_autoexecdata(0))
        return actual

    def _read_autoexec_loop(self, base_address: int, count: int,
                             stride: int) -> List[int]:
        """Read DATA0 count times with per-response DMI busy recovery.

        Reads are chunked into BATCH_CHUNK_SIZE per USB transfer to stay
        within CMSIS-DAP packet limits. Between chunks, autoexecdata
        remains enabled — the pipeline continues without interruption
        since each DATA0 read auto-triggers the abstract command
        (progbuf execution).

        On busy: recover pipeline, increase idle, retry remaining reads.

        Args:
            base_address: Memory address of the first word (for progress
                          tracking via s0 register).
            count: Number of DATA0 reads to perform.
            stride: Byte stride between consecutive words (size // 8).

        Returns:
            List of count 32-bit values.
        """
        results: List[int] = []
        remaining = count
        retries = self._MAX_BUSY_RETRIES
        # Track base address for progress calculation. Each successful
        # word advances s0 by stride, so current_base tracks where s0 is.
        current_base = base_address

        _ac_retries = self._MAX_BUSY_RETRIES
        while remaining > 0:
            batch_size = min(remaining, READ_BATCH_CHUNK_SIZE)
            batch_start = len(results)  # mark where this batch's results begin

            # Schedule batch reads in deferred mode (1 USB transfer)
            self._dmi.start_deferred()
            for _ in range(batch_size):
                self._dmi.read(DMReg.DATA0)
            raw = self._dmi.flush_deferred_raw()

            # Wait for the last auto-executed abstract command to finish.
            # See _write_autoexec_loop for rationale: without polling
            # abstractcs.busy the batch is fire-and-forget and races the
            # in-flight command -> silent data corruption.
            self._poll_busy_safe()

            # Check each response for busy
            busy_at = -1
            for i, (data, status) in enumerate(raw):
                if status == DmiOperationStatus.OK:
                    results.append(data)
                elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                    busy_at = i
                    break
                else:
                    raise RiscvError(
                        f"Autoexec read error at index {len(results)}: "
                        f"dmi status={status}"
                    )

            if busy_at >= 0:
                retries -= 1
                if retries <= 0:
                    raise RiscvError(
                        f"Autoexec read: busy retries exhausted, "
                        f"{remaining}/{count} reads pending"
                    )
                # DMI busy is a batch-scan event: the index where busy hit
                # is precise progress. Recover, then re-prime the look-ahead
                # pipeline from the next address via the startup abstract
                # command. Without re-prime the hardware s0 stays at its
                # busy-time look-ahead position and the resumed batch reads
                # shifted words.
                actual = self._recover_autoexec_busy(
                    current_base, busy_at, stride
                )
                if actual < busy_at:
                    del results[len(results) - (busy_at - actual):]
                current_base += actual * stride
                remaining -= actual
                self._reprime_read_pipeline(current_base)
            else:
                # DMI all OK — check AC cmderr (same as write path): idle
                # too short -> autoexec concurrency -> cmderr=BUSY, and the
                # DATA0 reads that raced return stale values. Synchronous
                # ABSTRACTCS read (NOT deferred; batching shifts raw[]).
                abstractcs = self._dmi.read(DMReg.ABSTRACTCS)
                cmderr = AbstractCS.parse_cmderr(abstractcs)
                if cmderr == AbstractCmdErr.BUSY:
                    _ac_retries -= 1
                    if _ac_retries <= 0:
                        self._dmi.write(
                            DMReg.ABSTRACTCS,
                            AbstractCS.build_clear_cmderr(),
                        )
                        raise RiscvError(
                            f"AC BUSY retries exhausted, "
                            f"{remaining}/{count} reads pending"
                        )
                    # Recover: clear cmderr, read s0 for actual progress,
                    # re-arm COMMAND. `actual` = words s0 truly advanced.
                    actual = self._recover_ac_busy(
                        current_base, batch_size, stride
                    )
                    # Drop only the stale tail (actual..batch_size); keep the
                    # good `actual` prefix so len(results) stays consistent
                    # (review R2 fix #3: del results[batch_start:] caused
                    # short read). NOTE: equivalent to DMI-busy path's
                    # del results[len-(busy_at-actual):] because len(results)
                    # ==batch_start+batch_size here (all DMI-OK) and batch_size
                    # plays the busy_at role.
                    if actual < batch_size:
                        del results[batch_start + actual:]
                    current_base += actual * stride
                    remaining -= actual
                    # RE-PRIME the pipeline (review R2+R3 blocker): after
                    # _recover_ac_busy, DATA0 holds a stale race value and
                    # x9 is frozen at an unknown point. Rewrite x8 to the
                    # resume address, reload x9, priming DATA0 read so
                    # DATA0=M[current_base]. Without this, the resumed
                    # batch's first read returns stale -> silent corruption.
                    self._reprime_read_pipeline(current_base)
                elif cmderr != AbstractCmdErr.NONE:
                    self._dmi.write(DMReg.ABSTRACTCS,
                                    AbstractCS.build_clear_cmderr())
                    raise RiscvError(
                        f"Auto-exec read error (cmderr={cmderr})"
                    )
                else:
                    current_base += batch_size * stride
                    remaining -= batch_size

        return results

    def _write_autoexec_loop(self, base_address: int,
                              values: List[int], stride: int) -> None:
        """Write DATA0 N times with per-response DMI busy recovery.

        Writes are chunked into BATCH_CHUNK_SIZE per USB transfer.
        Between chunks, autoexecdata remains enabled.

        Args:
            base_address: Memory address of the first word.
            values: List of 32-bit values to write.
            stride: Byte stride between consecutive words.
        """
        if not values:
            return

        written = 0
        retries = self._MAX_BUSY_RETRIES
        # Separate counter for AC-layer cmderr=BUSY (distinct from DMI
        # REQUEST_IN_PROGRESS). Shared counter would let a mixed DMI+AC
        # busy pattern exhaust retries incorrectly.
        _ac_retries = self._MAX_BUSY_RETRIES
        current_base = base_address

        while written < len(values):
            batch = values[written:written + BATCH_CHUNK_SIZE]

            # Schedule batch writes in deferred mode
            self._dmi.start_deferred()
            for value in batch:
                self._dmi.write(DMReg.DATA0, value)
            raw = self._dmi.flush_deferred_raw()

            # Wait for the last auto-executed abstract command to finish.
            # Without this, the next batch's DATA0 writes race the in-flight
            # command -> DM state corrupts -> silent store loss.
            # abstractcs.busy (bit 12) is the command-complete signal;
            # polling it is what makes the deferred batch NOT fire-and-forget.
            self._poll_busy_safe()

            # Check each response for busy
            busy_at = -1
            for i, (data, status) in enumerate(raw):
                if status == DmiOperationStatus.OK:
                    continue
                elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                    busy_at = i
                    break
                else:
                    raise RiscvError(
                        f"Autoexec write error at index {written + i}: "
                        f"dmi status={status}"
                    )

            if busy_at >= 0:
                retries -= 1
                if retries <= 0:
                    raise RiscvError(
                        f"Autoexec write: busy retries exhausted, "
                        f"{len(values) - written}/{len(values)} writes pending"
                    )
                actual = self._recover_autoexec_busy(
                    current_base, busy_at, stride
                )
                written += actual
                current_base += actual * stride
            else:
                # DMI all OK — but some targets can still set AC cmderr=BUSY
                # (autoexec/AC concurrency): busy-time DATA0 writes are
                # discarded (spec dm_registers.adoc:1067-1070). Use a
                # separate synchronous ABSTRACTCS read (NOT deferred);
                # batching it into the deferred chunk would shift raw[]
                # indices and silently corrupt progress accounting.
                abstractcs = self._dmi.read(DMReg.ABSTRACTCS)
                cmderr = AbstractCS.parse_cmderr(abstractcs)
                if cmderr == AbstractCmdErr.BUSY:
                    _ac_retries -= 1
                    if _ac_retries <= 0:
                        # Clear sticky cmderr so the caller's finally
                        # s0/s1 restore (abstract commands) can run.
                        self._dmi.write(
                            DMReg.ABSTRACTCS,
                            AbstractCS.build_clear_cmderr(),
                        )
                        raise RiscvError(
                            f"AC BUSY retries exhausted, "
                            f"{len(values) - written}/{len(values)} "
                            f"writes pending"
                        )
                    actual = self._recover_ac_busy(
                        current_base, len(batch), stride
                    )
                    written += actual
                    current_base += actual * stride
                elif cmderr != AbstractCmdErr.NONE:
                    self._dmi.write(DMReg.ABSTRACTCS,
                                    AbstractCS.build_clear_cmderr())
                    raise RiscvError(
                        f"Auto-exec write error (cmderr={cmderr})"
                    )
                else:
                    written += len(batch)
                    current_base += len(batch) * stride

    # ========== Batch Memory Access ==========

    def read_memory_batch(self, address: int, count: int,
                          size: int = 32) -> List[int]:
        """Read multiple consecutive memory words via program buffer.

        Uses DM_ABSTRACTAUTO.autoexecdata to eliminate per-word COMMAND writes.
        Each DATA0 read automatically re-executes the abstract command,
        reducing per-word cost from ~5 DMI ops to ~1 DMI op.

        Saves s0 and s1, writes the load/increment program to the progbuf,
        loads the start address into s0, fires the startup
        AccessRegisterRead(X9, postexec=True) (the read returns old s1 as
        garbage and runs the first progbuf load), enables autoexecdata[0]
        so each DATA0 read auto-triggers command re-execution, reads
        DATA0 count times (discarding the first garbage value), disables
        autoexecdata and reads DATA0 one more time for the last value,
        and restores s1 and s0.

        Args:
            address: Start memory address (must be aligned to size)
            count: Number of words to read (must be >= 1)
            size: Access size in bits. Only 32 supported currently.

        Returns:
            List of count integers read from memory.

        Raises:
            RiscvError: If program buffer not available or too small
            ValueError: If count < 1 or size unsupported

        Requires:
            progbufsize >= 2 (with impebreak) or >= 3 (without impebreak)
        """
        if not self.available:
            raise RiscvError(
                "Program buffer not available for batch read (progbufsize=0)"
            )
        if count < 1:
            raise ValueError("count must be >= 1")
        if size != 32:
            raise RiscvError(
                f"Sub-word batch read not yet supported (size={size}), "
                f"use size=32"
            )

        # Validate progbuf size: 2 instructions need 2 (+1 without impebreak)
        min_size = 2 if self._has_impebreak else 3
        if self._size < min_size:
            raise RiscvError(
                f"Program buffer too small for batch access "
                f"(progbufsize={self._size}, need >={min_size})"
            )

        # Single-word: delegate to single-word method
        if count == 1:
            return [self.read_memory(address)]

        stride = size // 8
        lw_insn = RiscvInstr.lw(9, 8, 0)              # LW s1, 0(s0)
        addi_insn = RiscvInstr.addi(8, 8, stride)       # ADDI s0, s0, stride

        # Save s0 and s1 (need values for later restore)
        s0_saved = self._abstract.read_register(RiscvRegno.X8)
        s1_saved = self._abstract.read_register(RiscvRegno.X9)

        try:
            # Combined: write progbuf + address write in ONE USB transfer.
            # PROGBUF writes and ABSTRACTCS+DATA0+COMMAND are all DMI register
            # writes — no response needed between them. Saves 1 USB transfer
            # vs separate flush_deferred() + write_register_batched().
            self._dmi.start_deferred()
            self.write_program([lw_insn, addi_insn])
            self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
            self._dmi.write(DMReg.DATA0, address)
            cmd_addr = Command.build_access_register_write(RiscvRegno.X8)
            self._dmi.write(DMReg.COMMAND, cmd_addr)
            self._dmi.flush_deferred()
            abstractcs = self._abstract._poll_busy()
            self._abstract._check_cmderr(abstractcs)

            # Startup: read s1 with postexec (batched: clear+COMMAND → 1 USB)
            # After this: DATA0 = old s1 (garbage), s1 = mem[addr]
            # NOTE: ABSTRACTAUTO must be written AFTER this AC completes,
            # not in the same batch — some hardware sets cmderr=BUSY when
            # autoexecdata is enabled while an AC is still executing.
            cmd = Command.build_access_register_read(
                RiscvRegno.X9, postexec=True
            )
            # Capture for busy recovery to re-arm COMMAND after it gets
            # clobbered by access_register_read(X8) in _determine_progress.
            self._autoexec_command = cmd
            self._dmi.start_deferred()
            self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
            self._dmi.write(DMReg.COMMAND, cmd)
            self._dmi.flush_deferred()
            abstractcs = self._abstract._poll_busy()
            self._abstract._check_cmderr(abstractcs)

            # Enable autoexecdata[0]: DATA0 reads auto-trigger command
            self._dmi.write(DMReg.ABSTRACTAUTO,
                            AbstractAuto.enable_autoexecdata(0))

            try:
                # Apply learned autoexec-batch idle (instance-level, persists
                # across calls for adaptive backoff). The active override is
                # scoped to this loop only — cleared in finally so non-autoexec
                # DMI traffic (s0/s1 restore below, status reads) keeps the
                # short base idle (fix for code-review finding #1: override
                # leak inflated all DMI latency session-wide).
                if self._learned_batch_idle is None:
                    self._learned_batch_idle = AUTOEXECDATA_IDLE_CYCLES
                self._dmi.dtm.state.batch_idle_override = self._learned_batch_idle

                # Priming read: drain startup garbage from DATA0 + trigger
                # one autoexec so DATA0=M[addr] (first good word). After
                # this, loop read-k returns exactly M[addr+(k-1)*stride].
                # Runs UNDER the override
                # (60-TCK idle) so the priming autoexec doesn't race. Check
                # cmderr (review R1+R3: enable-autoexec window can set BUSY).
                priming_cs = self._poll_busy_safe_after_read()
                self._abstract._check_cmderr(priming_cs)

                # Loop reads exactly `count` good words (primed pipeline).
                raw_results = self._read_autoexec_loop(
                    address, count, stride
                )

                # Batch: disable autoexecdata + read ABSTRACTCS → 1 USB transfer
                self._dmi.start_deferred()
                self._dmi.write(DMReg.ABSTRACTAUTO,
                                AbstractAuto.disable_all())
                self._dmi.read(DMReg.ABSTRACTCS)
                raw = self._dmi.flush_deferred_raw()
                # raw[0] = (junk, status) from ABSTRACTAUTO write
                # raw[1] = (abstractcs_value, dmi_status) from ABSTRACTCS read
                abstractcs = raw[1][0]
                cmderr = AbstractCS.parse_cmderr(abstractcs)
                if cmderr != AbstractCmdErr.NONE:
                    self._dmi.write(DMReg.ABSTRACTCS,
                                    AbstractCS.build_clear_cmderr())
                    if cmderr == AbstractCmdErr.BUSY:
                        raise RiscvError(
                            f"Abstract command busy during batch read. "
                            f"Retry the batch operation."
                        )
                    raise RiscvError(
                        f"Auto-exec error during batch read (cmderr={cmderr})"
                    )

                # Primed pipeline: all count reads are good (no garbage).
                return raw_results
            except Exception:
                # Ensure autoexecdata is disabled on error
                try:
                    self._dmi.write(DMReg.ABSTRACTAUTO,
                                    AbstractAuto.disable_all())
                except Exception:
                    pass
                raise
        finally:
            # Clear active override BEFORE s0/s1 restore so the restore's
            # _execute_batch uses the short base idle, not the autoexec idle.
            self._dmi.dtm.state.batch_idle_override = None
            # Restore s1 first, then s0 (batched: 2 USB each vs 5)
            self._abstract.write_register_batched(RiscvRegno.X9, s1_saved)
            self._abstract.write_register_batched(RiscvRegno.X8, s0_saved)

    def write_memory_batch(self, address: int, values: List[int],
                           size: int = 32) -> None:
        """Write multiple consecutive memory words via program buffer.

        Uses DM_ABSTRACTAUTO.autoexecdata to eliminate per-word COMMAND writes.
        Each DATA0 write automatically triggers command re-execution, reducing
        per-word cost from ~5 DMI ops to ~1 DMI op.

        Saves s0 and s1, writes the store/increment program to the progbuf,
        loads the start address into s0, fires the startup write (first
        value to DATA0 plus AccessRegisterWrite(X9, postexec=True)),
        enables autoexecdata[0] so each DATA0 write auto-triggers command
        re-execution, loops the remaining values through DATA0 (each
        auto-triggers the store and the address increment), disables
        autoexecdata, and restores s1 and s0.

        Args:
            address: Start memory address (must be aligned to size)
            values: List of values to write (must have >= 1 element)
            size: Access size in bits. Only 32 supported currently.

        Raises:
            RiscvError: If program buffer not available or too small
            ValueError: If values is empty or size unsupported

        Requires:
            progbufsize >= 2 (with impebreak) or >= 3 (without impebreak)
        """
        if not self.available:
            raise RiscvError(
                "Program buffer not available for batch write (progbufsize=0)"
            )
        if not values:
            raise ValueError("values must not be empty")
        if size != 32:
            raise RiscvError(
                f"Sub-word batch write not yet supported (size={size}), "
                f"use size=32"
            )

        # Validate progbuf size
        min_size = 2 if self._has_impebreak else 3
        if self._size < min_size:
            raise RiscvError(
                f"Program buffer too small for batch access "
                f"(progbufsize={self._size}, need >={min_size})"
            )

        # Single-word: delegate to single-word method
        if len(values) == 1:
            self.write_memory(address, values[0])
            return

        stride = size // 8
        sw_insn = RiscvInstr.sw(9, 8, 0)              # SW s1, 0(s0)
        addi_insn = RiscvInstr.addi(8, 8, stride)       # ADDI s0, s0, stride

        # Save s0 and s1
        s0_saved = self._abstract.read_register(RiscvRegno.X8)
        s1_saved = self._abstract.read_register(RiscvRegno.X9)

        try:
            # Combined: write progbuf + address write in ONE USB transfer.
            # Saves 1 USB vs separate flush_deferred() + write_register_batched().
            self._dmi.start_deferred()
            self.write_program([sw_insn, addi_insn])
            self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
            self._dmi.write(DMReg.DATA0, address)
            cmd_addr = Command.build_access_register_write(RiscvRegno.X8)
            self._dmi.write(DMReg.COMMAND, cmd_addr)
            self._dmi.flush_deferred()
            abstractcs = self._abstract._poll_busy()
            self._abstract._check_cmderr(abstractcs)

            # Startup: write first value + execute with postexec
            # NOTE: ABSTRACTAUTO must be written AFTER this AC completes,
            # not in the same batch — some hardware sets cmderr=BUSY when
            # autoexecdata is enabled while an AC is still executing.
            cmd = Command.build_access_register_write(
                RiscvRegno.X9, postexec=True
            )
            # Capture for busy recovery to re-arm COMMAND after it gets
            # clobbered by access_register_read(X8) in _determine_progress.
            self._autoexec_command = cmd
            self._dmi.start_deferred()
            self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
            self._dmi.write(DMReg.DATA0, values[0])
            self._dmi.write(DMReg.COMMAND, cmd)
            self._dmi.flush_deferred()
            abstractcs = self._abstract._poll_busy()
            self._abstract._check_cmderr(abstractcs)

            # Enable autoexecdata[0]: DATA0 writes auto-trigger command
            self._dmi.write(DMReg.ABSTRACTAUTO,
                            AbstractAuto.enable_autoexecdata(0))

            try:
                # Apply learned autoexec-batch idle (instance-level, persists
                # across calls for adaptive backoff). Active override scoped
                # to this loop only — cleared in finally so non-autoexec DMI
                # traffic keeps the short base idle (code-review fix #1).
                if self._learned_batch_idle is None:
                    self._learned_batch_idle = AUTOEXECDATA_IDLE_CYCLES
                self._dmi.dtm.state.batch_idle_override = self._learned_batch_idle

                # Write remaining values with per-response busy recovery.
                # _write_autoexec_loop uses deferred mode to batch writes
                # in one USB transfer, but checks each DMI response status.
                self._write_autoexec_loop(
                    address, values[1:], stride
                )

                # Disable autoexecdata
                self._dmi.write(DMReg.ABSTRACTAUTO,
                                AbstractAuto.disable_all())

                # Check for errors during auto-execution
                abstractcs = self._dmi.read(DMReg.ABSTRACTCS)
                cmderr = AbstractCS.parse_cmderr(abstractcs)
                if cmderr != AbstractCmdErr.NONE:
                    self._dmi.write(DMReg.ABSTRACTCS,
                                    AbstractCS.build_clear_cmderr())
                    raise RiscvError(
                        f"Auto-exec error during batch write (cmderr={cmderr})"
                    )
            except Exception:
                # Ensure autoexecdata is disabled on error
                try:
                    self._dmi.write(DMReg.ABSTRACTAUTO,
                                    AbstractAuto.disable_all())
                except Exception:
                    pass
                raise
        finally:
            # Clear active override BEFORE s0/s1 restore so the restore's
            # _execute_batch uses the short base idle, not the autoexec idle.
            self._dmi.dtm.state.batch_idle_override = None
            # Restore s1 first, then s0 (batched: 2 USB each vs 5)
            self._abstract.write_register_batched(RiscvRegno.X9, s1_saved)
            self._abstract.write_register_batched(RiscvRegno.X8, s0_saved)