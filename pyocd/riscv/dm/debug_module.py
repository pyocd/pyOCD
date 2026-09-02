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
RISC-V Debug Module unified interface.

This is the top-level class for RISC-V debug operations, providing
a unified API over Abstract Commands, Program Buffer, and System Bus Access.

Architecture: DTM -> DMI -> DebugModule
                              -> AbstractCommands
                              -> ProgramBuffer
                              -> SystemBusAccess

Reference: RISC-V Debug Spec v0.13.2 §3 (Debug Module)
"""

import logging
import time
from typing import Callable, List, Optional, Union

from ..dtm.jtag_dtm import JtagDtm, RiscvError
from ..dmi.dmi import DMI
from .registers import (
    DMReg, AbstractCS, AbstractCmdErr, Command, DMControl, DMStatus,
    RiscvRegno,
)
from .abstract_commands import AbstractCommands, AbstractCommandError
from .program_buffer import ProgramBuffer
from .system_bus_access import SystemBusAccess, SBAError

LOG = logging.getLogger(__name__)


class DebugModule:
    """Unified Debug Module interface.

    Provides a single entry point for all RISC-V debug operations:
    - Register access (abstract commands / program buffer fallback)
    - Memory access (SBA / program buffer / abstract commands)
    - Hart control (halt / resume / reset)

    Design principles:
    - dmcontrol state caching to prevent bit loss
    - Automatic method selection with fallback
    - Capability detection on init
    - Fast-path for common operations

    Usage:
        probe = ...  # DebugProbe
        dm = DebugModule(probe)
        dm.init()
        dm.halt_hart()
        pc = dm.read_register(RiscvRegno.DPC)
        dm.resume_hart()
    """

    # Timeout for halt/resume DMSTATUS polling (seconds).
    _HALT_TIMEOUT_SEC = 5.0
    _RESUME_TIMEOUT_SEC = 5.0

    def __init__(self, probe, is_cjtag=None):
        """Initialize Debug Module with layered architecture.

        Args:
            probe: DebugProbe instance with JTAG capability
            is_cjtag: Override cJTAG mode detection. None=auto-detect from probe.
        """
        # Layer 1: DTM (JTAG transport)
        self._dtm = JtagDtm(probe, is_cjtag=is_cjtag)
        # Layer 2: DMI (register access)
        self._dmi = DMI(self._dtm)
        # Layer 3: DM sub-modules
        self._abstract = AbstractCommands(self._dmi)
        self._progbuf = ProgramBuffer(self._dmi, self._abstract)
        self._sysbus = SystemBusAccess(self._dmi)

        # dmcontrol state cache to preserve bit settings across writes
        self._current_dmcontrol = 0

        # Detected capabilities
        self._datacount = 0
        self._progbufsize = 0
        self._impebreak = False
        self._hasresethaltreq = False

        # Multi-hart state
        self._num_harts = 1
        self._hartsellen = 0
        self._enabled_harts = 1  # hart 0 always exists
        self._last_selected_hart = 0

        # Registers known to require progbuf (populated on first fallback).
        # Avoids repeated abstract-command-failure overhead for vendor CSRs.
        self._progbuf_preferred: set = set()

        # SRST-once guard: set True by perform_srst_prelude(), checked by
        # the SoC-level reset() caller so a dual-core reset does not
        # double-pulse SRST. Cleared by the SoC-level reset() caller after
        # delegating to per-core reset.
        self._srst_pulsed: bool = False

    def lock(self) -> None:
        """Acquire JTAG transport lock.

        Delegates to DTM which delegates to probe's RLock.
        Used by RISCVCore to serialize hart selection + operation.
        """
        self._dtm.lock()

    def unlock(self) -> None:
        """Release JTAG transport lock."""
        self._dtm.unlock()

    @property
    def is_cjtag(self) -> bool:
        """True iff the underlying DTM is in cJTAG (OScan1) mode.

        SRST eligibility and certain transport workarounds branch on this.
        Delegates to the JtagDtm so callers depend on a single source of
        truth (override or auto-detected at construction).
        """
        return self._dtm.is_cjtag

    def srst_eligible(self) -> bool:
        """True iff a hardware SRST prelude can run now.

        Requires the probe to advertise ``Capability.RESET_ASSERT`` (a JTAG
        probe that can drive nRESET, e.g. fireDAP / FTDI) and a plain JTAG
        link. cJTAG's OScan1 scan format is destroyed by the TLR-during-SRST
        step, so SRST prelude must not run on cJTAG links (caller falls back
        to sw / ndmreset).
        """
        from ...probe.debug_probe import DebugProbe
        if self.is_cjtag:
            return False
        return DebugProbe.Capability.RESET_ASSERT in self._dtm.probe.capabilities

    def perform_srst_prelude(self, settle_ms: Optional[int] = None) -> bool:
        """Assert hardware SRST, re-init DTM, verify dmactive.

        Drives nRESET low via ``probe.assert_reset(True)``, TLR-resets the
        TAP through TMS (``dtm._tap_tlr_reset()``) while nRESET is
        asserted, releases nRESET via ``probe.assert_reset(False)``,
        sleeps the post-release settle, re-inits the DTM via ``dtm.init()``
        (SRST may perturb TAP), and verifies ``dmactive == 1`` — falling
        back to a minimal re-activate (write dmactive=1, brief sleep,
        re-read; warn if still 0). Per IEEE 1149.1 §5.2 the
        TLR-mid-SRST sequence is what re-samples the boot strap without
        a power-cycle.

        Args:
            settle_ms: Override the post-release settle in ms. When ``None``
                (production path), the value comes from the
                ``riscv.srst_settle_ms`` session option (default 500; long
                enough for SRST-domain peripherals to release). Tests pass
                an explicit value (e.g. 0) to bypass the option read,
                keeping the method unit-testable without a fake session.

        Returns:
            True (SRST was asserted). Sets ``self._srst_pulsed`` so the
            SoC-level reset() caller can enforce once-per-SoC.
        """
        # Re-activate settle: allow time for dmactive to latch
        # across the reset domain after a dmactive=1 write
        # following a lost-dmactive recovery.
        REACTIVATE_SETTLE_SEC = 0.05

        if settle_ms is None:
            # OptionsManager.get() takes only the key (no default arg); the
            # registered default (riscv.srst_settle_ms = 500) applies when unset.
            # None-guard defends against an unregistered option lookup.
            settle_ms = self._dtm.probe.session.options.get('riscv.srst_settle_ms')
            if settle_ms is None:
                settle_ms = 500
        settle_s = settle_ms / 1000.0

        # Three separate synchronous USB transactions (assert, TLR, release),
        # each flushed, so nRESET-low spans the USB round-trips.
        # No Python hold sleep or read-back; the round-trip
        # gap IS the nRESET-low duration.
        LOG.info("SRST prelude: asserting nRESET")
        self._dtm.probe.assert_reset(True)    # DAP_SWJ_PINS assert (sync)
        self._dtm.probe.flush()
        try:
            self._dtm._tap_tlr_reset()        # DAP_SWJ_SEQ TLR
            self._dtm.probe.flush()           # flush so TLR is its own USB op, not batched with release
        finally:
            self._dtm.probe.assert_reset(False)  # DAP_SWJ_PINS release (sync)
        time.sleep(settle_s)
        self._dtm.init()

        # Verify dmactive survived the SRST; re-activate if lost.
        dmcontrol = self._dmi.read(DMReg.DMCONTROL)
        if not DMControl.parse_dmactive(dmcontrol):
            LOG.warning("SRST prelude: dmactive==0 after reset; re-activating DM")
            self._dmi.write(DMReg.DMCONTROL, DMControl.build_dmactive())
            time.sleep(REACTIVATE_SETTLE_SEC)
            dmcontrol = self._dmi.read(DMReg.DMCONTROL)
            if not DMControl.parse_dmactive(dmcontrol):
                LOG.warning("SRST prelude: dmactive still 0 after re-activate; "
                            "downstream ndmreset sequence will retry")

        self._srst_pulsed = True
        return True

    def init(self, pre_hart_discover: Union[Callable, List[Callable], None] = None) -> None:
        """Initialize Debug Module (examine path: DTM + DM reset + discovery).

        Examine does NOT halt or ndmreset the hart. Halt is the job of
        halt_on_connect (connect_mode) or reset_and_halt, both of which have
        their own complete sequences. Doing ndmreset in examine pushes some
        harts into unavail where haltreq is ineffective (RISC-V Debug Spec
        §3.4). Examine only sets up the DM, not hart state.

        The examine sequence (RISC-V Debug Spec §3.1 dmactive handshake):
        init the DTM (TAP reset, IDCODE, DTMCS); reset the DM by writing
        dmactive=0 then dmactive=1 to clear stale DM state; detect
        capabilities; invoke any pre_hart_discover callback(s); discover
        harts via dmcontrol/dmstatus status bits only.

        Raises:
            RiscvError: If initialization fails
        """
        # Init DTM
        self._dtm.init()

        # Reset DM (dmactive=0 → dmactive=1)
        # Writing dmactive=0 resets all DM state. This is necessary when
        # the DM was already active from a previous session (board still
        # powered) to clear stale DM state. dmactive does NOT halt the hart.
        self._write_dmcontrol(0)  # dmactive=0
        time.sleep(0.01)          # Wait for DM to acknowledge reset

        self._write_dmcontrol(DMControl.build_dmactive())  # dmactive=1
        time.sleep(0.01)          # Wait for DM to initialize

        # Verify dmactive
        dmcontrol = self._dmi.read(DMReg.DMCONTROL)
        if not DMControl.parse_dmactive(dmcontrol):
            raise RiscvError("Failed to activate Debug Module")

        # NOTE: no ndmreset/halt here on purpose — see docstring.
        # reset_and_halt carries its own ndmreset +
        # sticky-halt-on-reset, so removing it from examine loses nothing.

        # Detect capabilities
        self._detect_capabilities()

        # Pre-hart-discover callback(s) (for SoC-specific hart release)
        if pre_hart_discover is not None:
            callbacks = pre_hart_discover if isinstance(pre_hart_discover, list) else [pre_hart_discover]
            for cb in callbacks:
                cb()

        # Discover harts
        self._discover_harts()

    def _detect_capabilities(self) -> None:
        """Detect DM capabilities from registers.

        Reads:
        - abstractcs -> datacount, progbufsize
        - dmstatus -> impebreak, hasresethaltreq
        - sbcs -> SBA capabilities
        - progbuf -> program buffer availability
        """
        # AbstractCS
        abstractcs = self._dmi.read(DMReg.ABSTRACTCS)
        self._datacount = AbstractCS.parse_datacount(abstractcs)
        self._progbufsize = AbstractCS.parse_progbufsize(abstractcs)

        # DMStatus
        dmstatus = self._dmi.read(DMReg.DMSTATUS)
        self._impebreak = DMStatus.parse_impebreak(dmstatus)
        self._hasresethaltreq = DMStatus.parse_hasresethaltreq(dmstatus)

        # Program Buffer
        if hasattr(self, '_progbuf') and self._progbuf is not None:
            self._progbuf.detect_capabilities()

        # System Bus Access
        if hasattr(self, '_sysbus') and self._sysbus is not None:
            self._sysbus.detect_capabilities()

    def _write_dmcontrol(self, value: int) -> None:
        """Write dmcontrol with state caching.

        Always updates cache to prevent losing other dmcontrol bits
        when modifying specific fields.

        Args:
            value: Full dmcontrol value to write
        """
        self._dmi.write(DMReg.DMCONTROL, value)
        self._current_dmcontrol = value

    # ========== Register Access ==========

    def read_register(self, regno: int, method: str = 'auto') -> int:
        """Read register with automatic method selection.

        With ``method='auto'`` the program buffer wins when cached as
        preferred for this register; otherwise the abstract command is
        attempted and the program buffer is the fallback on NOT_SUPPORTED
        or EXCEPTION for CSRs.

        Args:
            regno: Register number (see RiscvRegno)
            method: 'auto', 'abstract', or 'progbuf'

        Returns:
            32-bit register value

        Raises:
            AbstractCommandError: If register read fails
            RiscvError: If method not available
        """
        if method == 'auto':
            if regno in self._progbuf_preferred:
                return self._progbuf.read_csr(regno)
            try:
                return self._abstract.read_register(regno)
            except AbstractCommandError as e:
                is_csr = 0x000 <= regno <= 0xFFF
                if (is_csr
                        and e.cmderr in (AbstractCmdErr.NOT_SUPPORTED,
                                         AbstractCmdErr.EXCEPTION)
                        and self._progbuf.available):
                    LOG.debug("read_register 0x%04x: abstract cmderr=%d, "
                              "falling back to progbuf", regno, e.cmderr)
                    result = self._progbuf.read_csr(regno)
                    self._progbuf_preferred.add(regno)
                    return result
                raise
        elif method == 'abstract':
            return self._abstract.read_register(regno)
        elif method == 'progbuf':
            return self._progbuf.read_csr(regno)
        else:
            raise RiscvError(f"Unknown register read method: {method}")

    def write_register(self, regno: int, value: int,
                       method: str = 'auto') -> None:
        """Write register with automatic method selection.

        Args:
            regno: Register number (see RiscvRegno)
            value: 32-bit value to write
            method: 'auto', 'abstract', or 'progbuf'

        Raises:
            AbstractCommandError: If register write fails
            RiscvError: If method not available
        """
        if method == 'auto':
            if regno in self._progbuf_preferred:
                self._progbuf.write_csr(regno, value)
                return
            try:
                self._abstract.write_register(regno, value)
            except AbstractCommandError as e:
                is_csr = 0x000 <= regno <= 0xFFF
                if (is_csr
                        and e.cmderr in (AbstractCmdErr.NOT_SUPPORTED,
                                         AbstractCmdErr.EXCEPTION)
                        and self._progbuf.available):
                    self._progbuf.write_csr(regno, value)
                    self._progbuf_preferred.add(regno)
                    return
                raise
        elif method == 'abstract':
            self._abstract.write_register(regno, value)
        elif method == 'progbuf':
            self._progbuf.write_csr(regno, value)
        else:
            raise RiscvError(f"Unknown register write method: {method}")

    def write_registers_batch(self, pairs: list) -> None:
        """Write multiple registers using batched abstract commands.

        Uses write_register_batched for reduced USB transfers: 2 per register
        instead of 4. Caller must ensure registers are supported via abstract
        commands (all GPRs and standard CSRs are).

        Args:
            pairs: List of (regno, value) tuples

        Raises:
            AbstractCommandError: If any register write fails
        """
        for regno, value in pairs:
            self._abstract.write_register_batched(regno, value)

    # ========== Memory Access ==========

    def read_memory(self, address: int, size: int = 32,
                    method: str = 'auto') -> int:
        """Read memory, hart-view mechanism first.

        The program buffer (hart view) reaches hart-local memory that the
        system bus cannot. Sizes 8/16/32 dispatch to the program buffer when
        available; sizes the program buffer cannot serve (64/128) and the
        system-bus fallback path go straight to SBA. Per the RISC-V Debug Spec
        (Program Buffer section), the program buffer executes a hart load, so sub-word access
        returns the zero-extended value at the hart-local address. A progbuf
        runtime error propagates (no SBA fallback) so misaligned/exception
        failures stay loud.

        Args:
            address: Target memory address.
            size: Access size in bits (8, 16, 32, 64, 128).
            method: 'auto', 'sysbus', or 'progbuf'.

        Returns:
            Read value.

        Raises:
            RiscvError: If no access method available, or progbuf runtime error.
        """
        if method == 'auto':
            if size in (8, 16, 32) and self._progbuf.available:
                return self._progbuf.read_memory(address, size)
            if self._sysbus.available:
                return self._sysbus.read_memory(address, size)
            raise RiscvError("No memory access method available")
        elif method == 'sysbus':
            return self._sysbus.read_memory(address, size)
        elif method == 'progbuf':
            return self._progbuf.read_memory(address, size)
        else:
            raise RiscvError(f"Unknown memory read method: {method}")

    def read_memory_batch(self, address: int, count: int,
                          size: int = 32,
                          method: str = 'auto') -> list:
        """Read consecutive memory words in batch.

        Uses SBA batch read when available, falls back to per-word
        reads otherwise. Significantly reduces USB overhead for
        block reads (e.g., GDB compare-sections).

        Args:
            address: Start memory address
            count: Number of words to read
            size: Access size in bits
            method: 'auto', 'sysbus', or 'progbuf'

        Returns:
            List of read values

        Raises:
            RiscvError: If no access method available
        """
        if count < 1:
            return []
        if method == 'auto':
            # progbuf first (hart-local correctness).
            # progbuf read batch (autoexecdata) is correct for all loads
            # (progbuf priming + AC-busy re-prime). SBA batch is
            # fallback for progbuf-inaccessible system addresses.
            if size == 32 and self._progbuf.available:
                try:
                    return self._progbuf.read_memory_batch(address, count, size)
                except RiscvError:
                    pass
            if self._sysbus.available:
                try:
                    return self._sysbus.read_memory_batch(address, count, size)
                except SBAError:
                    raise
            raise RiscvError("No memory access method available")
        elif method == 'sysbus':
            return self._sysbus.read_memory_batch(address, count, size)
        elif method == 'progbuf':
            return [self._progbuf.read_memory(address + i * (size // 8), size)
                    for i in range(count)]
        else:
            raise RiscvError(f"Unknown memory read method: {method}")

    def write_memory(self, address: int, value: int, size: int = 32,
                     method: str = 'auto') -> None:
        """Write memory, hart-view mechanism first.

        Same dispatch shape as read_memory: 8/16/32 to the program buffer
        (hart view), 64/128 and fallback to the system bus. See read_memory.

        Args:
            address: Target memory address.
            value: Value to write.
            size: Access size in bits.
            method: 'auto', 'sysbus', or 'progbuf'.

        Raises:
            RiscvError: If no access method available, or progbuf runtime error.
        """
        if method == 'auto':
            if size in (8, 16, 32) and self._progbuf.available:
                self._progbuf.write_memory(address, value, size)
                return
            if self._sysbus.available:
                self._sysbus.write_memory(address, value, size)
                return
            raise RiscvError("No memory access method available")
        elif method == 'sysbus':
            self._sysbus.write_memory(address, value, size)
        elif method == 'progbuf':
            self._progbuf.write_memory(address, value, size)
        else:
            raise RiscvError(f"Unknown memory write method: {method}")

    def write_memory_batch(self, address: int, values: list,
                           size: int = 32,
                           method: str = 'auto') -> None:
        """Write consecutive memory words in batch.

        Uses SBA batch write when available, falls back to per-word
        writes otherwise.

        Args:
            address: Start memory address
            values: List of values to write
            size: Access size in bits
            method: 'auto', 'sysbus', or 'progbuf'

        Raises:
            RiscvError: If no access method available
        """
        if not values:
            return
        if method == 'auto':
            # progbuf first (hart-local correctness),
            # then SBA batch, then per-word fallback.
            if size == 32 and self._progbuf.available:
                try:
                    self._progbuf.write_memory_batch(address, values, size)
                    return
                except RiscvError:
                    pass
            if self._sysbus.available:
                try:
                    self._sysbus.write_memory_batch(address, values, size)
                    return
                except SBAError:
                    pass
            for i, v in enumerate(values):
                self.write_memory(address + i * (size // 8), v, size)
        elif method == 'sysbus':
            self._sysbus.write_memory_batch(address, values, size)
        else:
            for i, v in enumerate(values):
                self.write_memory(
                    address + i * (size // 8), v, size)

    # ========== Hart Control ==========

    def halt_hart(self) -> None:
        """Halt hart by setting haltreq, waiting for halt, then clearing.

        Per RISC-V Debug Spec v0.13.2, haltreq is WARZ (level-sensitive):
        Writing 0 clears the halt request and may cancel outstanding requests.
        Therefore haltreq must stay 1 until the hart actually halts.

        The halt sequence (RISC-V Debug Spec v0.13.2 §3.4) writes
        haltreq=1, polls DMSTATUS until allhalted latches, and clears
        haltreq=0 once the hart is halted.
        """
        dmi = self._dmi

        # If the hart is in havereset-pending-ack state (e.g. just released
        # from reset by a pre-discover or post-reset hook), haltreq has no
        # effect — RISC-V Debug Spec v0.13 §3.4.2 requires ackhavereset to
        # clear the sticky havereset/unavail state before the hart responds
        # to halt. Without this, halt_hart polls forever on a freshly-released
        # hart (dmstatus shows allunavail=1, allhavereset=1, allhalted=0).
        dmstatus = dmi.read(DMReg.DMSTATUS)
        if DMStatus.parse_allhavereset(dmstatus) or DMStatus.parse_allunavail(dmstatus):
            dmi.write(DMReg.DMCONTROL,
                     self._current_dmcontrol | (1 << DMControl.ACKHAVERESET_BIT))
            LOG.debug("halt_hart: wrote ackhavereset (havereset=%s unavail=%s)",
                     DMStatus.parse_allhavereset(dmstatus),
                     DMStatus.parse_allunavail(dmstatus))

        # Set haltreq=1 (keep it set until hart halts)
        dmcontrol = DMControl.build_haltreq(self._current_dmcontrol)
        dmi.write(DMReg.DMCONTROL, dmcontrol)
        self._current_dmcontrol = dmcontrol

        # Poll DMSTATUS until hart halts
        deadline = time.monotonic() + self._HALT_TIMEOUT_SEC
        poll_count = 0
        while time.monotonic() < deadline:
            dmstatus = dmi.read(DMReg.DMSTATUS)
            poll_count += 1
            if DMStatus.parse_allhalted(dmstatus):
                break
        else:
            # Timeout — clear haltreq before raising
            LOG.error("halt_hart timeout after %d polls, dmstatus=0x%08x",
                      poll_count, dmstatus)
            dmcontrol = DMControl.clear_haltreq(self._current_dmcontrol)
            dmi.write(DMReg.DMCONTROL, dmcontrol)
            self._current_dmcontrol = dmcontrol
            raise TimeoutError("Hart halt timeout")

        # Clear haltreq now that hart is halted
        dmcontrol = DMControl.clear_haltreq(self._current_dmcontrol)
        dmi.write(DMReg.DMCONTROL, dmcontrol)
        self._current_dmcontrol = dmcontrol

    def resume_hart(self) -> None:
        """Resume hart by setting resumereq, waiting for resumeack, then clearing.

        Per RISC-V Debug Spec v0.13.2, resumereq is W1 (write-1-only):
        writing 0 has no effect. We still clear resumereq after confirming
        resume via resumeack for symmetric bit accounting.

        The resume sequence (RISC-V Debug Spec v0.13.2 §3.4) writes
        resumereq=1, polls DMSTATUS for allresumeack, and clears
        resumereq=0 once resume is acknowledged.
        """
        dmi = self._dmi

        # Set resumereq=1
        dmcontrol = DMControl.build_resumereq(self._current_dmcontrol)
        dmi.write(DMReg.DMCONTROL, dmcontrol)
        self._current_dmcontrol = dmcontrol

        # Poll DMSTATUS for resumeack
        deadline = time.monotonic() + self._RESUME_TIMEOUT_SEC
        dmstatus = 0
        while time.monotonic() < deadline:
            dmstatus = dmi.read(DMReg.DMSTATUS)
            if DMStatus.parse_allresumeack(dmstatus):
                break
        else:
            raise TimeoutError(f"resume_hart: resumeack timeout, dmstatus=0x{dmstatus:08x}")

        # Clear resumereq
        dmcontrol = DMControl.clear_resumereq(self._current_dmcontrol)
        dmi.write(DMReg.DMCONTROL, dmcontrol)
        self._current_dmcontrol = dmcontrol

    # ========== Properties ==========

    @property
    def capabilities(self) -> dict:
        """Report detected capabilities."""
        return {
            'datacount': self._datacount,
            'progbufsize': self._progbufsize,
            'impebreak': self._impebreak,
            'has_sba': self._sysbus.available,
            'hasresethaltreq': self._hasresethaltreq,
            'num_harts': self._num_harts,
            'hartsellen': self._hartsellen,
            'enabled_harts': self._enabled_harts,
        }

    @property
    def hasresethaltreq(self) -> bool:
        """Whether DM supports setresethaltreq/clrresethaltreq."""
        return self._hasresethaltreq

    @property
    def abstract(self) -> AbstractCommands:
        """Direct access to Abstract Commands."""
        return self._abstract

    @property
    def progbuf(self) -> ProgramBuffer:
        """Direct access to Program Buffer."""
        return self._progbuf

    @property
    def sysbus(self) -> SystemBusAccess:
        """Direct access to System Bus."""
        return self._sysbus

    # ========== Multi-Hart Support ==========

    def _discover_harts(self) -> None:
        """Discover available harts.

        Determines hartsellen by writing 0xFFFFFFFF to hartsel and reading
        back the truncated value, enumerates harts via the anynonexistent
        status bit, and tracks enabled harts in a bitmask.

        Reference: RISC-V Debug Spec v0.13.2 §3.4 (hartsel/anynonexistent)
        """
        # Determine hartsellen
        dmcontrol = DMControl.build_dmactive()
        dmcontrol = DMControl.set_hartsel(dmcontrol, 0xFFFFF)
        self._write_dmcontrol(dmcontrol)

        dmcontrol_read = self._dmi.read(DMReg.DMCONTROL)
        hartsel_readback = DMControl.parse_hartsel(dmcontrol_read)
        self._hartsellen = bin(hartsel_readback).count('1')

        max_hart_index = 1 << self._hartsellen

        LOG.debug("hartsellen=%d, max_hart_index=%d", self._hartsellen, max_hart_index)

        # Hart discovery
        # Hart 0 always exists
        self._num_harts = 1
        self._enabled_harts = 1  # bit 0 = hart 0

        # Check if anynonexistent is functional by selecting max hart
        dmcontrol = DMControl.build_dmactive()
        dmcontrol = DMControl.set_hartsel(dmcontrol, max_hart_index - 1)
        self._write_dmcontrol(dmcontrol)

        dmstatus = self._dmi.read(DMReg.DMSTATUS)

        LOG.debug("max hart dmstatus=0x%08x, anynonexistent=%s",
                  dmstatus, DMStatus.parse_anynonexistent(dmstatus))

        if DMStatus.parse_anynonexistent(dmstatus):
            # Enumerate harts from 1 upward
            for hart_index in range(1, max_hart_index):
                dmcontrol = DMControl.build_dmactive()
                dmcontrol = DMControl.set_hartsel(dmcontrol, hart_index)
                self._write_dmcontrol(dmcontrol)

                dmstatus = self._dmi.read(DMReg.DMSTATUS)

                LOG.debug("hart %d: dmstatus=0x%08x, anynonexistent=%s, allunavail=%s",
                          hart_index, dmstatus,
                          DMStatus.parse_anynonexistent(dmstatus),
                          DMStatus.parse_allunavail(dmstatus))

                if DMStatus.parse_anynonexistent(dmstatus):
                    break

                # A hart may read allunavail transiently — e.g. when it was
                # just released from reset by a pre-discover hook and the
                # release effect has not yet propagated to the debug module.
                # Retry once after a short delay before concluding the hart
                # is permanently unavailable, so a slow-to-ready hart is not
                # silently dropped from _enabled_harts.
                if DMStatus.parse_allunavail(dmstatus):
                    import time as _time
                    for _ in range(5):
                        _time.sleep(0.01)
                        dmstatus = self._dmi.read(DMReg.DMSTATUS)
                        if not DMStatus.parse_allunavail(dmstatus):
                            break
                    LOG.debug("hart %d allunavail after retry loop: dmstatus=0x%08x",
                              hart_index, dmstatus)

                if not DMStatus.parse_allunavail(dmstatus):
                    self._enabled_harts |= 1 << self._num_harts

                self._num_harts += 1
        else:
            # anynonexistent not supported, assume single hart
            pass

        LOG.debug("Hart discovery done: num_harts=%d, enabled_harts=0x%x",
                  self._num_harts, self._enabled_harts)

        # Select hart 0 as default
        dmcontrol = DMControl.build_dmactive()
        dmcontrol = DMControl.set_hartsel(dmcontrol, 0)
        self._write_dmcontrol(dmcontrol)
        self._last_selected_hart = 0

    def select_hart(self, hart: int) -> None:
        """Select hart for subsequent operations.

        Args:
            hart: Hart index to select

        Raises:
            RiscvError: If hart is not enabled

        Reference: RISC-V Debug Spec v0.13.2 §3.4 (dmcontrol.hartsel)
        """
        if not self.hart_enabled(hart):
            raise RiscvError(f"Hart {hart} is not available")

        if self._last_selected_hart == hart:
            return

        # Read-modify-write dmcontrol with new hartsel
        dmcontrol = self._dmi.read(DMReg.DMCONTROL)
        dmcontrol = DMControl.set_hartsel(dmcontrol, hart)
        self._write_dmcontrol(dmcontrol)
        self._last_selected_hart = hart

    def hart_enabled(self, hart: int) -> bool:
        """Check if hart is enabled.

        Args:
            hart: Hart index to check

        Returns:
            True if hart is enabled
        """
        return bool(self._enabled_harts & (1 << hart))
