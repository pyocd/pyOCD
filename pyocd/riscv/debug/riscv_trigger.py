# pyOCD debugger
# Copyright (c) 2025 Ryan QIAN
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
RISC-V Trigger Module for hardware breakpoints and watchpoints.

Uses mcontrol (type=2) or mcontrol6 (type=6) address/data match triggers
per the RISC-V Debug Specification v0.13 (Sdtrig extension).

Trigger CSR programming follows Sdtrig WARL ordering: disable tdata1 so the
type field reads as "disabled", write the match value to tdata2, write the
desired configuration to tdata1, and read both back to confirm WARL accepted
the requested bits.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

from ...core.target import Target
from ...debug.breakpoints.provider import Breakpoint, BreakpointProvider
from ..dm.registers import RiscvRegno

if TYPE_CHECKING:
    from ...riscv.dm.debug_module import DebugModule

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# mcontrol (type=2) register bit field positions for RV32
# Source: RISC-V Debug Spec v0.13, Sdtrig, hwbp_registers.adoc
# ---------------------------------------------------------------------------

class MControl:
    """mcontrol (type=2) register bit field constants and builder for RV32.

    RV32 layout:
        [31:28] type      [27] dmode     [26:21] maskmax(RO)
        [20]    hit       [19] select    [18] timing
        [17:16] sizelo    [15:12] action [11] chain
        [10:7]  match     [6] m          [4] s  [3] u
        [2] execute       [1] store      [0] load
    """

    # Field positions (RV32)
    TYPE_SHIFT = 28
    TYPE_MASK = 0xF
    DMODE_SHIFT = 27
    MASKMAX_SHIFT = 21
    MASKMAX_MASK = 0x3F
    HIT_SHIFT = 20
    SELECT_SHIFT = 19
    TIMING_SHIFT = 18
    SIZELO_SHIFT = 16
    SIZELO_MASK = 0x3
    ACTION_SHIFT = 12
    ACTION_MASK = 0xF
    CHAIN_SHIFT = 11
    MATCH_SHIFT = 7
    MATCH_MASK = 0xF
    M_SHIFT = 6
    S_SHIFT = 4
    U_SHIFT = 3
    EXECUTE_SHIFT = 2
    STORE_SHIFT = 1
    LOAD_SHIFT = 0

    # Trigger type values
    TYPE_NONE = 0
    TYPE_MCONTROL = 2
    TYPE_ICOUNT = 3
    TYPE_ITRIGGER = 4
    TYPE_ETRIGGER = 5
    TYPE_MCONTROL6 = 6
    TYPE_TMEXTTRIGGER = 7
    TYPE_DISABLED = 15

    # Action values
    ACTION_BREAKPOINT_EXCEPTION = 0
    ACTION_ENTER_DEBUG_MODE = 1

    # Match values
    MATCH_EQUAL = 0
    MATCH_NAPOT = 1
    MATCH_GE = 2
    MATCH_LT = 3

    # Size values (sizelo field)
    SIZE_ANY = 0
    SIZE_8BIT = 1
    SIZE_16BIT = 2
    SIZE_32BIT = 3

    @staticmethod
    def build_hw_breakpoint() -> int:
        """Build tdata1 value for execute-address-match hardware breakpoint.

        Config: type=2, dmode=1, action=1(enter_debug), m=1, u=1,
                execute=1, match=0(equal), timing=0(before)
        """
        val = 0
        val |= (MControl.TYPE_MCONTROL << MControl.TYPE_SHIFT)
        val |= (1 << MControl.DMODE_SHIFT)
        val |= (MControl.ACTION_ENTER_DEBUG_MODE << MControl.ACTION_SHIFT)
        val |= (1 << MControl.M_SHIFT)
        val |= (1 << MControl.U_SHIFT)
        val |= (1 << MControl.EXECUTE_SHIFT)
        val |= (MControl.MATCH_EQUAL << MControl.MATCH_SHIFT)
        return val

    @staticmethod
    def build_watchpoint(load: bool, store: bool, size: int = 0) -> int:
        """Build tdata1 value for address-match watchpoint.

        Args:
            load: Match on load accesses
            store: Match on store accesses
            size: Access size (0=any, 1=8bit, 2=16bit, 3=32bit)
        """
        val = 0
        val |= (MControl.TYPE_MCONTROL << MControl.TYPE_SHIFT)
        val |= (1 << MControl.DMODE_SHIFT)
        val |= (MControl.ACTION_ENTER_DEBUG_MODE << MControl.ACTION_SHIFT)
        val |= (1 << MControl.M_SHIFT)
        val |= (1 << MControl.U_SHIFT)
        if load:
            val |= (1 << MControl.LOAD_SHIFT)
        if store:
            val |= (1 << MControl.STORE_SHIFT)
        val |= ((size & MControl.SIZELO_MASK) << MControl.SIZELO_SHIFT)
        val |= (MControl.MATCH_EQUAL << MControl.MATCH_SHIFT)
        return val

    @staticmethod
    def parse_type(tdata1: int) -> int:
        """Extract type field from tdata1."""
        return (tdata1 >> MControl.TYPE_SHIFT) & MControl.TYPE_MASK

    @staticmethod
    def parse_execute_capable(tdata1: int) -> bool:
        """Check if trigger supports execute matching (read from tdata1)."""
        return bool(tdata1 & (1 << MControl.EXECUTE_SHIFT))

    @staticmethod
    def parse_load_capable(tdata1: int) -> bool:
        """Check if trigger supports load matching."""
        return bool(tdata1 & (1 << MControl.LOAD_SHIFT))

    @staticmethod
    def parse_store_capable(tdata1: int) -> bool:
        """Check if trigger supports store matching."""
        return bool(tdata1 & (1 << MControl.STORE_SHIFT))

    @staticmethod
    def parse_maskmax(tdata1: int) -> int:
        """Extract maskmax (read-only field, max NAPOT range log2)."""
        return (tdata1 >> MControl.MASKMAX_SHIFT) & MControl.MASKMAX_MASK


# ---------------------------------------------------------------------------
# Size mapping helper
# ---------------------------------------------------------------------------

def _map_size_to_sizelo(size_bytes: int) -> int:
    """Map byte size to mcontrol sizelo encoding.

    Args:
        size_bytes: Size in bytes (0=any, 1, 2, 4)

    Returns:
        sizelo field value (0=any, 1=8bit, 2=16bit, 3=32bit)
    """
    _SIZE_MAP = {0: 0, 1: 1, 2: 2, 4: 3}
    return _SIZE_MAP.get(size_bytes, 0)


# ---------------------------------------------------------------------------
# TriggerInfo: per-trigger capability record
# ---------------------------------------------------------------------------

@dataclass
class TriggerInfo:
    """Discovered capabilities of a single trigger."""

    index: int
    type_value: int       # 2=mcontrol, 6=mcontrol6
    has_execute: bool
    has_load: bool
    has_store: bool
    maskmax: int          # max NAPOT range (log2), 0=no NAPOT
    in_use: bool = False
    current_addr: int = 0
    is_watchpoint: bool = False  # True if currently used as watchpoint


# ---------------------------------------------------------------------------
# RiscvTriggerModule
# ---------------------------------------------------------------------------

class RiscvTriggerModule:
    """RISC-V Trigger Module manager.

    Discovers available triggers via tselect/tinfo iteration,
    manages allocation for HW breakpoints and watchpoints.
    """

    MAX_TRIGGERS = 32  # Safety limit

    def __init__(self, dm: "DebugModule") -> None:
        self._dm = dm
        self._triggers: List[TriggerInfo] = []
        self._trigger_by_addr: Dict[int, TriggerInfo] = {}

    # ---- Properties ----

    @property
    def total_triggers(self) -> int:
        return len(self._triggers)

    @property
    def hw_bp_count(self) -> int:
        """Count of triggers that support execute matching."""
        return sum(1 for t in self._triggers if t.has_execute)

    @property
    def available_hw_breakpoints(self) -> int:
        """Count of free execute-capable triggers."""
        return sum(1 for t in self._triggers if t.has_execute and not t.in_use)

    @property
    def watchpoint_count(self) -> int:
        """Count of triggers that support load/store matching."""
        return sum(1 for t in self._triggers if t.has_load or t.has_store)

    @property
    def available_watchpoints(self) -> int:
        """Count of free load/store-capable triggers."""
        return sum(1 for t in self._triggers if (t.has_load or t.has_store)
                   and not t.in_use)

    # ---- Initialization: trigger discovery ----

    def init(self) -> None:
        """Discover available triggers per Sdtrig enumeration algorithm.

        Per Debug Spec v0.13 Sdtrig, write 0 to tselect and read it back; a
        nonzero readback indicates no triggers exist, otherwise iterate indices
        writing tselect and reading tinfo/tdata1 to enumerate each trigger's
        type.
        """
        self._triggers.clear()

        for index in range(self.MAX_TRIGGERS):
            try:
                # Select trigger
                self._dm.write_register(RiscvRegno.TSELECT, index)
                readback = self._dm.read_register(RiscvRegno.TSELECT)

                # Verify selection stuck
                if readback != index:
                    break  # Past last trigger

                # Read tinfo to discover supported types
                trigger_type = self._discover_trigger_type(index)
                if trigger_type is None:
                    break  # No usable trigger at this index

                if trigger_type not in (MControl.TYPE_MCONTROL,
                                        MControl.TYPE_MCONTROL6):
                    # Not an address/data match trigger; skip but continue
                    # (could be icount, itrigger, etc.)
                    continue

                # Probe capabilities using WARL detection
                # mcontrol execute/load/store/m/u are WARL fields are We write all capability bits
                # set, read back to see which WARL kept.
                info = self._probe_trigger_capabilities(index)

                self._triggers.append(info)
                LOG.debug("Trigger %d: type=%d execute=%s load=%s store=%s maskmax=%d",
                          index, trigger_type, info.has_execute, info.has_load,
                          info.has_store, info.maskmax)

            except Exception as e:
                LOG.debug("Trigger discovery stopped at index %d: %s", index, e)
                break

        LOG.debug("Trigger module: %d triggers discovered (%d execute, %d load/store)",
                  len(self._triggers), self.hw_bp_count, self.watchpoint_count)

    def _discover_trigger_type(self, index: int) -> Optional[int]:
        """Determine the type of trigger at given tselect index.

        Try tinfo first; fall back to reading tdata1 type field.
        Returns None if trigger doesn't exist.
        """
        # Try tinfo first
        try:
            tinfo = self._dm.read_register(RiscvRegno.TINFO)
            info_field = tinfo & 0xFFFF
            if info_field == 1:
                # info=1 means trigger doesn't exist
                return None
            # Check for mcontrol (bit 2) or mcontrol6 (bit 6)
            if info_field & (1 << MControl.TYPE_MCONTROL6):
                return MControl.TYPE_MCONTROL6
            if info_field & (1 << MControl.TYPE_MCONTROL):
                return MControl.TYPE_MCONTROL
            # Other trigger type present (icount, itrigger, etc.)
            # Extract lowest set bit as the type
            for t in range(16):
                if info_field & (1 << t):
                    return t
            return None
        except Exception:
            pass

        # Fallback: read tdata1 and extract type field
        try:
            tdata1 = self._dm.read_register(RiscvRegno.TDATA1)
            trigger_type = MControl.parse_type(tdata1)
            if trigger_type == MControl.TYPE_NONE:
                return None
            return trigger_type
        except Exception:
            return None

    def _probe_trigger_capabilities(self, index: int) -> TriggerInfo:
        """Probe trigger capabilities using WARL write-test-readback.

        Per Sdtrig spec, execute/load/store/m/u are WARL fields. Save the
        original tdata1 to preserve the read-only maskmax field, disable the
        trigger, write a probe value with all R/W capability bits set, read it
        back to see which bits WARL kept, and disable the trigger again.
        """
        # Read original tdata1 for read-only fields (maskmax)
        tdata1_orig = self._dm.read_register(RiscvRegno.TDATA1)
        maskmax = MControl.parse_maskmax(tdata1_orig)

        # Build probe value: type=2, all R/W capability bits set
        # action=0 (breakpoint exception - safest during discovery)
        probe_val = 0
        probe_val |= (MControl.TYPE_MCONTROL << MControl.TYPE_SHIFT)
        probe_val |= (1 << MControl.EXECUTE_SHIFT)
        probe_val |= (1 << MControl.LOAD_SHIFT)
        probe_val |= (1 << MControl.STORE_SHIFT)
        probe_val |= (1 << MControl.M_SHIFT)
        probe_val |= (1 << MControl.U_SHIFT)

        # WARL probe: disable -> write probe -> read
        self._dm.write_register(RiscvRegno.TDATA1, 0)
        self._dm.write_register(RiscvRegno.TDATA1, probe_val)
        actual = self._dm.read_register(RiscvRegno.TDATA1)

        # Parse WARL results
        has_execute = MControl.parse_execute_capable(actual)
        has_load = MControl.parse_load_capable(actual)
        has_store = MControl.parse_store_capable(actual)

        # Restore trigger to disabled state
        self._dm.write_register(RiscvRegno.TDATA1, 0)

        LOG.debug("WARL probe trigger %d: exec=%s load=%s store=%s maskmax=%d "
                  "(wrote=0x%08x, got=0x%08x)",
                  index, has_execute, has_load, has_store, maskmax,
                  probe_val, actual)

        return TriggerInfo(
            index=index,
            type_value=MControl.TYPE_MCONTROL,
            has_execute=has_execute,
            has_load=has_load,
            has_store=has_store,
            maskmax=maskmax,
        )

    # ---- Hardware Breakpoint operations ----

    def set_hw_breakpoint(self, addr: int, provider: Optional["BreakpointProvider"] = None) -> Optional[Breakpoint]:
        """Set a hardware breakpoint at the given address.

        Selects a free trigger, disables it, writes the match address to tdata2,
        enables it via the mcontrol configuration in tdata1, and reads both back
        to verify WARL acceptance per Sdtrig.

        @param addr Address to set breakpoint at.
        @param provider The BreakpointProvider that owns this breakpoint. If None,
            defaults to self (RiscvTriggerModule) for backward compatibility.
        """
        # Find free execute-capable trigger
        trigger = self._find_free_execute_trigger()
        if trigger is None:
            LOG.warning("No free execute triggers for HW BP at 0x%08x", addr)
            return None

        tdata1_val = MControl.build_hw_breakpoint()
        try:
            self._dm.write_register(RiscvRegno.TSELECT, trigger.index)
            self._dm.write_register(RiscvRegno.TDATA1, 0)       # disable first
            self._dm.write_register(RiscvRegno.TDATA2, addr)     # write address
            self._dm.write_register(RiscvRegno.TDATA1, tdata1_val)  # enable

            # Verify WARL accepted configuration
            actual_tdata1 = self._dm.read_register(RiscvRegno.TDATA1)
            actual_tdata2 = self._dm.read_register(RiscvRegno.TDATA2)

            if actual_tdata2 != addr:
                # Address not accepted; disable and fail
                self._dm.write_register(RiscvRegno.TDATA1, 0)
                LOG.warning("Trigger %d rejected address 0x%08x (got 0x%08x)",
                            trigger.index, addr, actual_tdata2)
                return None

            trigger.in_use = True
            trigger.current_addr = addr
            self._trigger_by_addr[addr] = trigger

            bp = Breakpoint(provider if provider is not None else self)
            bp.type = Target.BreakpointType.HW
            bp.enabled = True
            bp.addr = addr
            LOG.debug("HW BP set: trigger %d -> 0x%08x (tdata1=0x%08x)",
                      trigger.index, addr, actual_tdata1)
            return bp

        except Exception as e:
            LOG.error("Failed to set HW BP at 0x%08x: %s", addr, e)
            # Try to clean up
            try:
                self._dm.write_register(RiscvRegno.TSELECT, trigger.index)
                self._dm.write_register(RiscvRegno.TDATA1, 0)
            except Exception:
                pass
            return None

    def remove_hw_breakpoint(self, bp: Breakpoint) -> None:
        """Remove a hardware breakpoint by disabling its trigger."""
        trigger = self._trigger_by_addr.get(bp.addr)
        if trigger is None:
            LOG.warning("HW BP at 0x%08x not found in trigger map", bp.addr)
            return

        try:
            self._dm.write_register(RiscvRegno.TSELECT, trigger.index)
            self._dm.write_register(RiscvRegno.TDATA1, 0)  # disable
            LOG.debug("HW BP removed: trigger %d <- 0x%08x",
                      trigger.index, bp.addr)
        except Exception as e:
            LOG.error("Failed to remove HW BP at 0x%08x: %s", bp.addr, e)
        finally:
            trigger.in_use = False
            trigger.current_addr = 0
            self._trigger_by_addr.pop(bp.addr, None)

    def find_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        """Check if a HW breakpoint is set at the given address."""
        if addr in self._trigger_by_addr:
            trigger = self._trigger_by_addr[addr]
            bp = Breakpoint(self)
            bp.type = Target.BreakpointType.HW
            bp.enabled = True
            bp.addr = addr
            return bp
        return None

    # ---- Watchpoint operations ----

    def set_watchpoint(self, addr: int, size: int,
                       wp_type: Target.WatchpointType) -> bool:
        """Set a watchpoint.

        Args:
            addr: Memory address to watch
            size: Access size in bytes (0=any, 1, 2, 4)
            wp_type: READ, WRITE, or READ_WRITE
        """
        # Determine load/store bits
        load = wp_type in (Target.WatchpointType.READ,
                           Target.WatchpointType.READ_WRITE)
        store = wp_type in (Target.WatchpointType.WRITE,
                            Target.WatchpointType.READ_WRITE)

        # Find free trigger with required load/store capability
        trigger = self._find_free_watchpoint_trigger(load, store)
        if trigger is None:
            LOG.warning("No free watchpoint triggers for addr=0x%08x type=%s",
                        addr, wp_type.name)
            return False

        sizelo = _map_size_to_sizelo(size)
        tdata1_val = MControl.build_watchpoint(load=load, store=store, size=sizelo)

        try:
            self._dm.write_register(RiscvRegno.TSELECT, trigger.index)
            self._dm.write_register(RiscvRegno.TDATA1, 0)       # disable
            self._dm.write_register(RiscvRegno.TDATA2, addr)     # write address
            self._dm.write_register(RiscvRegno.TDATA1, tdata1_val)  # enable

            # Verify
            actual_tdata2 = self._dm.read_register(RiscvRegno.TDATA2)
            if actual_tdata2 != addr:
                self._dm.write_register(RiscvRegno.TDATA1, 0)
                LOG.warning("Watchpoint trigger %d rejected address 0x%08x",
                            trigger.index, addr)
                return False

            trigger.in_use = True
            trigger.is_watchpoint = True
            trigger.current_addr = addr
            self._trigger_by_addr[addr] = trigger

            LOG.debug("Watchpoint set: trigger %d -> 0x%08x load=%s store=%s size=%d",
                      trigger.index, addr, load, store, size)
            return True

        except Exception as e:
            LOG.error("Failed to set watchpoint at 0x%08x: %s", addr, e)
            try:
                self._dm.write_register(RiscvRegno.TSELECT, trigger.index)
                self._dm.write_register(RiscvRegno.TDATA1, 0)
            except Exception:
                pass
            return False

    def remove_watchpoint(self, addr: int, size: Optional[int] = None,
                          wp_type: Optional[Target.WatchpointType] = None) -> None:
        """Remove a watchpoint by disabling its trigger."""
        trigger = self._trigger_by_addr.get(addr)
        if trigger is None:
            LOG.debug("Watchpoint at 0x%08x not found", addr)
            return

        try:
            self._dm.write_register(RiscvRegno.TSELECT, trigger.index)
            self._dm.write_register(RiscvRegno.TDATA1, 0)
            LOG.debug("Watchpoint removed: trigger %d <- 0x%08x",
                      trigger.index, addr)
        except Exception as e:
            LOG.error("Failed to remove watchpoint at 0x%08x: %s", addr, e)
        finally:
            trigger.in_use = False
            trigger.is_watchpoint = False
            trigger.current_addr = 0
            self._trigger_by_addr.pop(addr, None)

    # ---- Trigger allocation helpers ----

    def _find_free_execute_trigger(self) -> Optional[TriggerInfo]:
        """Find the lowest-index free execute-capable trigger."""
        for t in self._triggers:
            if t.has_execute and not t.in_use:
                return t
        return None

    def _find_free_watchpoint_trigger(self, need_load: bool,
                                       need_store: bool) -> Optional[TriggerInfo]:
        """Find a free trigger that supports the required load/store capability.

        Prefers triggers that are NOT execute-capable (to preserve HW BP resources).
        """
        # First pass: prefer load/store-only triggers (no execute)
        for t in self._triggers:
            if t.in_use:
                continue
            if need_load and not t.has_load:
                continue
            if need_store and not t.has_store:
                continue
            if not t.has_execute:
                return t

        # Second pass: accept execute-capable triggers as fallback
        for t in self._triggers:
            if t.in_use:
                continue
            if need_load and not t.has_load:
                continue
            if need_store and not t.has_store:
                continue
            return t

        return None

    # ---- BreakpointProvider factory ----

    def create_breakpoint_provider(self) -> "RiscvHardwareBreakpointProvider":
        """Create a BreakpointProvider backed by this trigger module."""
        return RiscvHardwareBreakpointProvider(self)


# ---------------------------------------------------------------------------
# RiscvHardwareBreakpointProvider
# ---------------------------------------------------------------------------

class RiscvHardwareBreakpointProvider(BreakpointProvider):
    """Hardware breakpoint provider using RISC-V mcontrol triggers.

    Implements BreakpointProvider so BreakpointManager can dispatch
    HW breakpoints to this provider.
    """

    def __init__(self, trigger_module: RiscvTriggerModule) -> None:
        self._tm = trigger_module

    @property
    def bp_type(self) -> Target.BreakpointType:
        return Target.BreakpointType.HW

    @property
    def do_filter_memory(self) -> bool:
        return False

    @property
    def available_breakpoints(self) -> int:
        return self._tm.available_hw_breakpoints

    def can_support_address(self, addr: int) -> bool:
        """mcontrol triggers match full virtual address space."""
        return True

    def find_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        return self._tm.find_breakpoint(addr)

    def set_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        return self._tm.set_hw_breakpoint(addr, provider=self)

    def remove_breakpoint(self, bp: Breakpoint) -> None:
        self._tm.remove_hw_breakpoint(bp)

    def init(self) -> None:
        pass

    def flush(self) -> None:
        pass
