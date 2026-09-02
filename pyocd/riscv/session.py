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
RISC-V debug session API.

High-level interface for RISC-V debug operations. Wraps DebugModule,
RISCVCore, and RiscvTriggerModule into a context-manager-based session
with per-core accessor objects.

Usage:
    with RiscvSession.attach() as session:
        core = session.core(0)
        core.halt()
        pc = core.read_reg('dpc')
        core.step()
        core.resume()

Adapted to pyOCD's Session object-graph lifecycle.
"""

import logging
from typing import List, Optional, Union

from ..probe.aggregator import DebugProbeAggregator
from ..probe.debug_probe import DebugProbe
from ..core.session import Session
from ..core.target import Target

from .dm.debug_module import DebugModule
from .dm.registers import DMReg, DMStatus, RiscvRegno
from .core.core_registers import RiscvCoreRegisterInfo

LOG = logging.getLogger(__name__)


class RiscvCoreAccessor:
    """Per-hart debug interface.

    Provides register, memory, and run-control operations
    for a single hart. Automatically selects the correct hart
    before each operation.
    """

    def __init__(self, session: 'RiscvSession', hart_id: int) -> None:
        self._session = session
        self._dm = session.dm
        self._hart_id = hart_id

    @property
    def hart_id(self) -> int:
        return self._hart_id

    # ---- Run control ----

    def halt(self) -> None:
        """Halt this hart."""
        self._dm.select_hart(self._hart_id)
        self._dm.halt_hart()

    def resume(self) -> None:
        """Resume this hart."""
        self._dm.select_hart(self._hart_id)
        self._dm.resume_hart()

    def step(self) -> None:
        """Single-step this hart.

        Requires hart to be halted first.
        """
        self._dm.select_hart(self._hart_id)
        # Read DCSR, set step bit, batched resume, clear step
        dcsr = self._dm.read_register(RiscvRegno.DCSR)
        self._dm._abstract.write_register_batched(
            RiscvRegno.DCSR, dcsr | (1 << 2))
        # Batched resume
        dmi = self._dm._dmi
        dmi.start_deferred()
        from ..dm.registers import DMControl
        dmcontrol = DMControl.build_resumereq(self._dm._current_dmcontrol)
        dmi.write(DMReg.DMCONTROL, dmcontrol)
        dmcontrol = DMControl.clear_resumereq(self._dm._current_dmcontrol)
        dmi.write(DMReg.DMCONTROL, dmcontrol)
        dmi.flush_deferred()
        self._dm._current_dmcontrol = dmcontrol
        # Wait for halt
        import time
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            dmstatus = dmi.read(DMReg.DMSTATUS)
            if DMStatus.parse_allhalted(dmstatus):
                break
        # Clear step bit using cached DCSR
        self._dm._abstract.write_register_batched(
            RiscvRegno.DCSR, dcsr & ~(1 << 2))

    def reset(self, halt: bool = True) -> None:
        """Reset this hart via ndmreset.

        Args:
            halt: If True, halt after reset (default).
        """
        self._dm.select_hart(self._hart_id)
        if halt:
            from ..core.riscv import RISCVCore
            core = self._session._cores.get(self._hart_id)
            if core is not None:
                core.reset_and_halt()
                return
        # Fallback: raw ndmreset
        self._dm.ndmreset()

    def is_halted(self) -> bool:
        """Check if this hart is halted."""
        self._dm.select_hart(self._hart_id)
        dmstatus = self._dm._dmi.read(DMReg.DMSTATUS)
        return DMStatus.parse_allhalted(dmstatus)

    # ---- Register access ----

    def read_reg(self, name_or_regno: Union[str, int]) -> int:
        """Read a register by name or regno.

        Args:
            name_or_regno: Register name ('dpc', 'x0', 'sp') or RiscvRegno value

        Returns:
            Register value as integer
        """
        self._dm.select_hart(self._hart_id)
        return self._dm.read_register(
            RiscvCoreRegisterInfo.register_name_to_index(name_or_regno)
            if isinstance(name_or_regno, str)
            else name_or_regno
        )

    def write_reg(self, name_or_regno: Union[str, int], value: int) -> None:
        """Write a register by name or regno.

        Args:
            name_or_regno: Register name or RiscvRegno value
            value: Value to write
        """
        self._dm.select_hart(self._hart_id)
        self._dm.write_register(
            RiscvCoreRegisterInfo.register_name_to_index(name_or_regno)
            if isinstance(name_or_regno, str)
            else name_or_regno,
            value,
        )

    def read_regs(self, names: List[Union[str, int]]) -> List[int]:
        """Read multiple registers.

        Args:
            names: List of register names or regnos

        Returns:
            List of register values
        """
        return [self.read_reg(n) for n in names]

    # ---- Memory access ----

    def read_mem(self, addr: int, size: int = 32) -> int:
        """Read memory.

        Args:
            addr: Address to read
            size: Access size in bits (8, 16, 32)

        Returns:
            Value read
        """
        self._dm.select_hart(self._hart_id)
        return self._dm.read_memory(addr, size)

    def write_mem(self, addr: int, value: int, size: int = 32) -> None:
        """Write memory.

        Args:
            addr: Address to write
            value: Value to write
            size: Access size in bits (8, 16, 32)
        """
        self._dm.select_hart(self._hart_id)
        self._dm.write_memory(addr, value, size)

    def read_mem_block32(self, addr: int, count: int) -> List[int]:
        """Read block of 32-bit words.

        Args:
            addr: Start address (must be 4-byte aligned)
            count: Number of 32-bit words to read

        Returns:
            List of integer values
        """
        self._dm.select_hart(self._hart_id)
        abstract = self._dm._abstract
        return [abstract.read_memory(addr + i * 4, 32) for i in range(count)]

    def write_mem_block32(self, addr: int, values: List[int]) -> None:
        """Write block of 32-bit words.

        Args:
            addr: Start address (must be 4-byte aligned)
            values: List of 32-bit values to write
        """
        self._dm.select_hart(self._hart_id)
        abstract = self._dm._abstract
        for i, val in enumerate(values):
            abstract.write_memory(addr + i * 4, val, 32)

    def read_mem_block8(self, addr: int, count: int) -> bytes:
        """Read block of bytes.

        Args:
            addr: Start address
            count: Number of bytes to read

        Returns:
            bytes object
        """
        self._dm.select_hart(self._hart_id)
        result = bytearray()
        for offset in range(count):
            byte_offset = offset % 4
            word_addr = addr + offset - byte_offset
            word = self._dm.read_memory(word_addr, 32)
            result.append((word >> (byte_offset * 8)) & 0xFF)
        return bytes(result)

    # ---- Breakpoints ----

    def set_breakpoint(self, addr: int) -> bool:
        """Set a hardware breakpoint.

        Args:
            addr: Breakpoint address

        Returns:
            True if breakpoint was set successfully
        """
        core = self._session._cores.get(self._hart_id)
        if core is not None:
            return core.set_breakpoint(addr)
        LOG.warning("set_breakpoint: no core for hart %d", self._hart_id)
        return False

    def remove_breakpoint(self, addr: int) -> None:
        """Remove a breakpoint.

        Args:
            addr: Breakpoint address
        """
        core = self._session._cores.get(self._hart_id)
        if core is not None:
            core.remove_breakpoint(addr)

    # ---- Watchpoints ----

    def set_watchpoint(self, addr: int, size: int,
                       wtype: Target.WatchpointType = Target.WatchpointType.WRITE) -> bool:
        """Set a hardware watchpoint.

        Args:
            addr: Watchpoint address
            size: Watchpoint size in bytes
            wtype: Watchpoint type (READ, WRITE, READ_WRITE)

        Returns:
            True if watchpoint was set successfully
        """
        core = self._session._cores.get(self._hart_id)
        if core is not None:
            return core.set_watchpoint(addr, size, wtype)
        return False

    def remove_watchpoint(self, addr: int, size: Optional[int] = None,
                          wtype: Optional[Target.WatchpointType] = None) -> None:
        """Remove a watchpoint.

        Args:
            addr: Watchpoint address
            size: Watchpoint size (optional)
            wtype: Watchpoint type (optional)
        """
        core = self._session._cores.get(self._hart_id)
        if core is not None:
            core.remove_watchpoint(addr, size, wtype)


class RiscvSession:
    """RISC-V debug session with context-manager lifecycle.

    Encapsulates probe discovery, connection, DebugModule initialization,
    core creation, and cleanup into a single object.

    Usage:
        with RiscvSession.attach() as session:
            core = session.core(0)
            core.halt()
            pc = core.read_reg('dpc')
            core.resume()
    """

    def __init__(self, probe, clock: int = 8000000,
                 protocol: DebugProbe.Protocol = DebugProbe.Protocol.JTAG) -> None:
        """Initialize session (low-level).

        Prefer using RiscvSession.attach() classmethod.

        Args:
            probe: DebugProbe instance
            clock: JTAG clock frequency in Hz (default 8 MHz)
            protocol: Debug protocol (default JTAG)
        """
        self._probe = probe
        self._clock = clock
        self._protocol = protocol
        self._session: Optional[Session] = None
        self._dm: Optional[DebugModule] = None
        self._cores: dict = {}
        self._accessors: dict = {}

    @classmethod
    def attach(cls, clock: int = 8000000,
               protocol: DebugProbe.Protocol = DebugProbe.Protocol.JTAG) -> 'RiscvSession':
        """Attach to first available probe and target.

        Args:
            clock: JTAG clock frequency in Hz (default 8 MHz)
            protocol: Debug protocol (default JTAG)

        Returns:
            RiscvSession instance (use as context manager)

        Raises:
            RuntimeError: If no probe found
        """
        probes = DebugProbeAggregator.get_all_connected_probes()
        if not probes:
            raise RuntimeError("No debug probe found")

        probe = probes[0]
        LOG.info("Attaching to probe: %s", probe.description)

        session = cls(probe, clock=clock, protocol=protocol)
        session._connect()
        return session

    def _connect(self) -> None:
        """Open probe, connect, and initialize DebugModule."""
        # Create pyOCD session
        self._session = Session(self._probe, auto_open=False,
                                options={'target': None})

        # Open and configure probe
        self._probe.open()
        self._probe.set_clock(self._clock)
        self._probe.connect(self._protocol)

        # Initialize DebugModule (DTM + DM + capabilities + hart discovery)
        self._dm = DebugModule(self._probe)
        self._dm.init()

        # Halt hart 0 for trigger discovery
        self._dm.halt_hart()

        # Create core accessors for each enabled hart
        for hart_id in range(self._dm._num_harts):
            if self._dm.hart_enabled(hart_id):
                accessor = RiscvCoreAccessor(self, hart_id)
                self._accessors[hart_id] = accessor

        # Initialize triggers for all cores (requires halted hart)
        self._init_triggers()

        LOG.info("Session attached: %d hart(s), DM capabilities: %s",
               len(self._accessors),
               self._dm.capabilities)

    def _init_triggers(self) -> None:
        """Initialize trigger modules for all cores."""
        for hart_id in range(self._dm._num_harts):
            if not self._dm.hart_enabled(hart_id):
                continue
            try:
                from .debug.riscv_trigger import RiscvTriggerModule
                trigger = RiscvTriggerModule(self._dm)
                trigger.init()
                self._cores[hart_id] = trigger
                LOG.info("Hart %d: %d triggers (%d execute, %d load/store)",
                         hart_id, trigger.total_triggers,
                         trigger.hw_bp_count, trigger.watchpoint_count)
            except Exception as e:
                LOG.warning("Hart %d trigger init failed: %s", hart_id, e)

    def core(self, hart_id: int = 0) -> RiscvCoreAccessor:
        """Get core accessor for a hart.

        Args:
            hart_id: Hart index (default 0)

        Returns:
            RiscvCoreAccessor for the specified hart

        Raises:
            KeyError: If hart_id not found
        """
        if hart_id not in self._accessors:
            raise KeyError(f"Hart {hart_id} not found. "
                           f"Available: {list(self._accessors.keys())}")
        return self._accessors[hart_id]

    @property
    def dm(self) -> DebugModule:
        """Direct access to DebugModule (for advanced use)."""
        return self._dm

    @property
    def probe(self):
        """Direct access to probe."""
        return self._probe

    @property
    def num_cores(self) -> int:
        """Number of accessible cores."""
        return len(self._accessors)

    @property
    def hart_ids(self) -> List[int]:
        """Available hart IDs."""
        return list(self._accessors.keys())

    # ---- Context manager ----

    def __enter__(self) -> 'RiscvSession':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Cleanup: resume harts, disconnect probe."""
        try:
            # Resume all halted harts
            for hart_id in self._accessors:
                try:
                    self._dm.select_hart(hart_id)
                    dmstatus = self._dm._dmi.read(DMReg.DMSTATUS)
                    if DMStatus.parse_allhalted(dmstatus):
                        self._dm.resume_hart()
                        LOG.info("Resumed hart %d on disconnect", hart_id)
                except Exception as e:
                    LOG.debug("Could not resume hart %d: %s", hart_id, e)
        except Exception as e:
            LOG.debug("Cleanup error: %s", e)
        finally:
            try:
                self._probe.disconnect()
                self._probe.close()
            except Exception:
                pass
            if self._session:
                try:
                    self._session.close()
                except Exception:
                    pass
        LOG.info("Session disconnected")

    # ---- Direct DM access shortcuts ----

    def read_reg(self, name_or_regno: Union[str, int]) -> int:
        """Shortcut: read register on hart 0."""
        return self.core(0).read_reg(name_or_regno)

    def write_reg(self, name_or_regno: Union[str, int], value: int) -> None:
        """Shortcut: write register on hart 0."""
        self.core(0).write_reg(name_or_regno, value)

    def halt(self) -> None:
        """Shortcut: halt hart 0."""
        self.core(0).halt()

    def resume(self) -> None:
        """Shortcut: resume hart 0."""
        self.core(0).resume()
