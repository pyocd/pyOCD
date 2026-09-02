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
RISC-V Abstract Command execution.

Implements the abstract command mechanism for register access via
Debug Module data registers.

Source: RISC-V Debug Specification v0.13.2
"""

import time
from typing import Optional

from ..dtm.jtag_dtm import RiscvError
from ..dmi.dmi import DMI
from .registers import (
    DMReg, AbstractCS, AbstractCmdErr, Command, RiscvRegno,
    RiscvInstr,
)


class AbstractCommandError(RiscvError):
    """Error during abstract command execution.

    Attributes:
        cmderr: Error code from abstractcs.cmderr (bits 10:8)
    """

    def __init__(self, cmderr: int, message: str = ""):
        self.cmderr = cmderr
        error_names = {
            AbstractCmdErr.NONE: "none",
            AbstractCmdErr.BUSY: "busy",
            AbstractCmdErr.NOT_SUPPORTED: "not supported",
            AbstractCmdErr.EXCEPTION: "exception",
            AbstractCmdErr.HALT_RESUME: "halt/resume",
            AbstractCmdErr.BUS_ERROR: "bus error",
            AbstractCmdErr.OTHER: "other",
        }
        name = error_names.get(cmderr, f"unknown({cmderr})")
        msg = message or f"Abstract command error: {name} ({cmderr})"
        super().__init__(msg)


class AbstractCommands:
    """Abstract command execution with busy polling and error handling.

    Implements the abstract command sequence per RISC-V Debug Spec v0.13.2
    §4.8: clear previous cmderr (write 0x700 to abstractcs), write the
    command to COMMAND, poll ABSTRACTCS.busy until cleared, check cmderr,
    and read/write data registers.

    Reference: RISC-V Debug Specification v0.13.2 §4.8 (Abstract Commands)
    """

    # ABSTRACTCS reads per USB transfer during busy polling. A single
    # multi-read USB transfer overlaps the abstract-command completion
    # time with the JTAG scan traffic: the transfer's own duration
    # (N DR scans back-to-back) is the busy-wait, so polling is
    # transport-bound rather than command-latency-bound.
    _POLL_BATCH_SIZE = 8

    def __init__(self, dmi: DMI):
        """Initialize Abstract Commands.

        Args:
            dmi: DMI instance for register access
        """
        self._dmi = dmi
        # Cache per-register support status
        # regno -> set of supported operations ('read', 'write')
        self._cmd_support_cache = {}

    def _clear_cmderr(self) -> None:
        """Clear cmderr by writing 0b111 to abstractcs.cmderr."""
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())

    def _poll_busy(self, timeout: float = 5.0) -> int:
        """Poll abstractcs.busy until command completes.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            Final abstractcs value

        Raises:
            TimeoutError: If busy doesn't clear within timeout
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            abstractcs = self._dmi.read(DMReg.ABSTRACTCS)
            if not AbstractCS.parse_busy(abstractcs):
                return abstractcs
        raise TimeoutError(
            f"Abstract command busy poll timeout after {timeout}s"
        )

    def _check_cmderr(self, abstractcs: int) -> None:
        """Parse cmderr and raise on error.

        Args:
            abstractcs: ABSTRACTCS register value

        Raises:
            AbstractCommandError: If cmderr != 0
        """
        cmderr = AbstractCS.parse_cmderr(abstractcs)
        if cmderr != AbstractCmdErr.NONE:
            raise AbstractCommandError(cmderr)

    def execute(self, command: int, timeout: float = 5.0) -> None:
        """Execute abstract command.

        Implements the spec-defined sequence: clear cmderr, write COMMAND,
        poll ABSTRACTCS.busy, and check cmderr for errors.

        Args:
            command: 32-bit abstract command value
            timeout: Maximum time to wait for completion

        Raises:
            AbstractCommandError: On command error
            TimeoutError: If command doesn't complete
        """
        self._clear_cmderr()
        self._dmi.write(DMReg.COMMAND, command)
        abstractcs = self._poll_busy(timeout)
        self._check_cmderr(abstractcs)

    def execute_batched(self, command: int, timeout: float = 5.0) -> None:
        """Execute abstract command with reduced USB transfers.

        Batches ABSTRACTCS clear + COMMAND write into single USB transfer,
        then polls busy. Saves 1 USB transfer vs execute().

        Args:
            command: 32-bit abstract command value
            timeout: Maximum time to wait for completion

        Raises:
            AbstractCommandError: On command error
            TimeoutError: If command doesn't complete
        """
        self._dmi.start_deferred()
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
        self._dmi.write(DMReg.COMMAND, command)
        self._dmi.flush_deferred()
        abstractcs = self._poll_busy(timeout)
        self._check_cmderr(abstractcs)

    def write_register_batched(self, regno: int, value: int,
                                aarsize: int = Command.AARSIZE_32BIT,
                                postexec: bool = False) -> None:
        """Write register with reduced USB transfers.

        Batches ABSTRACTCS clear + DATA0 + COMMAND into single USB transfer,
        then polls busy. Saves 2-3 USB transfers vs write_register().

        Note: Does NOT check or update command support cache. Only use for
        registers known to be supported (e.g., s0/s1 in ProgramBuffer).

        Args:
            regno: Register number (see RiscvRegno)
            value: 32-bit value to write
            aarsize: Access size (default: 32-bit)
            postexec: Execute program buffer after transfer

        Raises:
            AbstractCommandError: On command error
            TimeoutError: If command doesn't complete
        """
        cmd = Command.build_access_register_write(regno, aarsize,
                                                   postexec=postexec)
        self._dmi.start_deferred()
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
        self._dmi.write(DMReg.DATA0, value)
        self._dmi.write(DMReg.COMMAND, cmd)
        self._dmi.flush_deferred()
        abstractcs = self._poll_busy()
        self._check_cmderr(abstractcs)

    def read_register(self, regno: int,
                      aarsize: int = Command.AARSIZE_32BIT) -> int:
        """Read register via Access Register abstract command.

        Args:
            regno: Register number (see RiscvRegno)
            aarsize: Access size (default: 32-bit)

        Returns:
            32-bit register value

        Raises:
            AbstractCommandError: If command fails or register not supported
        """
        # Check cache
        if regno in self._cmd_support_cache:
            if 'read' not in self._cmd_support_cache[regno]:
                raise AbstractCommandError(
                    AbstractCmdErr.NOT_SUPPORTED,
                    f"Register {regno:#06x} not supported for read (cached)"
                )

        cmd = Command.build_access_register_read(regno, aarsize)
        try:
            self.execute_batched(cmd)
            return self._dmi.read(DMReg.DATA0)
        except AbstractCommandError as e:
            if e.cmderr == AbstractCmdErr.NOT_SUPPORTED:
                # Cache that this register is unsupported for read.
                # Default to both supported, then remove the failed operation
                if regno not in self._cmd_support_cache:
                    self._cmd_support_cache[regno] = {'read', 'write'}
                self._cmd_support_cache[regno].discard('read')
            raise

    def write_register(self, regno: int, value: int,
                       aarsize: int = Command.AARSIZE_32BIT) -> None:
        """Write register via Access Register abstract command.

        Note: Data is written to DATA0 FIRST, then command is executed.
        This order is required so the COMMAND write observes the new DATA0
        value when the abstract command fires.

        Args:
            regno: Register number (see RiscvRegno)
            value: 32-bit value to write
            aarsize: Access size (default: 32-bit)

        Raises:
            AbstractCommandError: If command fails or register not supported
        """
        # Check cache
        if regno in self._cmd_support_cache:
            if 'write' not in self._cmd_support_cache[regno]:
                raise AbstractCommandError(
                    AbstractCmdErr.NOT_SUPPORTED,
                    f"Register {regno:#06x} not supported for write (cached)"
                )

        # Write data BEFORE the command so COMMAND observes the new DATA0
        self._dmi.write(DMReg.DATA0, value)
        cmd = Command.build_access_register_write(regno, aarsize)
        try:
            self.execute(cmd)
        except AbstractCommandError as e:
            if e.cmderr == AbstractCmdErr.NOT_SUPPORTED:
                # Cache that this register is unsupported for write
                if regno not in self._cmd_support_cache:
                    self._cmd_support_cache[regno] = {'read', 'write'}
                self._cmd_support_cache[regno].discard('write')
            raise

    # ========== Access Memory Commands (cmdtype=2) ==========

    def read_memory(self, address: int, aamsize: int = Command.AARSIZE_32BIT,
                    aamvirtual: bool = False) -> int:
        """Read memory via Access Memory abstract command (batched).

        Batches DATA1 + ABSTRACTCS clear + COMMAND into 1 USB transfer,
        then polls busy and reads DATA0. Reduces from 5 to 3 USB transfers.

        Args:
            address: Memory address to read from
            aamsize: Access size (2=32-bit, 3=64-bit, etc.)
            aamvirtual: Use virtual address translation (M-mode with MPRV)

        Returns:
            Value read from memory

        Raises:
            AbstractCommandError: If Access Memory not supported or error occurs
        """
        cmd = Command.build_access_memory_read(aamsize, aamvirtual)
        self._dmi.start_deferred()
        self._dmi.write(DMReg.DATA1, address)
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
        self._dmi.write(DMReg.COMMAND, cmd)
        self._dmi.flush_deferred()
        abstractcs = self._poll_busy()
        self._check_cmderr(abstractcs)
        return self._dmi.read(DMReg.DATA0)

    def write_memory(self, address: int, value: int,
                     aamsize: int = Command.AARSIZE_32BIT,
                     aamvirtual: bool = False) -> None:
        """Write memory via Access Memory abstract command (batched).

        Batches DATA1 + DATA0 + ABSTRACTCS clear + COMMAND into 1 USB
        transfer, then polls busy. Reduces from 5 to 2 USB transfers.

        Args:
            address: Memory address to write to
            value: Value to write
            aamsize: Access size
            aamvirtual: Use virtual address translation

        Raises:
            AbstractCommandError: If Access Memory not supported or error occurs
        """
        cmd = Command.build_access_memory_write(aamsize, aamvirtual)
        self._dmi.start_deferred()
        self._dmi.write(DMReg.DATA1, address)
        self._dmi.write(DMReg.DATA0, value)
        self._dmi.write(DMReg.ABSTRACTCS, AbstractCS.build_clear_cmderr())
        self._dmi.write(DMReg.COMMAND, cmd)
        self._dmi.flush_deferred()
        abstractcs = self._poll_busy()
        self._check_cmderr(abstractcs)
