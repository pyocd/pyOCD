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
RISC-V DMI operations with automatic timeout retry.

This module implements high-level DMI operations with automatic retry on
RequestInProgress status, scaling idle cycles between attempts until the
target completes the request.
"""

import logging
import time
from typing import Optional

from typing import List, Tuple

LOG = logging.getLogger(__name__)
DMI_TRACE = logging.getLogger("dmi.trace")
_DMI_TRACE_FILE = None
_DMI_TRACE_SEQ = [0]  # Mutable container to avoid global/nonlocal issues
import os as _os
_trace_path = _os.environ.get('DMI_TRACE_FILE')
if _trace_path:
    try:
        _DMI_TRACE_FILE = open(_trace_path, 'w')
    except OSError as e:
        LOG.warning("Failed to open DMI trace file '%s': %s", _trace_path, e)

from ..dtm.jtag_dtm import (
    JtagDtm,
    DmiOperation,
    DmiOperationStatus,
    RiscvError,
)


class DmiError(RiscvError):
    """DMI operation errors."""
    pass


class DMI:
    """DMI operations with automatic timeout retry.

    This class provides high-level DMI read/write operations with:
    - Automatic retry on RequestInProgress
    - Adaptive idle cycle adjustment
    - Timeout protection

    Usage:
        dtm = JtagDtm(probe)
        dtm.init()
        dmi = DMI(dtm)
        data = dmi.read(0x11, timeout=5.0)  # Read dmstatus
        dmi.write(0x10, 0x1, timeout=5.0)  # Write dmcontrol
    """

    def __init__(self, dtm: JtagDtm):
        """Initialize DMI wrapper.

        Args:
            dtm: Initialized JtagDtm instance
        """
        self.dtm = dtm
        self.current_idle_cycles = dtm.state.idle_cycles
        self.max_idle_cycles = 20  # Prevent infinite loops
        self.default_timeout = 5.0  # Default timeout in seconds
        self._deferred_mode = False
        self._deferred_ops = []  # List of (op, address, value) tuples

    def read(self, address: int, timeout: Optional[float] = None) -> int:
        """Read a DMI register with automatic retry on RequestInProgress.

        Executes queued DTM commands and polls the register until the
        operation completes with non-busy status. On RequestInProgress
        the sticky status is cleared, idle cycles are increased, and
        the read retried. Returns the register data on OK; raises on
        any other status or timeout.

        Args:
            address: 7-bit DMI register address
            timeout: Timeout in seconds (default: 5.0)

        Returns:
            32-bit register data

        Raises:
            DmiError: If operation fails or times out
        """
        if timeout is None:
            timeout = self.default_timeout

        # Deferred mode: accumulate without executing
        if self._deferred_mode:
            self._deferred_ops.append((DmiOperation.READ, address, 0))
            if _DMI_TRACE_FILE:
                _DMI_TRACE_SEQ[0] += 1
                _DMI_TRACE_FILE.write(f"{_DMI_TRACE_SEQ[0]:04d} RD 0x{address:02x} 0x00000000\n")
                _DMI_TRACE_FILE.flush()
            return 0

        start_time = time.time()
        self.dtm._execute()

        while True:
            status, data = self.dtm.dmi_read(address)

            if status == DmiOperationStatus.OK:
                if _DMI_TRACE_FILE:
                    _DMI_TRACE_SEQ[0] += 1
                    _DMI_TRACE_FILE.write(f"{_DMI_TRACE_SEQ[0]:04d} R 0x{address:02x} 0x{data:08x}\n")
                    _DMI_TRACE_FILE.flush()
                return data
            elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                # Clear sticky status and retry with a longer idle period.
                self.dtm.clear_error_state()
                self.current_idle_cycles += 1

                if self.current_idle_cycles > self.max_idle_cycles:
                    raise DmiError(
                        f"Max idle cycles ({self.max_idle_cycles}) exceeded. "
                        "Target may be in a bad state."
                    )

                self.dtm.set_idle_cycles(self.current_idle_cycles)
            else:
                raise DmiError(
                    f"DMI read failed: status={status.name} ({status})"
                )

            if time.time() - start_time > timeout:
                raise DmiError(f"DMI read timeout after {timeout}s")

    def write(self, address: int, value: int,
             timeout: Optional[float] = None) -> None:
        """Write with automatic retry.

        Args:
            address: 7-bit DMI register address
            value: 32-bit data to write
            timeout: Timeout in seconds (default: 5.0)

        Raises:
            DmiError: If operation fails or times out
        """
        # Deferred mode: accumulate without executing
        if self._deferred_mode:
            self._deferred_ops.append((DmiOperation.WRITE, address, value))
            if _DMI_TRACE_FILE:
                _DMI_TRACE_SEQ[0] += 1
                _DMI_TRACE_FILE.write(f"{_DMI_TRACE_SEQ[0]:04d} WD 0x{address:02x} 0x{value:08x}\n")
                _DMI_TRACE_FILE.flush()
            return

        if timeout is None:
            timeout = self.default_timeout

        start_time = time.time()

        while True:
            status = self.dtm.dmi_write(address, value)

            if status == DmiOperationStatus.OK:
                if _DMI_TRACE_FILE:
                    _DMI_TRACE_SEQ[0] += 1
                    _DMI_TRACE_FILE.write(f"{_DMI_TRACE_SEQ[0]:04d} W 0x{address:02x} 0x{value:08x}\n")
                    _DMI_TRACE_FILE.flush()
                return
            elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                # Clear sticky status and retry with a longer idle period.
                self.dtm.clear_error_state()
                self.current_idle_cycles += 1

                if self.current_idle_cycles > self.max_idle_cycles:
                    raise DmiError(
                        f"Max idle cycles ({self.max_idle_cycles}) exceeded. "
                        "Target may be in a bad state."
                    )

                self.dtm.set_idle_cycles(self.current_idle_cycles)
            else:
                raise DmiError(
                    f"DMI write failed: status={status.name} ({status})"
                )

            if time.time() - start_time > timeout:
                raise DmiError(f"DMI write timeout after {timeout}s")

    def reset_idle_cycles(self) -> None:
        """Reset idle cycles to DTMCS value.

        This can be called after a successful operation to restore
        the original idle cycle count.
        """
        self.current_idle_cycles = self.dtm.state.idle_cycles
        self.dtm.set_idle_cycles(self.current_idle_cycles)

    def increase_idle_cycles(self, max_idle: int = 63) -> int:
        """Increase idle cycles by 10% + 1 on DMI busy to back off.

            new = current + max(current // 10, 1) + 1

        Progression from 32: 32 -> 36 -> 40 -> 45 -> 50 -> 56 -> 63 (cap)

        Args:
            max_idle: Upper cap (default 63 = CMSIS-DAP jtag_sequence limit).

        Returns:
            New idle cycle count.
        """
        step = max(self.current_idle_cycles // 10, 1) + 1
        new_idle = min(self.current_idle_cycles + step, max_idle)
        self.current_idle_cycles = new_idle
        self.dtm.set_idle_cycles(new_idle)
        return new_idle

    # ========== Batch Operations ==========

    def read_batch(self, address: int, count: int) -> List[int]:
        """Read same DMI register N times in one USB transfer.

        Schedules count READ operations plus a trailing NO_OP for the
        last response capture, then executes everything in a single
        USB transfer. Each DR scan includes idle cycles (as configured
        on the DTM), giving the target time between operations.

        Designed for use with DM_ABSTRACTAUTO.autoexecdata: each DATA0
        read auto-triggers abstract command re-execution, and all N
        triggers complete within a single USB round-trip.

        Args:
            address: 7-bit DMI register address
            count: Number of reads to perform

        Returns:
            List of count 32-bit values. The first element may be
            stale (response from before the batch); callers using
            autoexecdata typically skip it.

        Raises:
            DmiError: If any response has non-OK status
        """
        if count < 1:
            raise ValueError("count must be >= 1")

        # Schedule count READs + 1 trailing NO_OP
        for _ in range(count):
            self.dtm._schedule_dmi_register_access(
                DmiOperation.READ, address)
        self.dtm._schedule_dmi_register_access(DmiOperation.NO_OP, 0)

        # Execute all in one USB transfer
        self.dtm._execute_batch()

        # Extract results
        results = []
        for i in range(count):
            result = self.dtm._read_deferred_result(i)
            status = result & 0x3
            data = (result >> 2) & 0xFFFFFFFF
            if status != 0:
                raise DmiError(
                    f"Batch DMI read error at index {i}: "
                    f"status={DmiOperationStatus(status).name}"
                )
            results.append(data)
        return results

    def write_batch(self, address: int, values: List[int]) -> None:
        """Write to same DMI register N times in one USB transfer.

        Schedules count WRITE operations, then executes everything in
        a single USB transfer. Each DR scan includes idle cycles,
        giving the target time between operations.

        Designed for use with DM_ABSTRACTAUTO.autoexecdata: each DATA0
        write auto-triggers abstract command re-execution.

        Args:
            address: 7-bit DMI register address
            values: List of 32-bit values to write

        Raises:
            DmiError: If final response has non-OK status
        """
        if not values:
            return

        for value in values:
            self.dtm._schedule_dmi_register_access(
                DmiOperation.WRITE, address, value)

        # Execute all in one USB transfer
        self.dtm._execute_batch()

        # Check last result for errors
        last_result = self.dtm._read_deferred_result(len(values) - 1)
        status = last_result & 0x3
        if status != 0:
            raise DmiError(
                f"Batch DMI write error: "
                f"status={DmiOperationStatus(status).name}"
            )

    # ========== Deferred Batch Mode ==========

    def start_deferred(self) -> None:
        """Start deferred batch mode for accumulating DMI operations.

        In deferred mode, read() and write() calls accumulate operations
        without executing USB transfers. All accumulated operations are
        sent in a single USB transfer when flush_deferred() is called.

        This is used by ProgramBuffer to batch setup/teardown DMI
        operations, reducing USB round-trips from N to 1.

        Note: Deferred operations bypass individual retry logic.
        Only use for operations that don't need response-dependent
        control flow (e.g., pure register writes, known-safe reads).
        """
        if self._deferred_mode:
            LOG.warning("Nested deferred mode detected, ignoring start_deferred()")
            return
        self._deferred_mode = True
        self._deferred_ops = []

    def flush_deferred(self) -> List[int]:
        """Execute all deferred DMI operations in a single USB transfer.

        Sends all operations accumulated since start_deferred() as one
        batch, returning results for reads. Write operations return
        their status.

        Returns:
            List of 34-bit results (data[33:2] + status[1:0]) for each
            deferred operation, in the same order they were queued.

        Raises:
            DmiError: If any operation has non-OK status
        """
        if not self._deferred_ops:
            self._deferred_mode = False
            return []

        ops = self._deferred_ops
        self._deferred_mode = False
        self._deferred_ops = []

        # Schedule all operations
        for op, address, value in ops:
            self.dtm._schedule_dmi_register_access(op, address, value)

        # Execute all in one batch
        self.dtm._execute_batch()

        # Read all results
        results = []
        for i in range(len(ops)):
            result = self.dtm._read_deferred_result(i)
            results.append(result)

        # Check for errors
        for i, result in enumerate(results):
            status = result & 0x3
            if status != 0:
                raise DmiError(
                    f"Deferred batch error at index {i}: "
                    f"status={DmiOperationStatus(status).name}"
                )

        return results

    def flush_deferred_raw(self) -> List[Tuple[int, int]]:
        """Execute deferred DMI ops, returning (data, status) per op.

        Unlike flush_deferred(), does NOT raise on non-OK status.
        Caller handles busy/error checking per-response.

        Returns:
            List of (data: int, status: int) tuples, one per deferred op.
            status is a DmiOperationStatus value (0=OK, 3=REQUEST_IN_PROGRESS).
        """
        if not self._deferred_ops:
            self._deferred_mode = False
            return []

        ops = self._deferred_ops
        self._deferred_mode = False
        self._deferred_ops = []

        # TDO capture optimization: disable TDO capture for write-only batches.
        # For write-only ops, only the trailing NO_OP (added by _execute_batch)
        # needs TDO capture. This reduces USB response from ~N*6 bytes to ~6 bytes.
        # Read/mixed batches keep all captures (data values must be returned).
        has_reads = any(op == DmiOperation.READ for op, _, _ in ops)
        capture = has_reads  # False for write-only, True for read/mixed

        for op, address, value in ops:
            self.dtm._schedule_dmi_register_access(op, address, value, capture=capture)
        self.dtm._execute_batch()

        results: List[Tuple[int, int]] = []
        for i in range(len(ops)):
            result = self.dtm._read_deferred_result(i)
            results.append(((result >> 2) & 0xFFFFFFFF, result & 0x3))
        return results

    def cancel_deferred(self) -> None:
        """Discard all queued deferred operations without executing.

        Used when a batch fails and caller wants to fall back to
        individual operations.
        """
        self._deferred_mode = False
        self._deferred_ops = []
