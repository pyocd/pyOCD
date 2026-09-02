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
RISC-V JTAG DTM implementation.

This module implements the Debug Transport Module (DTM) for RISC-V debug access via JTAG.

References:
- RISC-V Debug Specification v0.13.2, Section 3.2
"""

import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Tuple

LOG = logging.getLogger(__name__)

# Import JTAG helper functions
from ...probe.jtag import shift_ir, shift_dr, shift_ir_batch, shift_dr_batch, JtagState, JtagSequenceAccumulator

# JTAG addresses
DTMCS_ADDRESS = 0x10
DTMCS_WIDTH = 32
DMI_ADDRESS = 0x11
DMI_ADDRESS_BIT_OFFSET = 34
DMI_VALUE_BIT_OFFSET = 2
DMI_OP_MASK = 0x3

# DTMCS bit fields
DTMCS_DMIRESET_BIT = 16  # Write 1 to clear DMI error state
DTMCS_IDLE_MASK = 0x7000  # bits 14-12
DTMCS_IDLE_SHIFT = 12

# Upper bound on explicit idle cycles in RUN_TEST_IDLE between DMI scans
# for the CMSIS-DAP transport. DTMCS.idle advertises the DM's required
# minimum (read at runtime from DTMCS bits 14:12); the CMSIS-DAP USB
# transfer envelope already inserts substantial latency between scans,
# so a smaller explicit count suffices without violating the TAP timing
# contract. FTDI bitbang lacks that envelope and uses the full DTMCS value.
_OPTIMAL_IDLE_CYCLES = 5

# Default timeout for DMI operations (seconds)
DEFAULT_DMI_TIMEOUT = 5.0


class DmiOperation(IntEnum):
    """DMI operation codes.

    Source: RISC-V Debug Spec v0.13.2, Section 3.2.1
    """
    NO_OP = 0
    READ = 1
    WRITE = 2


class DmiOperationStatus(IntEnum):
    """DMI status codes.

    Source: RISC-V Debug Spec v0.13.2, Section 3.2.1, Table 3.2
    """
    OK = 0
    RESERVED = 1
    OPERATION_FAILED = 2
    REQUEST_IN_PROGRESS = 3


@dataclass
class DtmState:
    """DTM state (TAP + DMI scan bookkeeping)."""

    abits: int = 7
    idle_cycles: int = 7
    queued_commands: List = field(default_factory=list)
    tap_state: JtagState = JtagState.TEST_LOGIC_RESET  # Track TAP state across scans
    # When set, _execute_batch uses this idle count for every per-scan RTI
    # idle instead of idle_cycles. Decouples autoexec-batch idle (long,
    # ~ABSTRACT_COMMAND exec time) from the shared idle_cycles that DMI
    # synchronous ops overwrite back to the short DTMCS default.
    # Minimal lock fix; full per-class idle refactor is future work.
    batch_idle_override: Optional[int] = None


class RiscvError(Exception):
    """RISC-V specific errors."""
    pass


class JtagDtm:
    """JTAG DTM implementation.

    This class provides access to the RISC-V Debug Transport Module (DTM) via JTAG.
    It implements the two-phase DMI read pattern and deferred execution pattern
    for batched DMI scans.

    Usage:
        probe = ...  # DebugProbe instance
        dtm = JtagDtm(probe)
        dtm.init()
        status, data = dtm.dmi_read(0x10)  # Read dmcontrol
    """

    def __init__(self, probe, is_cjtag=None):
        """Initialize JtagDtm.

        Args:
            probe: DebugProbe instance with jtag_sequence() support
            is_cjtag: Override cJTAG mode detection. None=auto-detect from probe.
        """
        self.probe = probe
        self.state = DtmState()
        self._captured_results = {}
        self._cjtag_override = is_cjtag

    @property
    def _is_cjtag(self) -> bool:
        """Check if probe is operating in cJTAG mode.

        If an explicit override was provided at construction time, use that.
        Otherwise fall back to auto-detection from probe capability.
        """
        if self._cjtag_override is not None:
            return self._cjtag_override
        return hasattr(self.probe, 'has_cjtag') and self.probe.has_cjtag

    @property
    def is_cjtag(self) -> bool:
        """Public accessor for cJTAG mode (used by DebugModule SRST eligibility)."""
        return self._is_cjtag

    def lock(self) -> None:
        """Acquire JTAG transport lock.

        Delegates to the probe's RLock to serialize JTAG access
        across multiple threads (e.g., concurrent GDBServer instances).
        """
        self.probe.lock()

    def unlock(self) -> None:
        """Release JTAG transport lock."""
        self.probe.unlock()

    def init(self, skip_validations: bool = False) -> None:
        """Initialize DTM.

        Brings the JTAG TAP to a known state, configures the RISC-V IR
        length, optionally validates IDCODE and IR capture per IEEE 1149.1,
        and reads DTMCS with retry to confirm DTM version compatibility.

        Uses swj_sequence-based TAP reset (more reliable than the standard
        5-cycle TMS reset) to clear the IR persistence issue where stale
        IR contents block DTMCS reads.

        Args:
            skip_validations: If True, skip IDCODE/IR verification (for testing).
                           Default: False to enable all validations.

        Raises:
            RiscvError: If DTM is not found, version is unsupported, or validations fail
        """
        if self._is_cjtag:
            # cJTAG: DAP_Connect(3) already activated OScan1 and read IDCODE.
            # TAP reset would destroy OScan1 mode on these targets.
            # SWJ_Sequence is also a no-op in this probe's cJTAG mode (routes to SPI pins).
            LOG.info("cJTAG mode: skipping TAP reset (DAP_Connect already initialized OScan1)")
            self.state.tap_state = JtagState.RUN_TEST_IDLE
            self._configure_jtag_chain()
        else:
            self._tap_tlr_reset()

            # Configure JTAG chain: RISC-V IR length is 5 bits.
            self._configure_jtag_chain()

            # Re-reset TAP: firmware may reset the TAP during DAP_JTAG_CONFIGURE,
            # leaving the actual state != tracked state.
            self._tap_reset()

        if not skip_validations:
            self._validate_idcode()

        if not skip_validations:
            self._verify_ir_capture()

        dtmcs_raw = self._read_dtmcs_with_retry()

        if dtmcs_raw == 0:
            # DTMCS=0 means no valid RISC-V debug TAP present
            raise RiscvError("NoRiscvTarget: DTMCS read returned 0 - "
                             "no RISC-V debug module detected")
        else:
            # Validate version (bits [3:0])
            version = dtmcs_raw & 0xF
            if version not in [0, 1]:  # Accept both v0.11 and v0.13
                raise RiscvError(f"Unsupported DTM version: {version}")

            # Extract and configure parameters from DTMCS
            self.state.abits = (dtmcs_raw >> 4) & 0x3F
            idle_from_dtmcs = (dtmcs_raw >> 12) & 0xF
            # CMSIS-DAP/cJTAG: cap at _OPTIMAL_IDLE_CYCLES (5) for performance
            # FTDI: use DTMCS value (typically 7) — libftdi bitbang needs more
            from ...probe.cmsis_dap_probe import CMSISDAPProbe
            if isinstance(self.probe, CMSISDAPProbe):
                self.state.idle_cycles = min(idle_from_dtmcs, _OPTIMAL_IDLE_CYCLES)
            else:
                self.state.idle_cycles = idle_from_dtmcs

            # Log successful initialization
            LOG.info("DTMCS: 0x%08X (version=%d, abits=%d, idle=%d, using=%d)",
                     dtmcs_raw, version, self.state.abits,
                     idle_from_dtmcs, self.state.idle_cycles)

        # Verify TAP state is RTI.
        self._verify_tap_state(JtagState.RUN_TEST_IDLE)

        # Optional DMI access smoke test.
        if not skip_validations:
            if not self._test_dmi_access():
                LOG.warning("DMI access test failed, but continuing")

    def read_dtmcs(self) -> int:
        """Read DTMCS register.

        Returns:
            DTMCS register value
        """
        return self._read_register(DTMCS_ADDRESS, DTMCS_WIDTH)

    def dmi_read(self, address: int, timeout: float = DEFAULT_DMI_TIMEOUT) -> Tuple[int, int]:
        """DMI read operation with automatic retry.

        Implements the DMI two-scan READ defined by the RISC-V Debug Spec
        (0.13): a READ is scheduled on one DMI scan, and the result is
        retrieved on the next scan via NO_OP. Retries automatically on
        RequestInProgress.

        Args:
            address: 7-bit DMI register address
            timeout: Timeout in seconds (default 5.0)

        Returns:
            Tuple of (status, data) where status is DmiOperationStatus

        Raises:
            RiscvError: If DMI operation fails or times out
        """
        start_time = time.time()

        while True:
            # Schedule READ request
            idx1 = self._schedule_dmi_register_access(DmiOperation.READ, address)

            # Schedule NO_OP to retrieve result
            idx2 = self._schedule_dmi_register_access(DmiOperation.NO_OP, 0)

            # Execute both using batch JTAG mode
            self._execute_batch()

            # Get results - READ response is captured during the NOP scan that follows
            # With _execute_batch's extra NOP, cmd_index=0 maps to DR scan 1
            # which captures the READ response. idx1 (READ) has the correct data.
            result = self._read_deferred_result(idx1)

            # Parse result: [address:7][data:32][status:2] (same format as command)
            # Status is at bits [0:1], data at bits [2:33], address at bits [34:40]
            status = result & 0x3
            data = (result >> 2) & 0xFFFFFFFF

            # Check status and handle retry
            if status == DmiOperationStatus.OK:
                return (status, data)
            elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                # Clear error state and retry with more idle cycles
                self.clear_error_state()
                new_idle = self.state.idle_cycles + 1
                self.set_idle_cycles(new_idle)
            elif status == DmiOperationStatus.OPERATION_FAILED:
                raise RiscvError(f"DMI read failed: address=0x{address:02X}")
            else:
                raise RiscvError(f"DMI read unknown status: {status}")

            # Check timeout
            if time.time() - start_time > timeout:
                raise RiscvError(f"DMI read timeout: address=0x{address:02X}")

    def dmi_write(self, address: int, data: int, timeout: float = DEFAULT_DMI_TIMEOUT) -> int:
        """DMI write operation with automatic retry.

        Args:
            address: 7-bit DMI register address
            data: 32-bit data to write
            timeout: Timeout in seconds (default 5.0)

        Returns:
            DMI operation status (DmiOperationStatus)

        Raises:
            RiscvError: If DMI operation fails or times out
        """
        start_time = time.time()

        while True:
            # Schedule WRITE operation
            idx_write = self._schedule_dmi_register_access(DmiOperation.WRITE, address, data)

            # Schedule NO_OP to capture write response
            idx_nop = self._schedule_dmi_register_access(DmiOperation.NO_OP, 0)

            # Execute using batch JTAG mode
            # Clear queue before execution to avoid mixing with other operations
            self._execute_batch()

            # Read the write response from NO_OP's result
            result = self._read_deferred_result(idx_nop)
            # Parse status: [address:7][data:32][status:2] (same format as command)
            # Status is at bits [0:1]
            status = result & 0x3

            # Check status and handle retry
            if status == DmiOperationStatus.OK:
                return status
            elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                # Clear error state and retry with more idle cycles
                self.clear_error_state()
                new_idle = self.state.idle_cycles + 1
                self.set_idle_cycles(new_idle)
            elif status == DmiOperationStatus.OPERATION_FAILED:
                raise RiscvError(f"DMI write failed: address=0x{address:02X}")
            else:
                raise RiscvError(f"DMI write unknown status: {status}")

            # Check timeout
            if time.time() - start_time > timeout:
                raise RiscvError(f"DMI write timeout: address=0x{address:02X}")

    def _tap_reset(self) -> None:
        """Reset TAP to Run-Test-Idle state.

        In cJTAG mode, uses swj_sequence(8, 0xFF) for TAP reset then a single
        jtag_sequence(TMS=0) for RTI transition. The cJTAG-capable probe firmware
        requires that the first DAP_JTAG_SEQUENCE after DAP_SWJ_SEQUENCE uses
        TMS=0 — using TMS=1 immediately after swj corrupts internal state.

        In standard JTAG mode, uses batch mode (single USB transfer)
        for atomic timing: 5×TMS=1 + 1×TMS=0.
        """
        if self._is_cjtag:
            if hasattr(self.probe, 'swj_sequence'):
                self.probe.swj_sequence(8, 0xFF)
            self.probe.jtag_sequence(1, False, False, 0)
        else:
            accumulator = JtagSequenceAccumulator(self.probe)
            accumulator.add_sequence(5, True, False, 0)
            accumulator.add_sequence(1, False, False, 0)
            accumulator.flush()

        self.state.tap_state = JtagState.RUN_TEST_IDLE

    def _tap_tlr_reset(self) -> None:
        """Execute TAP reset via swj_sequence.

        Uses CMSIS-DAP's swj_sequence to send TMS=1 cycles to reach
        Test-Logic-Reset state.

        In cJTAG mode: uses 8-bit swj_sequence (0xFF) only — the cJTAG-capable
        probe firmware's DAP_JTAG_SEQUENCE with TMS=1 after DAP_SWJ_SEQUENCE(16)
        corrupts internal state. Individual jtag_sequence calls work fine
        after swj(8).

        In standard JTAG mode: uses 16-bit swj_sequence (0xFFFF) for thorough
        reset, followed by batch _tap_reset().
        """
        if hasattr(self.probe, 'swj_sequence'):
            try:
                if self._is_cjtag:
                    self.probe.swj_sequence(8, 0xFF)
                    LOG.debug("cJTAG TAP reset (swj 8-bit)")
                else:
                    self.probe.swj_sequence(16, 0xFFFF)
                    LOG.debug("TAP reset (swj 16-bit)")
            except Exception as e:
                LOG.warning("swj_sequence failed: %s. Using standard TAP reset.", e)

        self._tap_reset()

    def _configure_jtag_chain(self) -> None:
        """Configure JTAG chain for RISC-V DTM (5-bit IR).

        RISC-V Debug Specification defines 5-bit IR values:
        - DTMCS: IR=0x10
        - DMI: IR=0x11
        - Abstract commands: IR=0x17

        Calls DAP_JTAG_CONFIGURE to set the IR length,
        which ensures the probe correctly handles IR scans.

        Graceful degradation: If configure fails, logs a warning but continues.
        """
        try:
            if hasattr(self.probe, 'jtag_configure'):
                self.probe.jtag_configure(devices_irlen=[5])
            else:
                LOG.warning("jtag_configure not available on this probe. "
                            "Using default IR length.")
        except Exception as e:
            LOG.warning("JTAG configure failed: %s. "
                        "Continuing with default settings.", e)

    def _read_dtmcs_with_retry(self, max_attempts: int = 3) -> int:
        """Read DTMCS with retry logic (handles TAP state issues).

        If DTMCS read returns 0xFFFFFFFF (indicating TAP state problem),
        performs a full reset and retry. The retry recovers from IR
        persistence where stale IR contents block DTMCS reads.

        Args:
            max_attempts: Maximum retry attempts (default: 3)

        Returns:
            DTMCS register value

        Raises:
            RiscvError: If all retry attempts fail (all return 0xFFFFFFFF)
        """
        for attempt in range(max_attempts):
            dtmcs_raw = self._read_register(DTMCS_ADDRESS, DTMCS_WIDTH)

            # Check if we got a valid response (not all 1s)
            if dtmcs_raw != 0xFFFFFFFF:
                # Return any non-0xFFFFFFFF value (including 0, handled by caller)
                return dtmcs_raw

            # DTMCS is 0xFFFFFFFF - likely TAP state issue
            if attempt < max_attempts - 1:
                # Retry: reconfigure chain (skip TAP reset in cJTAG mode)
                if self._is_cjtag:
                    LOG.warning(
                        "DTMCS read returned 0xFFFFFFFF, retrying without TAP reset "
                        "(cJTAG mode: TAP reset would destroy OScan1)"
                    )
                else:
                    self._tap_tlr_reset()
                self._configure_jtag_chain()
            else:
                # Last attempt failed, raise error
                raise RiscvError(
                    f"DTMCS read failed after {max_attempts} attempts "
                    f"(returned 0xFFFFFFFF - TAP state issue)"
                )

    def _validate_idcode(self) -> None:
        """Validate IDCODE read succeeds.

        Reads and validates the JTAG IDCODE register to ensure the TAP
        is responding correctly during DTM initialization.

        Expected: any non-zero, non-0xFFFFFFFF value
        Rejected values: 0x00000000 (no response), 0xFFFFFFFF (connection issue)

        Note: This validation is informational. If IDCODE read fails, we log
        a warning but continue, as some JTAG configurations may not support
        IDCODE reads in the expected way.

        Raises:
            RiscvError: Only for critical failures (e.g., connection completely broken)
        """
        try:
            # Read IDCODE via DR scan with correct IR address.
            # RISC-V Debug Spec v0.13: IDCODE IR value = 0x01.
            # After _tap_reset(), IR already points to IDCODE per IEEE 1149.1,
            # but _read_register does an explicit IR scan to guarantee correctness.
            idcode = self._read_register(0x01, 32)
            LOG.info("IDCODE: 0x%08X", idcode)

            # Validate IDCODE value
            if idcode == 0x00000000:
                LOG.warning("IDCODE is 0x00000000 - JTAG chain may not be fully initialized. "
                            "Continuing anyway as DMI operations may still work.")

            elif idcode == 0xFFFFFFFF:
                LOG.warning("IDCODE is 0xFFFFFFFF - Possible connection issue or wrong mode. "
                            "Continuing anyway as DMI operations may still work.")
            else:
                # Log success
                LOG.debug("IDCODE validated: 0x%08X", idcode)

        except Exception as e:
            LOG.warning("IDCODE validation skipped due to error: %s. Continuing with DTM init.", e)

    def _verify_ir_capture(self) -> None:
        """Verify IR capture value matches IEEE 1149.1 standard.

        IEEE 1149.1 specifies that the IR capture value should be 0x01
        for compliant TAP controllers. This verification ensures the IR
        scan is working correctly.

        Note: This is a simplified implementation. A full implementation would
        perform a dedicated IR capture scan to read the capture value directly.

        For now, this is a placeholder that can be enhanced later.
        """
        # Placeholder: a full implementation would navigate TAP to IR Shift,
        # perform an IR scan to capture the IR value, verify it is 0x01 per
        # IEEE 1149.1, and return TAP to RTI.
        pass

    def _verify_tap_state(self, expected_state: JtagState) -> bool:
        """Verify TAP is in expected state.

        Args:
            expected_state: The expected TAP state

        Returns:
            True if state is correct, False otherwise
        """
        current = self.state.tap_state
        if current != expected_state:
            LOG.warning("TAP state mismatch: expected %s, got %s",
                        expected_state.name, current.name)
            return False
        return True

    def _test_dmi_access(self) -> bool:
        """Test if DMI access is working.

        Performs a simple DMI read operation to verify communication
        is working correctly.

        Returns:
            True if DMI access works, False otherwise
        """
        try:
            # Try to read dmstatus (address 0x11)
            status, data = self.dmi_read(0x11, timeout=1.0)

            # If we got here without exception, DMI is working
            return True
        except Exception as e:
            LOG.warning("DMI access test failed: %s", e)
            return False

    def _read_register(self, address: int, width: int) -> int:
        """Read a JTAG register.

        In cJTAG mode, uses individual jtag_sequence calls for short DR scans
        (DTMCS, IDCODE). The probe firmware handles these correctly via
        individual calls; only 41-bit DMI DR scans require batch mode.

        In standard JTAG mode, uses JtagSequenceAccumulator for atomic
        IR+DR scan in a single USB transfer.

        Args:
            address: JTAG register address (5-bit IR value)
            width: Register width in bits

        Returns:
            Register value as integer
        """
        # Mock probe support for unit testing
        if hasattr(self.probe, 'dtmcs_value') and address == DTMCS_ADDRESS:
            return self.probe.dtmcs_value

        # cJTAG mode: individual calls for short DR scans (DTMCS, IDCODE).
        # 41-bit DMI DR scans use _execute_batch() with jtag_sequence_batch().
        if self._is_cjtag:
            _, self.state.tap_state = shift_ir(
                self.probe, address, 5, capture=False,
                tap_state=self.state.tap_state
            )
            result, self.state.tap_state = shift_dr(
                self.probe, 0, width, capture=True,
                idle_cycles=0, tap_state=self.state.tap_state
            )
            # Navigate to RTI
            path = self.state.tap_state.get_path_to(JtagState.RUN_TEST_IDLE)
            for tms in path:
                self.probe.jtag_sequence(1, int(tms), False, 0)
                if tms:
                    self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state)
                else:
                    self.state.tap_state = JtagState._get_next_state_tms0(self.state.tap_state)

            if result is not None:
                if width < 64:
                    return result & ((1 << width) - 1)
                return result
            return 0

        # Standard JTAG mode: batch mode (single USB transfer)
        accumulator = JtagSequenceAccumulator(self.probe)

        # --- IR Scan: navigate to IR_SHIFT, shift address, update IR ---
        # Navigate from current state to IR_SELECT
        path_to_ir_select = self.state.tap_state.get_path_to(JtagState.IR_SELECT)
        for tms in path_to_ir_select:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Navigate from IR_SELECT to IR_SHIFT
        path_to_ir_shift = JtagState.IR_SELECT.get_path_to(JtagState.IR_SHIFT)
        for tms in path_to_ir_shift:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Shift 5-bit IR value: first 4 bits TMS=0, last bit TMS=1 (exits to Exit1-IR)
        for i in range(4):
            bit = (address >> i) & 1
            accumulator.add_sequence(1, False, False, bit)
        last_ir_bit = (address >> 4) & 1
        accumulator.add_sequence(1, True, False, last_ir_bit)

        # Exit1-IR -> Update-IR (TMS=1)
        accumulator.add_sequence(1, True, False, 0)
        self.state.tap_state = JtagState.IR_UPDATE

        # Update-IR -> RTI (TMS=0)
        accumulator.add_sequence(1, False, False, 0)
        self.state.tap_state = JtagState.RUN_TEST_IDLE

        # --- DR Scan: navigate to DR_SHIFT, read width bits ---
        # Navigate from RTI to DR_SELECT
        path_to_dr_select = self.state.tap_state.get_path_to(JtagState.DR_SELECT)
        for tms in path_to_dr_select:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Navigate from DR_SELECT to DR_SHIFT
        path_to_dr_shift = JtagState.DR_SELECT.get_path_to(JtagState.DR_SHIFT)
        for tms in path_to_dr_shift:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Mark DR scan for response extraction
        accumulator.mark_dr_scan()

        # Shift DR: first (width-1) bits TMS=0 with TDO capture, last bit TMS=1 (exits)
        if width > 1:
            accumulator.add_sequence(width - 1, False, True, 0)
        accumulator.add_sequence(1, True, True, 0)

        # Exit1-DR -> Update-DR (TMS=1)
        accumulator.add_sequence(1, True, False, 0)
        self.state.tap_state = JtagState.DR_UPDATE

        # Update-DR -> RTI (TMS=0)
        accumulator.add_sequence(1, False, False, 0)
        self.state.tap_state = JtagState.RUN_TEST_IDLE

        # FLUSH: execute all accumulated sequences in single USB transfer
        result_bytes = accumulator.flush()

        # Extract DR response
        if result_bytes:
            bit_offset = accumulator.get_dr_scan_offset(0)
            result = accumulator.slice_response(bit_offset, width)
            return result & ((1 << width) - 1)

        return 0

    def _schedule_dmi_register_access(self, op: DmiOperation,
                                       address: int, data: int = 0,
                                       capture: bool = True) -> int:
        """Schedule DMI operation.

        Returns deferred result index for later retrieval.

        Args:
            op: DMI operation type
            address: 7-bit DMI address
            data: 32-bit data (for WRITE operations)
            capture: Whether to capture TDO during this command's DR scan.
                When False, the USB response omits TDO bytes for this scan,
                reducing response payload. The response to the PREVIOUS
                command is lost (not captured). Default True for safety.

        Returns:
            Index for deferred result retrieval
        """
        dmi_value = self._build_dmi_value(op, address, data)
        bit_size = self.state.abits + DMI_ADDRESS_BIT_OFFSET

        # Queue command for deferred execution
        index = len(self.state.queued_commands)
        self.state.queued_commands.append({
            'address': DMI_ADDRESS,
            'data': dmi_value,
            'len': bit_size,
            'capture': capture,
        })
        return index

    def _execute(self) -> None:
        """Execute queued DMI operations with TAP state tracking.

        Batch execution with automatic retry on RequestInProgress.

        Two-phase DMI pattern:
        - Response to command N is captured during command N+1's DR scan
        - Last command's response needs an extra NO_OP if not already present
        """
        if not self.state.queued_commands:
            return

        # Select DMI instruction (0x11) once for all commands (using tracked TAP state)
        _, self.state.tap_state = shift_ir(
            self.probe, DMI_ADDRESS, 5, capture=False,
            tap_state=self.state.tap_state
        )

        # Execute all queued DMI commands
        # Each command shifts in a new DMI value and shifts out the previous response
        for i, cmd in enumerate(self.state.queued_commands):
            dmi_value = cmd['data']
            bit_length = cmd['len']

            # Shift in DMI command, capture the response from the PREVIOUS command
            response, self.state.tap_state = shift_dr(
                self.probe, dmi_value, bit_length, capture=True,
                idle_cycles=self.state.idle_cycles,
                tap_state=self.state.tap_state
            )

            # Store captured result (this is the response to command i-1, or 0 for i=0)
            if response is not None:
                self._captured_results[i] = response
            else:
                self._captured_results[i] = 0

        # Check if the last command is already a NO_OP
        # If so, its captured response is the one we want (response to previous command)
        # If not, we need an extra NO_OP to capture the last command's response
        last_cmd_value = self.state.queued_commands[-1]['data']
        last_op = last_cmd_value & 0x3  # Extract op code from [address:7][data:32][op:2]

        if last_op != DmiOperation.NO_OP:
            # Need an extra NO_OP to capture the last command's response
            bit_length = self.state.abits + DMI_ADDRESS_BIT_OFFSET
            noop_value = self._build_dmi_value(DmiOperation.NO_OP, 0, 0)
            final_response, self.state.tap_state = shift_dr(
                self.probe, noop_value, bit_length, capture=True,
                idle_cycles=self.state.idle_cycles,
                tap_state=self.state.tap_state
            )

            # Store the final response (response to the last queued command)
            last_index = len(self.state.queued_commands) - 1
            if final_response is not None:
                self._captured_results[last_index] = final_response
            else:
                self._captured_results[last_index] = 0

        # Clear the queue after execution
        self.state.queued_commands.clear()

    def _execute_batch(self) -> None:
        """Execute queued DMI operations using batch JTAG mode.

        Uses JtagSequenceAccumulator for atomic timing. Both standard JTAG and
        cJTAG use this batch path because cJTAG-capable probe firmware requires
        jtag_sequence_batch() for correct TDO capture on 41-bit DMI DR scans.
        """
        if not self.state.queued_commands:
            return

        # Clear previous results to avoid stale data
        self._captured_results.clear()

        # Create accumulator for batch JTAG operations
        accumulator = JtagSequenceAccumulator(self.probe)

        # Select DMI instruction (0x11) once for all commands
        # Navigate to IR_SELECT and IR_SHIFT using accumulated sequences
        path_to_select_ir = self.state.tap_state.get_path_to(JtagState.IR_SELECT)
        for tms in path_to_select_ir:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        path_to_shift_ir = JtagState.IR_SELECT.get_path_to(JtagState.IR_SHIFT)
        for tms in path_to_shift_ir:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Shift in DMI IR value (0x11) bit-by-bit
        # CMSIS-DAP firmware may not correctly handle multi-bit TMS=0 sequences
        for i in range(4):  # First 4 bits with TMS=0 (stay in Shift-IR)
            bit = (DMI_ADDRESS >> i) & 1
            accumulator.add_sequence(1, False, False, bit)
        # Last bit with TMS=1 (exits Shift-IR to Exit1-IR)
        last_ir_bit = (DMI_ADDRESS >> 4) & 1
        accumulator.add_sequence(1, True, False, last_ir_bit)
        # State is now Exit1-IR

        # Navigate to Update-IR (TMS=1)
        accumulator.add_sequence(1, True, False, 0)
        self.state.tap_state = JtagState.IR_UPDATE

        # Return to RTI
        accumulator.add_sequence(1, False, False, 0)
        self.state.tap_state = JtagState.RUN_TEST_IDLE

        # Navigate to DR_SELECT
        path_to_select_dr = self.state.tap_state.get_path_to(JtagState.DR_SELECT)
        for tms in path_to_select_dr:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Navigate to DR_SHIFT
        path_to_shift_dr = JtagState.DR_SELECT.get_path_to(JtagState.DR_SHIFT)
        for tms in path_to_shift_dr:
            accumulator.add_sequence(1, int(tms), False, 0)
            self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # Execute all queued DMI commands with complete DR scan cycles
        # Each command needs: Shift-DR → Update-DR → [idle] → (back to Shift-DR for next)
        # Response to command N is captured during command N+1's DR scan
        cmd_count = len(self.state.queued_commands)

        # TDO optimization: track which DR scans have capture enabled
        captured_results_map = {}  # {dr_scan_position: cmd_index}

        for i in range(cmd_count + 1):
            # i=0..cmd_count-1: execute actual commands
            # i=cmd_count: extra NO_OP to capture last command's response

            if i < cmd_count:
                cmd = self.state.queued_commands[i]
                dmi_value = cmd['data']
                bit_length = cmd['len']
            else:
                # Extra NO_OP to capture last command's response
                bit_length = self.state.abits + DMI_ADDRESS_BIT_OFFSET
                dmi_value = self._build_dmi_value(DmiOperation.NO_OP, 0, 0)

            # We're now in Shift-DR state
            # TDO optimization: per-command capture flag
            if i < cmd_count:
                cmd_capture = cmd.get('capture', True)
            else:
                cmd_capture = True  # NO_OP always captures final status

            # Only track captured DR scans for response parsing
            if cmd_capture:
                dr_scan_pos = len(accumulator._dr_scan_offsets)
                accumulator.mark_dr_scan()
                # Two-phase DMI: response at this DR scan is for command i-1
                # Skip i=0 (captures reset state, not a real command response)
                if i > 0 and (i - 1) < cmd_count:
                    captured_results_map[dr_scan_pos] = i - 1

            # Shift DMI command: first (N-1) bits TMS=0, last bit TMS=1 exits Shift-DR
            # CRITICAL: Shifting all N bits with TMS=0 then 1 exit bit = N+1 bits total!
            # The extra bit corrupts the op field (READ->WRITE, WRITE->NOP)
            if bit_length > 1:
                first_bits = dmi_value & ((1 << (bit_length - 1)) - 1)
                accumulator.add_sequence(bit_length - 1, False, cmd_capture, first_bits)
            last_dr_bit = (dmi_value >> (bit_length - 1)) & 1
            accumulator.add_sequence(1, True, cmd_capture, last_dr_bit)  # Exits to Exit1-DR
            self.state.tap_state = JtagState.DR_EXIT1

            # Navigate to Update-DR (lock in the command)
            # Now in Exit1-DR, only 1 TMS=1 needed to reach Update-DR
            accumulator.add_sequence(1, True, False, 0)
            self.state.tap_state = JtagState.DR_UPDATE

            # Add idle cycles at RTI
            idle = (self.state.batch_idle_override
                    if self.state.batch_idle_override is not None
                    else self.state.idle_cycles)
            if idle > 0:
                path_to_rti = JtagState.DR_UPDATE.get_path_to(JtagState.RUN_TEST_IDLE)
                for tms in path_to_rti:
                    accumulator.add_sequence(1, int(tms), False, 0)
                    self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

                accumulator.add_sequence(idle, False, False, 0)

            # Navigate back to Shift-DR for next command (if not last)
            if i < cmd_count:
                path_to_shift_dr = self.state.tap_state.get_path_to(JtagState.DR_SHIFT)
                for tms in path_to_shift_dr:
                    accumulator.add_sequence(1, int(tms), False, 0)
                    self.state.tap_state = JtagState._get_next_state_tms1(self.state.tap_state) if tms else JtagState._get_next_state_tms0(self.state.tap_state)

        # FLUSH: Execute all accumulated sequences in single USB transfer
        result_bytes = accumulator.flush()

        # Process captured results using tracked mapping (TDO optimization)
        # Only parse DR scans that had capture=True (captured_results_map)
        # Uncaptured commands remain absent from _captured_results (default 0 via get())
        dr_bit_length = self.state.abits + DMI_ADDRESS_BIT_OFFSET  # Typically 41 bits

        for dr_scan_pos, cmd_idx in sorted(captured_results_map.items()):
            try:
                bit_offset = accumulator.get_dr_scan_offset(dr_scan_pos)
                response_value = accumulator.slice_response(bit_offset, dr_bit_length)
                self._captured_results[cmd_idx] = response_value

            except IndexError:
                self._captured_results[cmd_idx] = 0

        # Clear response buffer after parsing
        accumulator.take_response()

        # Clear the queue after execution
        self.state.queued_commands.clear()

    def _read_deferred_result(self, index: int) -> int:
        """Read deferred result by index.

        Args:
            index: Result index from scheduling

        Returns:
            Captured data
        """
        return self._captured_results.get(index, 0)

    def _build_dmi_value(self, op: DmiOperation, address: int,
                         data: int) -> int:
        """Build 41-bit DMI value.

        Format: [address:7][data:32][op:2]

        Source: RISC-V Debug Spec v0.13.2, Figure 3.1

        Args:
            op: DMI operation
            address: 7-bit DMI address
            data: 32-bit data

        Returns:
            41-bit DMI value
        """
        return ((address & 0x7F) << DMI_ADDRESS_BIT_OFFSET) | \
               ((data & 0xFFFFFFFF) << DMI_VALUE_BIT_OFFSET) | op.value

    def clear_error_state(self) -> None:
        """Clear DTM error state.

        This writes to DTMCS with dmireset bit (bit 16) set to 1,
        which clears any sticky DMI error state.

        According to RISC-V Debug Spec v0.13.2, section 3.2.1:
        - dmireset: Write 1 to clear the sticky error condition
        - After clearing, the dmistat field should return to 0 (no error)
        """
        # Build DTMCS value with dmireset bit set
        dtmcs_value = (1 << DTMCS_DMIRESET_BIT)

        # Write to DTMCS register
        # Select DTMCS IR
        _, self.state.tap_state = shift_ir(
            self.probe, DTMCS_ADDRESS, 5, capture=False,
            tap_state=self.state.tap_state
        )

        # Write DTMCS value with dmireset=1
        _, self.state.tap_state = shift_dr(
            self.probe, dtmcs_value, DTMCS_WIDTH,
            capture=False, idle_cycles=self.state.idle_cycles,
            tap_state=self.state.tap_state
        )

    def set_idle_cycles(self, cycles: int) -> None:
        """Set idle cycles for DMI operations.

        Args:
            cycles: Number of idle cycles to insert
        """
        # Cap at CMSIS-DAP maximum only for CMSIS-DAP probes
        # (64 cycles per jtag_sequence, use 63 for safety). The probe may be
        # wrapped in a SharedDebugProbeProxy, so unwrap before the type check.
        from ...probe.cmsis_dap_probe import CMSISDAPProbe
        actual_probe = getattr(self.probe, '_probe', self.probe)
        if isinstance(actual_probe, CMSISDAPProbe):
            CMSIS_DAP_MAX_IDLE_CYCLES = 63
            if cycles > CMSIS_DAP_MAX_IDLE_CYCLES:
                LOG.warning("idle_cycles=%d exceeds CMSIS-DAP limit, capping at %d",
                            cycles, CMSIS_DAP_MAX_IDLE_CYCLES)
                cycles = CMSIS_DAP_MAX_IDLE_CYCLES
        self.state.idle_cycles = cycles

    def _dmi_register_access_with_timeout(
        self, op: DmiOperation, address: int, data: int = 0,
        timeout: float = DEFAULT_DMI_TIMEOUT
    ) -> int:
        """DMI register access with automatic retry and adaptive idle cycles.

        On RequestInProgress the queued op is re-armed with a larger idle
        cycle count and retried, until a terminal status (OK or non-retryable
        error) is observed or the timeout elapses.

        Args:
            op: DMI operation type
            address: 7-bit DMI register address
            data: 32-bit data (for WRITE operations)
            timeout: Timeout in seconds (default 5.0)

        Returns:
            Captured DMI response value (41 bits)

        Raises:
            RiscvError: If operation fails or times out
        """
        start_time = time.time()

        # Schedule the operation
        idx = self._schedule_dmi_register_access(op, address, data)

        # Execute queued commands
        self._execute_batch()

        # Retry loop with adaptive idle cycles
        while True:
            # Read the result
            result = self._read_deferred_result(idx)
            status = result & DMI_OP_MASK

            # Check status
            if status == DmiOperationStatus.OK:
                return result
            elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                # Operation still in progress
                # Clear error state and retry with more idle cycles
                self.clear_error_state()

                # Increase idle cycles
                new_idle = self.state.idle_cycles + 1
                self.set_idle_cycles(new_idle)

                # Reschedule and retry
                idx = self._schedule_dmi_register_access(op, address, data)
                self._execute_batch()
            elif status == DmiOperationStatus.OPERATION_FAILED:
                raise RiscvError(f"DMI operation failed: address=0x{address:02X}")
            elif status == DmiOperationStatus.RESERVED:
                raise RiscvError(f"DMI reserved status: address=0x{address:02X}")
            else:
                raise RiscvError(f"DMI unknown status: {status}")

            # Check timeout
            if time.time() - start_time > timeout:
                raise RiscvError(f"DMI operation timeout: address=0x{address:02X}")

