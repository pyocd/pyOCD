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
JTAG TAP State Machine

IEEE 1149.1 TAP state machine and shift primitives used by DMI scan sequences.
The key algorithm is step_toward() which uses single-step lookahead (NOT BFS).
"""

from enum import IntEnum
from typing import Optional, Tuple


class JtagState(IntEnum):
    """JTAG TAP states (IEEE 1149.1 compliant).

    All 16 TAP controller states are represented. State transitions use a
    single-step lookahead algorithm.
    """

    # Stable states
    TEST_LOGIC_RESET = 0
    RUN_TEST_IDLE = 1

    # DR scan path
    DR_SELECT = 2       # SELECT-DR
    DR_CAPTURE = 3      # CAPTURE-DR
    DR_SHIFT = 4        # SHIFT-DR
    DR_EXIT1 = 5        # EXIT1-DR
    DR_PAUSE = 6        # PAUSE-DR
    DR_EXIT2 = 7        # EXIT2-DR
    DR_UPDATE = 8       # UPDATE-DR

    # IR scan path
    IR_SELECT = 9       # SELECT-IR
    IR_CAPTURE = 10     # CAPTURE-IR
    IR_SHIFT = 11       # SHIFT-IR
    IR_EXIT1 = 12       # EXIT1-IR
    IR_PAUSE = 13       # PAUSE-IR
    IR_EXIT2 = 14       # EXIT2-IR
    IR_UPDATE = 15      # UPDATE-IR

    def step_toward(self, target: 'JtagState') -> Optional[bool]:
        """Return TMS value to move one step toward target, or None if at target.

        Single-step lookahead: TMS=1 prioritized toward Reset, TMS=0 through scan
        chains. Simpler than BFS but sufficient for TAP navigation.

        Args:
            target: The destination state we want to reach

        Returns:
            TMS value (True=1, False=0) for one step, or None if already at target

        IEEE 1149.1 State Machine Transitions:
        - TMS=1 always moves toward TEST_LOGIC_RESET
        - TMS=0 moves through the scan chains
        """
        if self == target:
            return None

        # Prioritize TMS=1 path (toward Reset)
        # unless target is clearly in a TMS=0 branch

        if self == JtagState.TEST_LOGIC_RESET:
            # From Reset: TMS=0 goes to RTI, TMS=1 stays in Reset
            return False if target == JtagState.RUN_TEST_IDLE else True

        if self == JtagState.RUN_TEST_IDLE:
            # From RTI: TMS=1 goes to Select-DR
            # Check if target is in DR or IR path
            if target in (JtagState.DR_SELECT, JtagState.DR_CAPTURE, JtagState.DR_SHIFT,
                         JtagState.DR_EXIT1, JtagState.DR_PAUSE, JtagState.DR_EXIT2,
                         JtagState.DR_UPDATE, JtagState.IR_SELECT, JtagState.IR_CAPTURE,
                         JtagState.IR_SHIFT, JtagState.IR_EXIT1, JtagState.IR_PAUSE,
                         JtagState.IR_EXIT2, JtagState.IR_UPDATE):
                return True
            return False  # Stay in RTI

        # DR scan path transitions
        if self == JtagState.DR_SELECT:
            # Select-DR: TMS=1 goes to Select-IR, TMS=0 goes to Capture-DR
            if target in (JtagState.IR_SELECT, JtagState.IR_CAPTURE, JtagState.IR_SHIFT,
                         JtagState.IR_EXIT1, JtagState.IR_PAUSE, JtagState.IR_EXIT2,
                         JtagState.IR_UPDATE):
                return True
            return False

        if self == JtagState.DR_CAPTURE:
            # Capture-DR: TMS=1 goes to Exit1-DR, TMS=0 goes to Shift-DR
            if target == JtagState.DR_SHIFT:
                return False
            return True

        if self == JtagState.DR_SHIFT:
            # Shift-DR: TMS=1 goes to Exit1-DR, TMS=0 stays in Shift-DR
            if target in (JtagState.DR_EXIT1, JtagState.DR_PAUSE, JtagState.DR_EXIT2,
                         JtagState.DR_UPDATE, JtagState.RUN_TEST_IDLE, JtagState.DR_SELECT,
                         JtagState.TEST_LOGIC_RESET):
                return True
            return False

        if self == JtagState.DR_EXIT1:
            # Exit1-DR: TMS=1 goes to Update-DR, TMS=0 goes to Pause-DR
            if target == JtagState.DR_PAUSE:
                return False
            return True

        if self == JtagState.DR_PAUSE:
            # Pause-DR: TMS=1 goes to Exit2-DR, TMS=0 stays in Pause-DR
            if target in (JtagState.DR_EXIT2, JtagState.DR_UPDATE, JtagState.RUN_TEST_IDLE):
                return True
            return False

        if self == JtagState.DR_EXIT2:
            # Exit2-DR: TMS=1 goes to Update-DR, TMS=0 goes to Shift-DR
            if target == JtagState.DR_SHIFT:
                return False
            return True

        if self == JtagState.DR_UPDATE:
            # Update-DR: TMS=1 goes to Select-DR, TMS=0 goes to RTI
            if target == JtagState.RUN_TEST_IDLE:
                return False
            # Check if target is in IR path
            if target in (JtagState.IR_SELECT, JtagState.IR_CAPTURE, JtagState.IR_SHIFT,
                         JtagState.IR_EXIT1, JtagState.IR_PAUSE, JtagState.IR_EXIT2,
                         JtagState.IR_UPDATE):
                return True
            # Back to DR path
            return True

        # IR scan path transitions (parallel to DR path)
        if self == JtagState.IR_SELECT:
            # Select-IR: TMS=1 goes to Reset, TMS=0 goes to Capture-IR
            if target == JtagState.TEST_LOGIC_RESET:
                return True
            return False

        if self == JtagState.IR_CAPTURE:
            # Capture-IR: TMS=1 goes to Exit1-IR, TMS=0 goes to Shift-IR
            if target == JtagState.IR_SHIFT:
                return False
            return True

        if self == JtagState.IR_SHIFT:
            # Shift-IR: TMS=1 goes to Exit1-IR, TMS=0 stays in Shift-IR
            if target in (JtagState.IR_EXIT1, JtagState.IR_PAUSE, JtagState.IR_EXIT2,
                         JtagState.IR_UPDATE, JtagState.RUN_TEST_IDLE, JtagState.DR_SELECT,
                         JtagState.TEST_LOGIC_RESET):
                return True
            return False

        if self == JtagState.IR_EXIT1:
            # Exit1-IR: TMS=1 goes to Update-IR, TMS=0 goes to Pause-IR
            if target == JtagState.IR_PAUSE:
                return False
            return True

        if self == JtagState.IR_PAUSE:
            # Pause-IR: TMS=1 goes to Exit2-IR, TMS=0 stays in Pause-IR
            if target in (JtagState.IR_EXIT2, JtagState.IR_UPDATE, JtagState.RUN_TEST_IDLE):
                return True
            return False

        if self == JtagState.IR_EXIT2:
            # Exit2-IR: TMS=1 goes to Update-IR, TMS=0 goes to Shift-IR
            if target == JtagState.IR_SHIFT:
                return False
            return True

        if self == JtagState.IR_UPDATE:
            # Update-IR: TMS=1 goes to Select-DR, TMS=0 goes to RTI
            if target == JtagState.RUN_TEST_IDLE:
                return False
            return True

        # Should never reach here
        raise ValueError(f"Invalid state transition from {self} to {target}")

    def get_path_to(self, target: 'JtagState') -> Tuple[bool, ...]:
        """Get the complete TMS sequence to reach target from current state.

        This is a convenience method that iterates step_toward() to build
        a complete path. Used for testing and validation.

        Args:
            target: The destination state

        Returns:
            Tuple of TMS values (True=1, False=0) representing the path
        """
        path = []
        current = self
        max_steps = 20  # TAP has 16 states; any valid path <= 15 steps

        while current != target:
            tms = current.step_toward(target)
            if tms is None:
                break
            path.append(tms)
            # Move to next state based on TMS value
            if tms:
                current = self._get_next_state_tms1(current)
            else:
                current = self._get_next_state_tms0(current)
            max_steps -= 1
            if max_steps <= 0:
                break

        return tuple(path)

    @staticmethod
    def _get_next_state_tms1(state: 'JtagState') -> 'JtagState':
        """Get next state when TMS=1."""
        transitions_tms1 = {
            JtagState.TEST_LOGIC_RESET: JtagState.TEST_LOGIC_RESET,
            JtagState.RUN_TEST_IDLE: JtagState.DR_SELECT,
            JtagState.DR_SELECT: JtagState.IR_SELECT,
            JtagState.DR_CAPTURE: JtagState.DR_EXIT1,
            JtagState.DR_SHIFT: JtagState.DR_EXIT1,
            JtagState.DR_EXIT1: JtagState.DR_UPDATE,
            JtagState.DR_PAUSE: JtagState.DR_EXIT2,
            JtagState.DR_EXIT2: JtagState.DR_UPDATE,
            JtagState.DR_UPDATE: JtagState.DR_SELECT,
            JtagState.IR_SELECT: JtagState.TEST_LOGIC_RESET,
            JtagState.IR_CAPTURE: JtagState.IR_EXIT1,
            JtagState.IR_SHIFT: JtagState.IR_EXIT1,
            JtagState.IR_EXIT1: JtagState.IR_UPDATE,
            JtagState.IR_PAUSE: JtagState.IR_EXIT2,
            JtagState.IR_EXIT2: JtagState.IR_UPDATE,
            JtagState.IR_UPDATE: JtagState.DR_SELECT,
        }
        return transitions_tms1.get(state, state)

    @staticmethod
    def _get_next_state_tms0(state: 'JtagState') -> 'JtagState':
        """Get next state when TMS=0."""
        transitions_tms0 = {
            JtagState.TEST_LOGIC_RESET: JtagState.RUN_TEST_IDLE,
            JtagState.RUN_TEST_IDLE: JtagState.RUN_TEST_IDLE,
            JtagState.DR_SELECT: JtagState.DR_CAPTURE,
            JtagState.DR_CAPTURE: JtagState.DR_SHIFT,
            JtagState.DR_SHIFT: JtagState.DR_SHIFT,
            JtagState.DR_EXIT1: JtagState.DR_PAUSE,
            JtagState.DR_PAUSE: JtagState.DR_PAUSE,
            JtagState.DR_EXIT2: JtagState.DR_SHIFT,
            JtagState.DR_UPDATE: JtagState.RUN_TEST_IDLE,
            JtagState.IR_SELECT: JtagState.IR_CAPTURE,
            JtagState.IR_CAPTURE: JtagState.IR_SHIFT,
            JtagState.IR_SHIFT: JtagState.IR_SHIFT,
            JtagState.IR_EXIT1: JtagState.IR_PAUSE,
            JtagState.IR_PAUSE: JtagState.IR_PAUSE,
            JtagState.IR_EXIT2: JtagState.IR_SHIFT,
            JtagState.IR_UPDATE: JtagState.RUN_TEST_IDLE,
        }
        return transitions_tms0.get(state, state)


# ============================================================================
# JTAG IR/DR Scan Functions
# ============================================================================

def jtag_move_to_state(probe, target: JtagState, current: JtagState) -> None:
    """Move TAP to target state using step_toward().

    Args:
        probe: DebugProbe instance with jtag_sequence() method
        target: Destination JtagState
        current: Current JtagState
    """
    while current != target:
        tms = current.step_toward(target)
        if tms is None:
            break
        # Send single TMS cycle
        probe.jtag_sequence(cycles=1, tms=int(tms), read_tdo=False, tdi=0)
        # Update current state
        current = JtagState._get_next_state_tms1(current) if tms else JtagState._get_next_state_tms0(current)


def shift_ir(probe, data: int, length: int, capture: bool = False,
              irpre: int = 0, irpost: int = 0, tap_state: Optional[JtagState] = None
              ) -> Tuple[Optional[int], JtagState]:
    """Shift IR register with TAP state tracking.

    Tracks TAP state so shift_ir/shift_dr can compute TMS paths without
    re-resetting to a known state each call.

    Key behaviors:
    - Handle irpre/irpost (multi-TAP chain)
    - Stay in Shift for (len - 1) bits
    - Last bit exits to Exit1
    - Move to Update-IR
    - END in Update-IR (don't return to RTI)

    Args:
        probe: DebugProbe instance with jtag_sequence() method
        data: Integer with IR bit values to shift in
        length: Number of IR bits to shift
        capture: Whether to capture TDO during shift
        irpre: Number of IR bits to bypass before target TAP
        irpost: Number of IR bits to bypass after target TAP
        tap_state: Current TAP state (will be updated)

    Returns:
        Tuple of (captured data, new TAP state)

    Note:
        If tap_state is None, assumes RUN_TEST_IDLE (for backward compatibility).
    """
    # Use provided state or default to RTI
    if tap_state is None:
        tap_state = JtagState.RUN_TEST_IDLE

    # Navigate to Select-DR -> Select-IR
    path_to_select_ir = tap_state.get_path_to(JtagState.IR_SELECT)
    for tms in path_to_select_ir:
        probe.jtag_sequence(1, int(tms), False, 0)
        # Update state after each TMS cycle
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Navigate to Capture-IR -> Shift-IR
    path_to_shift_ir = JtagState.IR_SELECT.get_path_to(JtagState.IR_SHIFT)
    for tms in path_to_shift_ir:
        probe.jtag_sequence(1, int(tms), False, 0)
        # Update state after each TMS cycle
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Shift IR data bit-by-bit. CMSIS-DAP firmware may not correctly handle
    # multi-bit TMS=0 sequences for IR scan.
    # and testing/scripts/low_level_jtag_debug.py
    result = None
    if length > 0:
        # Send first (length - 1) bits with TMS=0 (stay in Shift-IR)
        for i in range(length - 1):
            bit = (data >> i) & 1
            probe.jtag_sequence(1, 0, False, bit)

        # Last bit with TMS=1 (exits Shift-IR to Exit1-IR)
        last_bit = (data >> (length - 1)) & 1
        result = probe.jtag_sequence(1, 1, capture, last_bit)
        # State is now Exit1-IR

    # Navigate to Update-IR (TMS=1)
    probe.jtag_sequence(1, 1, False, 0)
    tap_state = JtagState.IR_UPDATE

    # Return to RTI (matches working low-level tests)
    probe.jtag_sequence(1, 0, False, 0)
    tap_state = JtagState.RUN_TEST_IDLE

    # Process captured data if requested
    if result and capture:
        # Calculate the number of bytes needed for the given bit length
        num_bytes = (length + 7) // 8
        # Only take the required number of bytes (CMSIS-DAP may return extra data)
        result = result[:num_bytes]
        # Convert bytes to integer (little-endian)
        captured = int.from_bytes(result, byteorder='little')
        # Mask to only include the requested number of bits
        if length < 64:
            captured &= (1 << length) - 1
        return (captured, tap_state)

    return (None, tap_state)


def shift_dr(probe, data: int, length: int, capture: bool = False,
              idle_cycles: int = 0, tap_state: Optional[JtagState] = None
              ) -> Tuple[Optional[int], JtagState]:
    """Shift DR register with TAP state tracking.

    Tracks TAP state so shift_ir/shift_dr can compute TMS paths without
    re-resetting to a known state each call.

    Key behaviors:
    - Handle drpre/drpost (multi-TAP chain) - currently not used
    - Handle idle cycles after Update-DR
    - If idle_cycles > 0: move to RTI, add idle cycles, stay in RTI
    - If idle_cycles = 0: stay in Update-DR

    Args:
        probe: DebugProbe instance with jtag_sequence() method
        data: Integer with DR bit values to shift in
        length: Number of DR bits to shift
        capture: Whether to capture TDO during shift
        idle_cycles: Number of idle cycles to insert after Update-DR
        tap_state: Current TAP state (will be updated)

    Returns:
        Tuple of (captured data, new TAP state)

    Note:
        If tap_state is None, assumes RUN_TEST_IDLE (for backward compatibility).
    """
    # Use provided state or default to RTI
    if tap_state is None:
        tap_state = JtagState.RUN_TEST_IDLE

    # Navigate to Select-DR
    path_to_select_dr = tap_state.get_path_to(JtagState.DR_SELECT)
    for tms in path_to_select_dr:
        probe.jtag_sequence(1, int(tms), False, 0)
        # Update state after each TMS cycle
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Navigate to Capture-DR -> Shift-DR
    path_to_shift_dr = JtagState.DR_SELECT.get_path_to(JtagState.DR_SHIFT)
    for tms in path_to_shift_dr:
        probe.jtag_sequence(1, int(tms), False, 0)
        # Update state after each TMS cycle
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Shift DR data - Use TMS=0 for all bits, then navigate to exit separately
    result = None
    if length > 0:
        result = probe.jtag_sequence(length, 0, capture, data)
    # State stays in DR_SHIFT during data shift (TMS=0)

    # Navigate to Update-DR
    path_to_update_dr = JtagState.DR_SHIFT.get_path_to(JtagState.DR_UPDATE)
    for tms in path_to_update_dr:
        probe.jtag_sequence(1, int(tms), False, 0)
        # Update state after each TMS cycle
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Handle idle cycles
    if idle_cycles > 0:
        # Move to RTI
        path_to_rti = JtagState.DR_UPDATE.get_path_to(JtagState.RUN_TEST_IDLE)
        for tms in path_to_rti:
            probe.jtag_sequence(1, int(tms), False, 0)
            # Update state after each TMS cycle
            tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

        # Add idle cycles in RTI
        if idle_cycles > 0:
            probe.jtag_sequence(idle_cycles, 0, False, 0)
        # State stays in RUN_TEST_IDLE during idle cycles (TMS=0)

    # Process captured data if requested
    if result and capture:
        num_bytes = (length + 7) // 8
        result_bytes = result[:num_bytes]
        captured = int.from_bytes(result_bytes, byteorder='little')
        if length < 64:
            captured &= (1 << length) - 1
        return (captured, tap_state)

    return (None, tap_state)


# ========== JTAG Sequence Accumulator ==========

class JtagSequenceAccumulator:
    """Accumulate JTAG sequences and flush in batch.

    Buffers all JTAG operations and flushes them in a single USB transfer for
    atomic timing. Supports per-sequence TDO capture into an internal bit
    vector so callers can slice out individual scan responses after flush.

    Two usage modes are supported:
    - Normal: flush() sends all accumulated sequences in one USB transfer.
    - Atomic: flush_deferred() builds sub-commands without sending;
      flush_atomic() sends all deferred batches via DAP_ExecuteCommands.

    Usage (normal):
        accumulator = JtagSequenceAccumulator(probe)
        accumulator.add_sequence(...)
        result = accumulator.flush()

    Usage (atomic super-batch):
        accumulator = JtagSequenceAccumulator(probe, atomic=True)
        accumulator.add_sequence(...)  # example scan 1
        accumulator.flush_deferred()
        accumulator.add_sequence(...)  # example scan 2
        accumulator.flush_deferred()
        results = accumulator.flush_atomic()  # Single USB transfer
    """

    def __init__(self, probe, atomic=False):
        """Initialize the accumulator.

        Args:
            probe: DebugProbe instance with jtag_sequence_batch() method
            atomic: If True, enable atomic super-batch mode using DAP_ExecuteCommands
        """
        self.probe = probe
        self.sequences = []
        self._captured_offsets = []
        self._total_captured_bits = 0
        # Response bits accumulated across flushes as a single bit vector.
        self._response_buffer = 0  # int: accumulated TDO response bits
        self._response_bit_count = 0  # int: number of bits in buffer
        # DR scan offset tracking
        self._dr_scan_offsets = []  # List[int]: bit offsets of DR scan responses
        # Atomic super-batch mode
        self._atomic = atomic
        self._deferred_batches = []  # List of sequence lists for deferred execution
        self._deferred_dr_offsets = []  # Per-batch DR scan relative offsets
        self._deferred_batch_tdo_bits = []  # Per-batch total TDO bit count

    def add_sequence(self, cycles: int, tms: bool, read_tdo: bool, tdi: int):
        """Add a JTAG sequence to the accumulator.

        Consecutive sequences with the same TMS value and read_tdo=False
        are automatically merged to reduce USB data volume. This optimization
        reduces state navigation overhead in batch JTAG operations by combining
        individual 1-bit state transition sequences into multi-bit sequences.

        Args:
            cycles: Number of TCK cycles (1-64)
            tms: Fixed TMS value for this sequence
            read_tdo: Whether to capture TDO
            tdi: Integer with TDI bit values (LSB first)
        """
        if self._can_merge_with_last(cycles, tms, read_tdo):
            prev_cycles, prev_tms, _, prev_tdi = self.sequences[-1]
            self.sequences[-1] = (
                prev_cycles + cycles,
                prev_tms,
                False,
                prev_tdi | (tdi << prev_cycles),
            )
        else:
            self.sequences.append((cycles, tms, read_tdo, tdi))
            if read_tdo:
                self._captured_offsets.append((cycles, len(self.sequences) - 1))

    def _can_merge_with_last(self, cycles: int, tms: bool, read_tdo: bool) -> bool:
        """Check if this sequence can be merged with the previous one."""
        if not self.sequences:
            return False
        prev_cycles, prev_tms, prev_rdo, _ = self.sequences[-1]
        if prev_rdo or read_tdo:
            return False
        if prev_tms != tms:
            return False
        if prev_cycles + cycles > 64:
            return False
        return True

    def flush(self) -> Optional[bytes]:
        """Flush all accumulated sequences in a single USB transfer.

        Accumulates TDO responses into _response_buffer (int as bit vector)
        so callers can use slice_response() after one or more flushes.

        Returns:
            Concatenated TDO data from all sequences with read_tdo=True (backward compatible)
        """
        if not self.sequences:
            return None

        # Call probe's jtag_sequence_batch method
        result = self.probe.jtag_sequence_batch(self.sequences)

        # Accumulate response into bit buffer
        if result:
            new_bits = int.from_bytes(result, byteorder='little')
            new_bit_count = len(result) * 8
            self._response_buffer |= (new_bits << self._response_bit_count)
            self._response_bit_count += new_bit_count

        # Clear accumulator
        self.sequences = []
        self._captured_offsets = []
        self._total_captured_bits = 0

        return result

    def flush_deferred(self) -> None:
        """Defer accumulated sequences for later atomic execution.

        Stores the current batch of sequences without sending any USB transfer.
        Call flush_atomic() later to send all deferred batches in a single
        DAP_ExecuteCommands packet via probe.execute_commands().

        DR scan offsets within this batch are recorded relative to the batch's
        own TDO response. flush_atomic() converts them to absolute offsets.
        """
        if not self.sequences:
            return

        # Compute relative DR scan offsets within this batch's TDO response
        relative_dr_offsets = []
        batch_tdo_bit_pos = 0
        for cycles, tms, read_tdo, tdi in self.sequences:
            if read_tdo:
                byte_count = (cycles + 7) // 8
                relative_dr_offsets.append(batch_tdo_bit_pos)
                batch_tdo_bit_pos += byte_count * 8

        self._deferred_batches.append(list(self.sequences))
        self._deferred_dr_offsets.append(relative_dr_offsets)
        self._deferred_batch_tdo_bits.append(batch_tdo_bit_pos)

        # Clear sequences but NOT the response buffer
        self.sequences = []
        self._captured_offsets = []
        self._total_captured_bits = 0
        self._dr_scan_offsets = []

    def flush_atomic(self) -> Optional[bytes]:
        """Send all deferred batches via DAP_ExecuteCommands in one USB transfer.

        Packs all batches accumulated via flush_deferred() into DAP_JTAG_SEQUENCE
        sub-commands within a single DAP_ExecuteCommands (0x7F) packet.

        Requires the probe to support the execute_commands() method and
        ATOMIC_COMMANDS capability.

        After execution, TDO responses are accumulated into _response_buffer
        just like normal flush(), maintaining backward compatibility with
        slice_response() and get_dr_scan_offset().

        Returns:
            Concatenated TDO data from all batches, or None if no deferred batches.
        """
        if not self._deferred_batches:
            return None

        # Build DAP_JTAG_SEQUENCE sub-commands for each deferred batch
        jtag_subcmds = []
        for batch in self._deferred_batches:
            cmd = [0x14, len(batch)]  # DAP_JTAG_SEQUENCE + count
            for cycles, tms, read_tdo, tdi in batch:
                info = (((0 if cycles == 64 else cycles) & 0x3F) |
                        ((tms & 1) << 6) |
                        (int(read_tdo) << 7))
                cmd.append(info)
                byte_count = (cycles + 7) // 8
                for i in range(byte_count):
                    cmd.append(tdi & 0xFF)
                    tdi >>= 8
            jtag_subcmds.append(cmd)

        # Execute atomically via probe's execute_commands
        results = self.probe.execute_commands(jtag_subcmds)

        # Accumulate responses into bit buffer (same as flush())
        concatenated_tdo = bytearray()
        for tdo_data in results:
            if tdo_data is not None:
                concatenated_tdo.extend(tdo_data)
                new_bits = int.from_bytes(tdo_data, byteorder='little')
                self._response_buffer |= (new_bits << self._response_bit_count)
                self._response_bit_count += len(tdo_data) * 8

        # Rebuild DR scan offsets as absolute bit positions
        abs_bit_offset = 0
        for batch_idx, rel_offsets in enumerate(self._deferred_dr_offsets):
            for rel_bits in rel_offsets:
                self._dr_scan_offsets.append(abs_bit_offset + rel_bits)
            abs_bit_offset += self._deferred_batch_tdo_bits[batch_idx]

        # Clear deferred state
        self._deferred_batches = []
        self._deferred_dr_offsets = []
        self._deferred_batch_tdo_bits = []

        return bytes(concatenated_tdo) if concatenated_tdo else None

    def clear(self):
        """Clear the accumulator without flushing."""
        self.sequences = []
        self._captured_offsets = []
        self._total_captured_bits = 0
        self._response_buffer = 0
        self._response_bit_count = 0
        self._dr_scan_offsets = []
        self._deferred_batches = []
        self._deferred_dr_offsets = []
        self._deferred_batch_tdo_bits = []

    def take_response(self) -> int:
        """Take and clear accumulated response bits.

        Atomically returns and clears _response_buffer so the next flush
        starts a fresh accumulation window.

        Returns:
            int: All accumulated TDO response bits as integer

        Example:
            accumulator.flush()
            accumulator.flush()  # Multiple flushes accumulate response
            response_bits = accumulator.take_response()  # Take all bits
        """
        result = self._response_buffer
        self._response_buffer = 0
        self._response_bit_count = 0
        return result

    def slice_response(self, bit_offset: int, bit_length: int) -> int:
        """Extract bits from accumulated response buffer.

        Args:
            bit_offset: Starting bit offset
            bit_length: Number of bits to extract

        Returns:
            int: Extracted bit value

        Raises:
            IndexError: If bit_offset + bit_length exceeds buffer size
        """
        if bit_offset + bit_length > self._response_bit_count:
            raise IndexError(
                f"Slice [{bit_offset}:{bit_offset + bit_length}] "
                f"exceeds buffer size {self._response_bit_count}"
            )

        mask = (1 << bit_length) - 1
        return (self._response_buffer >> bit_offset) & mask

    def mark_dr_scan(self):
        """Mark that next sequence will be a DR scan.

        Call this before adding a DR scan sequence to track its response offset
        in the accumulated response buffer. This enables accurate extraction of
        DR scan responses even when the buffer contains mixed JTAG operations.

        The predicted bit offset is calculated by counting byte-aligned bits
        from all previously added read_tdo sequences, plus bits from previous
        flushes. Byte alignment is required because CMSIS-DAP returns
        ceil(cycles/8) bytes per sequence, and flush() accumulates these as
        len(bytes)*8 bits in _response_buffer.

        Example:
            accumulator.mark_dr_scan()  # Mark start of DR scan
            accumulator.add_sequence(40, False, True, first_bits)  # 5 bytes
            accumulator.add_sequence(1, True, True, last_bit)      # 1 byte
            # Actual offset = 48 bits (not 41)
        """
        # Predict bit offset by counting byte-aligned bits from previous read_tdo sequences
        # CMSIS-DAP returns ceil(cycles/8) bytes per capture sequence
        predicted_bits = 0
        for cycles, tms, read_tdo, tdi in self.sequences:
            if read_tdo:
                predicted_bits += ((cycles + 7) // 8) * 8
        self._dr_scan_offsets.append(self._response_bit_count + predicted_bits)

    def get_dr_scan_offset(self, dr_index: int) -> int:
        """Get bit offset of a DR scan response in the buffer.

        Args:
            dr_index: Index of DR scan (0-based)

        Returns:
            Bit offset in response buffer

        Raises:
            IndexError: If dr_index is out of range

        Example:
            offset = accumulator.get_dr_scan_offset(0)  # First DR scan
            response = accumulator.slice_response(offset, 41)
        """
        if dr_index >= len(self._dr_scan_offsets):
            raise IndexError(
                f"DR scan index {dr_index} out of range "
                f"(only {len(self._dr_scan_offsets)} DR scans tracked)"
            )
        return self._dr_scan_offsets[dr_index]


def flush_and_take(accumulator: JtagSequenceAccumulator) -> int:
    """Flush and take accumulated response helper function.

    Convenience function that combines flush() and take_response().

    Args:
        accumulator: JtagSequenceAccumulator instance

    Returns:
        int: Accumulated TDO response bits

    Example:
        bit_response = flush_and_take(accumulator)
        # Parse using slice_response
        value1 = accumulator.slice_response(0, 8)
        value2 = accumulator.slice_response(8, 16)
    """
    accumulator.flush()
    return accumulator.take_response()


def shift_ir_batch(probe, data: int, length: int, capture: bool = False,
                   tap_state: Optional[JtagState] = None) -> Tuple[Optional[int], JtagState]:
    """Shift IR register with batch accumulation.

    This is a batch version of shift_ir() that accumulates all JTAG operations
    and flushes them in a single USB transfer for atomic timing.

    Args:
        probe: DebugProbe instance
        data: Integer with IR bit values to shift in
        length: Number of IR bits to shift
        capture: Whether to capture TDO during shift
        tap_state: Current TAP state (will be updated)

    Returns:
        Tuple of (captured data, new TAP state)
    """
    # Use provided state or default to RTI
    if tap_state is None:
        tap_state = JtagState.RUN_TEST_IDLE

    accumulator = JtagSequenceAccumulator(probe)

    # Navigate to Select-DR -> Select-IR
    path_to_select_ir = tap_state.get_path_to(JtagState.IR_SELECT)
    for tms in path_to_select_ir:
        accumulator.add_sequence(1, int(tms), False, 0)
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Navigate to Capture-IR -> Shift-IR
    path_to_shift_ir = JtagState.IR_SELECT.get_path_to(JtagState.IR_SHIFT)
    for tms in path_to_shift_ir:
        accumulator.add_sequence(1, int(tms), False, 0)
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Shift IR data (length bits) while staying in Shift-IR
    result = None
    if length > 0:
        # Shift all bits with TMS=0 to stay in Shift-IR
        accumulator.add_sequence(length, False, capture, data)
    # State stays in IR_SHIFT during data shift (TMS=0)

    # Navigate to Update-IR
    path_to_update_ir = JtagState.IR_SHIFT.get_path_to(JtagState.IR_UPDATE)
    for tms in path_to_update_ir:
        accumulator.add_sequence(1, int(tms), False, 0)
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # END in Update-IR (don't return to RTI)
    # tap_state is now IR_UPDATE

    # Flush all accumulated sequences
    result_bytes = accumulator.flush()

    # Process captured data if requested
    if result_bytes and capture:
        # Calculate the number of bytes needed for the given bit length
        num_bytes = (length + 7) // 8
        # Find the data in the response (it should be at the end)
        # For now, take the last 'num_bytes' bytes
        if len(result_bytes) >= num_bytes:
            result_bytes = result_bytes[-num_bytes:]
        # Convert bytes to integer (little-endian)
        captured = int.from_bytes(result_bytes, byteorder='little')
        # Mask to only include the requested number of bits
        if length < 64:
            captured &= (1 << length) - 1
        return (captured, tap_state)

    return (None, tap_state)


def shift_dr_batch(probe, data: int, length: int, capture: bool = False,
                   idle_cycles: int = 0, tap_state: Optional[JtagState] = None
                   ) -> Tuple[Optional[int], JtagState]:
    """Shift DR register with batch accumulation.

    This is a batch version of shift_dr() that accumulates all JTAG operations
    and flushes them in a single USB transfer for atomic timing.

    Args:
        probe: DebugProbe instance
        data: Integer with DR bit values to shift in
        length: Number of DR bits to shift
        capture: Whether to capture TDO during shift
        idle_cycles: Number of idle cycles to insert after Update-DR
        tap_state: Current TAP state (will be updated)

    Returns:
        Tuple of (captured data, new TAP state)
    """
    # Use provided state or default to RTI
    if tap_state is None:
        tap_state = JtagState.RUN_TEST_IDLE

    accumulator = JtagSequenceAccumulator(probe)

    # Navigate to Select-DR
    path_to_select_dr = tap_state.get_path_to(JtagState.DR_SELECT)
    for tms in path_to_select_dr:
        accumulator.add_sequence(1, int(tms), False, 0)
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Navigate to Capture-DR -> Shift-DR
    path_to_shift_dr = JtagState.DR_SELECT.get_path_to(JtagState.DR_SHIFT)
    for tms in path_to_shift_dr:
        accumulator.add_sequence(1, int(tms), False, 0)
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Shift DR data (length bits) while staying in Shift-DR
    # All bits shifted with TMS=0 to stay in Shift-DR state
    result = None
    if length > 0:
        accumulator.add_sequence(length, False, capture, data)
    # State stays in DR_SHIFT during data shift (TMS=0)

    # Navigate to Update-DR
    path_to_update_dr = JtagState.DR_SHIFT.get_path_to(JtagState.DR_UPDATE)
    for tms in path_to_update_dr:
        accumulator.add_sequence(1, int(tms), False, 0)
        tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

    # Handle idle cycles
    if idle_cycles > 0:
        # Move to RTI
        path_to_rti = JtagState.DR_UPDATE.get_path_to(JtagState.RUN_TEST_IDLE)
        for tms in path_to_rti:
            accumulator.add_sequence(1, int(tms), False, 0)
            tap_state = JtagState._get_next_state_tms1(tap_state) if tms else JtagState._get_next_state_tms0(tap_state)

        # Add idle cycles in RTI
        if idle_cycles > 0:
            accumulator.add_sequence(idle_cycles, False, False, 0)
        # State stays in RUN_TEST_IDLE during idle cycles (TMS=0)

    # Flush all accumulated sequences
    result_bytes = accumulator.flush()

    # Process captured data if requested
    if result_bytes and capture:
        # Calculate the number of bytes needed for the given bit length
        num_bytes = (length + 7) // 8
        # Find the data in the response
        # For now, take the last 'num_bytes' bytes
        if len(result_bytes) >= num_bytes:
            result_bytes = result_bytes[-num_bytes:]
        # Convert bytes to integer (little-endian)
        captured = int.from_bytes(result_bytes, byteorder='little')
        # Mask to only include the requested number of bits
        if length < 64:
            captured &= (1 << length) - 1
        return (captured, tap_state)

    return (None, tap_state)
