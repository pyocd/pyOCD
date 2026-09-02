# Copyright 2026 Ryan QIAN
# SPDX-License-Identifier: Apache-2.0

"""Pure-logic MPSSE command builder for FTDI JTAG operations.

No I/O. Fully unit-testable.
Translates (cycles, tms, read_tdo, tdi) tuples into MPSSE command byte streams.
"""

from __future__ import annotations

from typing import List
from typing import Tuple


class MpsseCommandBuilder:
    """Builds MPSSE command byte streams from JTAG sequence descriptions.

    Three command paths:
    - Path A (tms=0): Data shift via TDI/TDO channel
    - Path B (tms=1): TAP state transition, TMS=all-1s, TDI from param
    - Path C (swj):   TAP reset/navigation, TMS from bits param, TDI=0

    No I/O. Fully unit-testable.
    """

    # MPSSE command bytes
    WRITE_BITS_NVE_LSB: int = 0x1B
    RW_BITS_PVE_NVE_LSB: int = 0x3B
    WRITE_BYTES_NVE_LSB: int = 0x19
    RW_BYTES_PVE_NVE_LSB: int = 0x39
    WRITE_BITS_TMS_NVE: int = 0x4B
    RW_BITS_TMS_PVE_NVE: int = 0x6B
    SEND_IMMEDIATE: int = 0x87
    SET_TCK_DIVISOR: int = 0x86
    SET_BITS_LOW: int = 0x80

    # Constraints
    MAX_TMS_BITS_PER_CMD: int = 7
    MAX_BITS_PER_CMD: int = 8
    FTDI_PIPE_LEN: int = 512

    def __init__(self) -> None:
        self._cmd_buf: bytearray = bytearray()
        self._tdo_entries: List[Tuple[int, int]] = []  # (bit_count, is_bit_cmd)
        # Track command boundaries for safe chunk splitting.
        # Each entry is (start_offset, byte_length, tdo_entry_index_or_-1).
        self._cmd_bounds: List[Tuple[int, int, int]] = []

    def append_sequence(self, cycles: int, tms: bool,
                        read_tdo: bool, tdi: int) -> None:
        """Append one JTAG sequence."""
        if not tms:
            self._append_data_shift(cycles, read_tdo, tdi)
        else:
            self._append_tap_transition(cycles, read_tdo, tdi)

    def append_tms_sequence(self, length: int, bits: int) -> None:
        """Append raw TMS sequence for swj_sequence()."""
        offset = 0
        while offset < length:
            chunk = min(length - offset, self.MAX_TMS_BITS_PER_CMD)
            tms_bits = (bits >> offset) & ((1 << chunk) - 1)
            data_byte = tms_bits  # bit7 = 0 (TDI = 0)
            self._cmd_buf.extend(bytes([
                self.WRITE_BITS_TMS_NVE,
                chunk - 1,
                data_byte,
            ]))
            self._register_cmd(3, -1)  # No TDO for swj sequences
            offset += chunk

    def build(self) -> List[Tuple[bytes, List[Tuple[int, int]]]]:
        """Build chunks with SEND_IMMEDIATE suffix.

        Returns list of (command_bytes, tdo_regions) tuples.
        Each chunk is <= FTDI_PIPE_LEN bytes and ends with SEND_IMMEDIATE.

        Splits at MPSSE command boundaries (never mid-command) and correctly
        partitions tdo_regions so each chunk only references its own TDO data.
        """
        if not self._cmd_buf:
            return []
        cmd_with_flush = bytes(self._cmd_buf) + bytes([self.SEND_IMMEDIATE])
        if len(cmd_with_flush) <= self.FTDI_PIPE_LEN:
            return [(cmd_with_flush, list(self._tdo_entries))]
        # Multi-chunk: split at command boundaries
        max_payload = self.FTDI_PIPE_LEN - 1  # -1 for SEND_IMMEDIATE
        chunks: List[Tuple[bytes, List[Tuple[int, int]]]] = []
        chunk_start = 0
        chunk_tdo: List[Tuple[int, int]] = []

        for start, length, tdo_idx in self._cmd_bounds:
            cmd_end = start + length
            # Would adding this command exceed the payload limit?
            if cmd_end - chunk_start > max_payload and chunk_start < start:
                # Flush current chunk
                chunk_bytes = bytes(
                    self._cmd_buf[chunk_start:start]
                ) + bytes([self.SEND_IMMEDIATE])
                chunks.append((chunk_bytes, chunk_tdo))
                chunk_start = start
                chunk_tdo = []

            # Add this command's TDO entry (if any)
            if tdo_idx >= 0:
                chunk_tdo.append(self._tdo_entries[tdo_idx])

        # Final chunk
        if chunk_start < len(self._cmd_buf):
            chunk_bytes = bytes(
                self._cmd_buf[chunk_start:]
            ) + bytes([self.SEND_IMMEDIATE])
            chunks.append((chunk_bytes, chunk_tdo))

        return chunks

    def build_single(self) -> bytes:
        """Return raw command buffer without SEND_IMMEDIATE or chunking."""
        return bytes(self._cmd_buf)

    @staticmethod
    def parse_tdo_response(response: bytes,
                           tdo_regions: List[Tuple[int, int]]) -> bytes:
        """Parse MSB-aligned MPSSE bit reads into LSB-first byte stream.

        MPSSE bit read commands return data MSB-aligned in a full byte.
        For example, a 3-bit read returns bits in positions [7:5], requiring
        a right-shift by (8 - bit_count) to normalize.
        """
        if not tdo_regions:
            return b""
        result = bytearray()
        resp_offset = 0
        for bit_count, _ in tdo_regions:
            if bit_count <= 0:
                continue
            if resp_offset >= len(response):
                break
            if bit_count % 8 == 0:
                # Byte-aligned read: no shift needed
                byte_count = bit_count // 8
                result.extend(response[resp_offset:resp_offset + byte_count])
                resp_offset += byte_count
            else:
                # Sub-byte read: MSB-aligned, needs right-shift
                raw = response[resp_offset]
                shifted = raw >> (8 - bit_count)
                result.append(shifted & ((1 << bit_count) - 1))
                resp_offset += 1
        return bytes(result)

    def _register_cmd(self, byte_count: int, tdo_entry: int = -1) -> None:
        """Record command boundary for safe chunk splitting."""
        start = len(self._cmd_buf) - byte_count
        self._cmd_bounds.append((start, byte_count, tdo_entry))

    def _append_data_shift(self, cycles: int, read_tdo: bool,
                           tdi: int) -> None:
        """Path A: data shift on TDI/TDO, TMS=0."""
        if cycles <= self.MAX_BITS_PER_CMD:
            cmd = self.RW_BITS_PVE_NVE_LSB if read_tdo else self.WRITE_BITS_NVE_LSB
            self._cmd_buf.extend(bytes([cmd, cycles - 1, tdi & 0xFF]))
            tdo_idx = len(self._tdo_entries) if read_tdo else -1
            if read_tdo:
                self._tdo_entries.append((cycles, 1))  # 1 = is_bit_cmd
            self._register_cmd(3, tdo_idx)
        else:
            byte_count = cycles // 8
            remaining = cycles % 8
            # Byte command
            cmd = (self.RW_BYTES_PVE_NVE_LSB if read_tdo
                   else self.WRITE_BYTES_NVE_LSB)
            length_lo = (byte_count - 1) & 0xFF
            length_hi = ((byte_count - 1) >> 8) & 0xFF
            start_pos = len(self._cmd_buf)
            self._cmd_buf.append(cmd)
            self._cmd_buf.extend(bytes([length_lo, length_hi]))
            for i in range(byte_count):
                self._cmd_buf.append((tdi >> (i * 8)) & 0xFF)
            tdo_idx = len(self._tdo_entries) if read_tdo else -1
            if read_tdo:
                self._tdo_entries.append((byte_count * 8, 0))  # 0 = is_byte_cmd
            self._register_cmd(len(self._cmd_buf) - start_pos, tdo_idx)
            # Remaining bits
            if remaining > 0:
                cmd_bit = (self.RW_BITS_PVE_NVE_LSB if read_tdo
                           else self.WRITE_BITS_NVE_LSB)
                tdi_rem = (tdi >> (byte_count * 8)) & 0xFF
                self._cmd_buf.extend(bytes([cmd_bit, remaining - 1, tdi_rem]))
                rem_tdo_idx = len(self._tdo_entries) if read_tdo else -1
                if read_tdo:
                    self._tdo_entries.append((remaining, 1))
                self._register_cmd(3, rem_tdo_idx)

    def _append_tap_transition(self, cycles: int, read_tdo: bool,
                               tdi: int) -> None:
        """Path B: TMS=all-1s, TDI from parameter in bit7."""
        cmd = self.RW_BITS_TMS_PVE_NVE if read_tdo else self.WRITE_BITS_TMS_NVE
        offset = 0
        while offset < cycles:
            chunk = min(cycles - offset, self.MAX_TMS_BITS_PER_CMD)
            tms_bits = (1 << chunk) - 1  # All TMS high
            tdi_bit = (tdi >> offset) & 1
            data_byte = tms_bits | (tdi_bit << 7)
            self._cmd_buf.extend(bytes([cmd, chunk - 1, data_byte]))
            tdo_idx = len(self._tdo_entries) if read_tdo else -1
            if read_tdo:
                self._tdo_entries.append((chunk, 1))  # TMS bit read
            self._register_cmd(3, tdo_idx)
            offset += chunk
