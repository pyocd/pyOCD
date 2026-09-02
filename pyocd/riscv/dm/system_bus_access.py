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
RISC-V System Bus Access.

Implements memory access via the System Bus Access mechanism in the
Debug Module. SBA provides DMA-like memory access independent of
hart state, making it ideal for background memory operations.

Key design: No busy polling - relies on DMI
timing guarantee for correct operation.

Reference: RISC-V Debug Spec v0.13.2 §3.6 (System Bus Access)
"""

from enum import IntEnum
from typing import List, Optional, Tuple

from ..dtm.jtag_dtm import RiscvError
from ..dmi.dmi import DMI, DmiOperationStatus
from .registers import DMReg, SBCS


class SBAccess(IntEnum):
    """System Bus access size encoding (SBCS.sbaccess).

    Source: RISC-V Debug Spec v0.13.2, Section 3.6.2
    """
    B8 = 0
    B16 = 1
    B32 = 2
    B64 = 3
    B128 = 4


class SBAError(RiscvError):
    """System Bus Access error.

    Attributes:
        sberror: Error code from SBCS.sberror (bits 14:12)
    """

    def __init__(self, sberror: int, message: str = ""):
        self.sberror = sberror
        error_names = {
            0: "none",
            1: "timeout",
            2: "bad address/alignment",
            3: "access size not supported",
            4: "other",
            7: "other",
        }
        name = error_names.get(sberror, f"unknown({sberror})")
        msg = message or f"SBA error: {name} ({sberror})"
        super().__init__(msg)


# Default DMI ops per USB transfer for READS.
# With sbreadondata=1, each SBDATA0 read triggers the next bus access;
# too many reads in one USB transfer overrun the SBA pipeline (the last
# reads return stale/zero data because the bus access hasn't completed
# before the next SBDATA0 scan). Chunk size 6 keeps the read pipeline
# depth within the SBA completion budget for tightly-coupled local
# memory accesses.
_DEFAULT_READ_BATCH_CHUNK = 6

# Default DMI ops per USB transfer for WRITES.
# Writes have no sbreadondata pipeline dependency — pure SBDATA0 writes
# with auto-increment. However, flushing too many writes in one deferred
# batch (128) corrupts SBA state on FTDI probes (SBCS cleared to 0,
# subsequent reads return zeros). Use 64 as safe default; CMSIS-DAP bulk
# probes override this via _init_batch_chunk_size() packet calculation.
_DEFAULT_WRITE_BATCH_CHUNK = 64

_MAX_BUSY_RETRIES = 20


class SystemBusAccess:
    """System Bus Access for memory operations.

    Provides DMA-like memory access through the Debug Module's
    System Bus Interface, independent of hart state.

    Design decisions:
    - No busy polling: rely on DMI timing guarantee
    - Single read: sbreadonaddr -> write address -> read data
    - Single write: write address -> write data
    - Batch read: sbreadonaddr + sbreadondata + sbautoincrement,
      clear SBCS before last read (two-phase pipeline)
    - Batch write: sbautoincrement -> write address -> write data

    Deferred batching:
    - read_memory_batch (count>1): uses _read_sba_deferred_loop
    - write_memory_batch (count>1): uses _write_sba_deferred_loop_fused
    - Both chunk operations to BATCH_CHUNK_SIZE per USB transfer
    - Busy-aware recovery with adaptive batch sizing

    Reference: RISC-V Debug Spec v0.13.2 §3.6 (System Bus Access)
    """

    def __init__(self, dmi: DMI):
        """Initialize System Bus Access.

        Args:
            dmi: DMI instance for register access
        """
        self._dmi = dmi
        self._sbversion = 0
        self._sbasize = 0
        self._sbaccess_mask = 0  # Which sizes are supported
        self._available = False

        # Adaptive batch size control (separate for reads and writes)
        self._read_batch_chunk_size = _DEFAULT_READ_BATCH_CHUNK
        self._write_batch_chunk_size = _DEFAULT_WRITE_BATCH_CHUNK
        self._success_streak = 0
        self._busy_events = 0

    @property
    def available(self) -> bool:
        """Whether System Bus Access is supported."""
        return self._available

    def supports_access_size(self, size: SBAccess) -> bool:
        """Check if specific access size is supported.

        Args:
            size: SBAccess enum value

        Returns:
            True if the access size is supported
        """
        return bool(self._sbaccess_mask & (1 << int(size)))

    @property
    def sbversion(self) -> int:
        """SBA version from sbcs.sbversion."""
        return self._sbversion

    @property
    def sbasize(self) -> int:
        """Address width from sbcs.sbasize."""
        return self._sbasize

    def detect_capabilities(self) -> None:
        """Detect SBA capabilities from SBCS register.

        Clears any stale SBA errors from previous sessions before reading
        capabilities. This ensures the SBA starts in a clean state even
        when the DM is re-initialized after a prior session left errors.

        Reads:
        - sbversion (bits 31:29): Version (1=1.0)
        - sbasize (bits 11:5): Address width
        - sbaccess128/64/32/16/8 (bits 4:0): Supported access sizes
        """
        # Clear stale SBA errors from prior sessions (W1C: write 1 to clear).
        sbcs = self._dmi.read(DMReg.SBCS)
        if SBCS.parse_sberror(sbcs) != 0:
            self._dmi.write(DMReg.SBCS, SBCS.SBERROR_CLEAR)
        self._sbversion = SBCS.parse_sbversion(sbcs)
        self._sbasize = SBCS.parse_sbasize(sbcs)
        self._sbaccess_mask = sbcs & 0x1F
        self._available = self._sbversion > 0
        # Initialize batch chunk size from probe packet size.
        # Probe is guaranteed open at this point (called from
        # DebugModule.init() which runs after probe.open()).
        self._init_batch_chunk_size()

    def _check_error(self) -> None:
        """Check sberror and raise on error.

        Waits for sbbusy=0 before reading SBCS, ensuring any in-progress
        SBA operation completes. This avoids reading stale/corrupted SBCS
        state that can produce reserved sberror values on some hardware.
        Then checks sberror (bits 14:12) and clears on error (W1C).
        """
        # Wait for sbbusy=0: the SBA may still be processing the last
        # bus access. Reading SBCS while sbbusy=1 can return corrupted
        # error values on some hardware (reserved values 5, 7). Polling
        # ensures we read a clean SBCS.
        sbcs = 0
        for _ in range(20):
            sbcs = self._dmi.read(DMReg.SBCS)
            if not (sbcs & (1 << SBCS.SBBUSY_BIT)):
                break
        sberror = SBCS.parse_sberror(sbcs)
        if sberror != 0:
            # Clear error by writing 1s to sberror field (W1C)
            self._dmi.write(DMReg.SBCS, SBCS.SBERROR_CLEAR)
            raise SBAError(sberror)

    def _poll_sbbusy(self, max_attempts: int = 20) -> None:
        """Wait for sbbusy to clear by polling SBCS.

        Used between deferred read chunks to ensure the stray bus access
        (triggered by the last SBDATA0 read with sbreadondata=1) completes
        before writing SBADDRESS0 for the next chunk. Per RISC-V Debug Spec
        v0.13.2, writing SBADDRESS0 while sbbusy=1 is UNPREDICTABLE.
        """
        for _ in range(max_attempts):
            sbcs = self._dmi.read(DMReg.SBCS)
            if not (sbcs & (1 << SBCS.SBBUSY_BIT)):
                return
        # If still busy after max attempts, _check_error will catch it
        # and raise SBAError if needed.

    # ========== Deferred Batch Methods ==========

    def _recover_sba_busy(self) -> None:
        """Recover from SBA busy condition.

        Disables SBA auto-read by writing SBCS=0, clears any sberror via W1C,
        and increases DMI idle cycles so subsequent transfers give the SBA
        pipeline more completion headroom.

        Reference: RISC-V Debug Spec v0.13.2 §3.6.2 (SBCS.sberror/sbbusyerror)
        """
        self._dmi.write(DMReg.SBCS, 0)
        sbcs = self._dmi.read(DMReg.SBCS)
        sberror = SBCS.parse_sberror(sbcs)
        if sberror != 0:
            self._dmi.write(DMReg.SBCS, SBCS.SBERROR_CLEAR)
        self._dmi.increase_idle_cycles(max_idle=63)

    def _on_batch_success(self) -> None:
        """Adaptive batch size: grow on consecutive successes.

        Read and write batch sizes grow independently with different caps.
        Reads are capped at _DEFAULT_READ_BATCH_CHUNK (6) for SBA pipeline
        safety. Writes can grow larger since they have no pipeline dependency.
        """
        self._success_streak += 1
        if self._success_streak > 4:
            self._read_batch_chunk_size = min(
                self._read_batch_chunk_size + 2, _DEFAULT_READ_BATCH_CHUNK)
            # Writes grow faster to reach optimal size quickly
            self._write_batch_chunk_size = min(
                self._write_batch_chunk_size + 8, _DEFAULT_WRITE_BATCH_CHUNK)
            self._success_streak = 0

    def _on_batch_busy(self) -> None:
        """Adaptive batch size: shrink on busy event."""
        self._busy_events += 1
        self._success_streak = 0
        self._read_batch_chunk_size = max(2, self._read_batch_chunk_size // 2)
        self._write_batch_chunk_size = max(2, self._write_batch_chunk_size // 2)

    @staticmethod
    def _calc_initial_batch_size(packet_size: int) -> int:
        """Calculate optimal initial batch chunk size from probe packet size.

        Each DMI operation consumes ~7 bytes in the CMSIS-DAP jtag_sequence
        payload (41-bit DR scan = 6 bytes TDI data + 1 byte sequence info).
        Fixed overhead of ~10 bytes covers the command header and initial
        IR scan to select the DMI register.

        Args:
            packet_size: Probe USB packet size in bytes.

        Returns:
            Optimal initial batch chunk size (6..32).
        """
        FIXED_OVERHEAD = 10       # CMSIS-DAP command header + IR scan
        BYTES_PER_DMI_OP = 7      # 41-bit DR scan packed into jtag_sequence
        ABSOLUTE_MAX = 128
        # SBA pipeline floor: chunk_size > 6 causes last 2 words per chunk
        # to return zero due to bus access latency exceeding DMI scan interval.
        SBA_PIPELINE_FLOOR = 6

        available = max(packet_size - FIXED_OVERHEAD, 0)
        max_ops = available // BYTES_PER_DMI_OP
        initial = min(max_ops, ABSOLUTE_MAX)
        return max(initial, SBA_PIPELINE_FLOOR)

    def _init_batch_chunk_size(self) -> None:
        """Initialize batch chunk sizes from probe packet size.

        Walks the object chain SBA -> DMI -> DTM -> probe -> link -> interface
        to discover the USB packet size. Falls back to defaults
        if any link in the chain is unavailable (non-CMSIS-DAP probes, testing).

        Important: DAP_Info(MAX_PACKET_SIZE) may report a theoretical maximum
        that exceeds the actual HID endpoint limit (64 bytes for Full-Speed USB).
        For HID interfaces, the effective packet size is capped at 64 to prevent
        USB write errors.
        """
        packet_size = None
        is_bulk = False

        try:
            # Chain: self._dmi.dtm.probe._link._interface.get_packet_size()
            # Each step guarded by getattr to handle mocks and non-CMSIS probes.
            dtm = getattr(self._dmi, 'dtm', None)
            probe = getattr(dtm, 'probe', None) if dtm else None
            link = getattr(probe, '_link', None) if probe else None

            if link is not None:
                interface = getattr(link, '_interface', None)
                if interface is not None:
                    if hasattr(interface, 'get_packet_size'):
                        packet_size = interface.get_packet_size()
                    is_bulk = getattr(interface, 'is_bulk', False)

                if packet_size is None:
                    packet_size = getattr(link, '_packet_size', None)
        except Exception:
            packet_size = None

        if isinstance(packet_size, int) and packet_size > 0:
            # HID endpoints are limited to 64 bytes regardless of what
            # DAP_Info reports. Only Bulk v2 interfaces can use larger sizes.
            effective_size = packet_size if is_bulk else min(packet_size, 64)
            calculated = self._calc_initial_batch_size(effective_size)
            # Read: capped at 6 for SBA pipeline safety
            self._read_batch_chunk_size = min(calculated, _DEFAULT_READ_BATCH_CHUNK)
            # Write: use full DAP_Info packet size (jtag_sequence_batch auto-splits)
            write_calculated = self._calc_initial_batch_size(packet_size)
            self._write_batch_chunk_size = min(write_calculated, _DEFAULT_WRITE_BATCH_CHUNK)
        else:
            self._read_batch_chunk_size = _DEFAULT_READ_BATCH_CHUNK
            self._write_batch_chunk_size = _DEFAULT_WRITE_BATCH_CHUNK

    def _read_sba_deferred_loop(self, base_address: int,
                                 count: int) -> List[int]:
        """Read SBDATA0 count times using deferred DMI batching.

        Pipeline design (per RISC-V Debug Spec Appendix A.2):
        - sbreadondata + sbautoincrement + sbreadonaddr: writing
          SBADDRESS0 triggers the first read; each subsequent SBDATA0
          read returns data AND triggers the next bus access.
        - For multi-chunk transfers, SBCS + SBADDRESS0 are reconfigured
          as individual DMI writes OUTSIDE the deferred batch. The USB
          round-trip between the address write and the SBDATA0 read
          gives the sbreadonaddr-triggered SBA read time to complete;
          putting them inside the batch would shift data because
          back-to-back JTAG scans leave no SBA completion window.
        - Final chunk appends SBCS=0 write to prevent stray bus access.

        Busy-aware: Checks per-response status, recovers with increased
        idle cycles and adaptive batch sizing.

        Args:
            base_address: Start memory address.
            count: Number of 32-bit words to read.

        Returns:
            List of count 32-bit values.

        Raises:
            RiscvError: If busy retries exhausted or fatal error.
        """
        results: List[int] = []
        offset = 0
        retries = _MAX_BUSY_RETRIES

        while offset < count:
            remaining = count - offset
            chunk = min(remaining, self._read_batch_chunk_size)

            is_final_chunk = (offset + chunk >= count)
            is_first_chunk = (offset == 0)

            # For non-first chunks, write SBADDRESS0 as individual DMI
            # (not deferred). With sbreadonaddr=1, writing SBADDRESS0
            # triggers an SBA bus read. The individual DMI write provides
            # USB round-trip delay for the SBA read to complete
            # before we read SBDATA0 in the deferred batch below.
            # SBCS remains configured from the caller's initial setup or
            # the previous non-final chunk — no re-write needed.
            #
            # CRITICAL: Must wait for sbbusy=0 before writing SBADDRESS0.
            # The previous chunk's last SBDATA0 read (with sbreadondata=1)
            # triggers a stray bus access. Per RISC-V Debug Spec v0.13.2,
            # writing SBADDRESS0 while sbbusy=1 is UNPREDICTABLE.
            if not is_first_chunk:
                self._poll_sbbusy()
                self._dmi.write(DMReg.SBADDRESS0,
                                base_address + offset * (32 // 8))

            # Deferred batch: pure SBDATA0 reads only.
            # Do NOT write SBCS=0 here — per RISC-V Debug Spec v0.13.2,
            # writing SBCS while sbbusy=1 is undefined behavior. The last
            # SBDATA0 read with sbreadondata=1 triggers a stray bus access,
            # and writing SBCS=0 before it completes causes UB (observed as
            # reserved sberror values 5, 7 on some hardware).
            # Instead, _check_error() waits for sbbusy=0 before reading SBCS,
            # and the next operation reconfigures SBCS.
            self._dmi.start_deferred()
            for _ in range(chunk):
                self._dmi.read(DMReg.SBDATA0)

            raw = self._dmi.flush_deferred_raw()

            # Parse responses: all are SBDATA0 reads.
            busy_at = -1
            data_count = 0
            for i, (data, status) in enumerate(raw):
                if data_count >= chunk:
                    break  # All reads collected
                if status == DmiOperationStatus.OK:
                    results.append(data)
                    data_count += 1
                elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                    busy_at = data_count
                    break
                else:
                    raise RiscvError(
                        f"SBA read error at index {offset + data_count}: "
                        f"dmi status={status}"
                    )

            if busy_at >= 0:
                retries -= 1
                if retries <= 0:
                    raise RiscvError(
                        f"SBA read: busy retries exhausted, "
                        f"{count - offset}/{count} reads pending"
                    )
                self._recover_sba_busy()
                self._on_batch_busy()
                offset += busy_at
                continue

            offset += chunk
            self._on_batch_success()

        return results

    def _write_sba_deferred_loop_fused(self, base_address: int,
                                       values: List[int],
                                       sbcs: int) -> None:
        """Write SBDATA0 with fused SBCS/SBADDRESS0 setup in first chunk.

        Optimized variant of _write_sba_deferred_loop that eliminates 2 USB
        round-trips by including SBCS and SBADDRESS0 writes in the first
        deferred chunk. This matches the reference four-layer optimization
        where setup overhead is amortized into the data USB transfer.

        USB round-trips for 25 words (was 4-5, now 2-3):
          Chunk 0 (fused): SBCS + SBADDRESS0 + chunk_size SBDATA0 = 1 USB
          Chunk 1..N:      pure SBDATA0 writes = 1 USB each
          Check error:     1 USB

        Args:
            base_address: Start memory address (for error recovery).
            values: List of 32-bit values to write.
            sbcs: Pre-built SBCS register value with autoincrement enabled.

        Raises:
            RiscvError: If busy retries exhausted or fatal error.
        """
        if not values:
            return

        written = 0
        retries = _MAX_BUSY_RETRIES
        need_setup = True

        while written < len(values):
            remaining = len(values) - written
            chunk_size = min(remaining, self._write_batch_chunk_size)
            chunk = values[written:written + chunk_size]

            self._dmi.start_deferred()

            # First chunk or post-recovery: include SBCS + SBADDRESS0 setup
            setup_offset = 0
            if need_setup:
                self._dmi.write(DMReg.SBCS, sbcs)
                self._dmi.write(DMReg.SBADDRESS0, base_address + written * 4)
                setup_offset = 2

            for value in chunk:
                self._dmi.write(DMReg.SBDATA0, value)
            raw = self._dmi.flush_deferred_raw()

            # Check setup writes (only in fused chunks)
            for i in range(setup_offset):
                _data, status = raw[i]
                if status == DmiOperationStatus.OK:
                    continue
                elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                    raise RiscvError(
                        f"SBA setup write (reg={('SBCS', 'SBADDRESS0')[i]}) "
                        f"returned busy — DTM/target may be overloaded"
                    )
                else:
                    raise RiscvError(
                        f"SBA setup write (reg={('SBCS', 'SBADDRESS0')[i]}) "
                        f"failed: dmi status={status}"
                    )

            # Check data writes
            busy_at = -1
            for i in range(setup_offset, len(raw)):
                _data, status = raw[i]
                data_idx = i - setup_offset
                if status == DmiOperationStatus.OK:
                    continue
                elif status == DmiOperationStatus.REQUEST_IN_PROGRESS:
                    busy_at = data_idx
                    break
                else:
                    raise RiscvError(
                        f"SBA write error at data index {written + data_idx}: "
                        f"dmi status={status}"
                    )

            if busy_at >= 0:
                retries -= 1
                if retries <= 0:
                    raise RiscvError(
                        f"SBA write: busy retries exhausted, "
                        f"{len(values) - written}/{len(values)} pending"
                    )
                self._recover_sba_busy()
                self._on_batch_busy()
                # Advance past successful data writes before busy point
                written += busy_at
                # Recovery reprograms SBCS + SBADDRESS0 in next chunk
                need_setup = True
                continue
            else:
                written += chunk_size
                need_setup = False
                self._on_batch_success()

    def _access_size_to_sbaccess(self, size: int) -> int:
        """Convert byte size to sbaccess encoding."""
        mapping = {8: SBAccess.B8, 16: SBAccess.B16, 32: SBAccess.B32,
                   64: SBAccess.B64, 128: SBAccess.B128}
        if size not in mapping:
            raise RiscvError(f"Invalid access size: {size}")
        return mapping[size]

    def read_memory(self, address: int, size: int = 32) -> int:
        """Read memory via System Bus Access (single read, batched).

        Batches SBCS + SBADDRESS0 into 1 USB transfer, then reads SBDATA0
        and checks error. Reduces from 4 to 3 USB transfers.

        Args:
            address: Target memory address
            size: Access size in bits (8, 16, 32, 64, 128)

        Returns:
            Read value

        Raises:
            RiscvError: If SBA not available or error occurs
        """
        if not self._available:
            raise RiscvError("SBA not available")

        sbaccess = self._access_size_to_sbaccess(size)
        sbcs = SBCS.build_read_config(sbaccess)
        self._dmi.start_deferred()
        self._dmi.write(DMReg.SBCS, sbcs)
        self._dmi.write(DMReg.SBADDRESS0, address)
        self._dmi.flush_deferred()
        data = self._dmi.read(DMReg.SBDATA0)
        self._check_error()
        return data

    def write_memory(self, address: int, value: int, size: int = 32) -> None:
        """Write memory via System Bus Access (single write, batched).

        Batches SBCS + SBADDRESS0 + SBDATA0 into 1 USB transfer,
        then checks error. Reduces from 4 to 2 USB transfers.

        Args:
            address: Target memory address
            value: Value to write
            size: Access size in bits

        Raises:
            RiscvError: If SBA not available or error occurs
        """
        if not self._available:
            raise RiscvError("SBA not available")

        sbaccess = self._access_size_to_sbaccess(size)
        sbcs = SBCS.build_write_config(sbaccess)
        self._dmi.start_deferred()
        self._dmi.write(DMReg.SBCS, sbcs)
        self._dmi.write(DMReg.SBADDRESS0, address)
        self._dmi.write(DMReg.SBDATA0, value)
        self._dmi.flush_deferred()
        self._check_error()

    def read_memory_batch(self, address: int, count: int,
                          size: int = 32) -> List[int]:
        """Read multiple consecutive memory locations.

        Uses deferred DMI batching for count > 1, reducing USB round-trips
        from N (one per word) to approximately N/BATCH_CHUNK_SIZE.

        Configures SBCS (sbreadonaddr + sbreadondata + sbautoincrement),
        writes SBADDRESS0 to trigger the first read, then reads SBDATA0 in
        chunked batches via the deferred loop (sbreadondata auto-triggers
        the next bus access; the final value is read in a separate batch
        after clearing SBCS), and checks sberror.

        For count=1, delegates to single read path (no batching overhead).

        Args:
            address: Start address
            count: Number of values to read
            size: Access size in bits

        Returns:
            List of read values
        """
        if not self._available:
            raise RiscvError("SBA not available")

        if count < 1:
            raise ValueError("count must be >= 1")

        # Single word: use direct path (no batching overhead)
        if count == 1:
            return [self.read_memory(address, size)]

        # Multi-word: use deferred batching
        sbaccess = self._access_size_to_sbaccess(size)

        sbcs = SBCS.build_batch_read_config(sbaccess)
        self._dmi.write(DMReg.SBCS, sbcs)
        self._dmi.write(DMReg.SBADDRESS0, address)

        results = self._read_sba_deferred_loop(address, count)

        self._check_error()
        return results

    def write_memory_batch(self, address: int, values: List[int],
                           size: int = 32) -> None:
        """Write multiple consecutive memory locations.

        Uses deferred DMI batching for count > 1, reducing USB round-trips
        from N to approximately N/BATCH_CHUNK_SIZE.

        Configures SBCS (sbaccess + sbautoincrement), writes SBADDRESS0,
        writes SBDATA0 in chunked batches via the deferred loop, and
        checks sberror.

        For single value, delegates to single write path.

        Args:
            address: Start address
            values: Values to write
            size: Access size in bits
        """
        if not self._available:
            raise RiscvError("SBA not available")

        if not values:
            return

        # Single value: use direct path
        if len(values) == 1:
            self.write_memory(address, values[0], size)
            return

        # Multi-value: use deferred batching with fused setup
        sbaccess = self._access_size_to_sbaccess(size)
        sbcs = SBCS.build_write_config(sbaccess, autoincrement=True)

        self._write_sba_deferred_loop_fused(address, values, sbcs)

        # Check for SBA errors.
        # Do NOT write SBCS=0 here: per RISC-V Debug Spec v0.13.2,
        # writing SBCS while sbbusy=1 is undefined behavior.
        # The deferred loop's last SBDATA0 write may still be processing
        # on the system bus. _check_error() reads SBCS (safe) and the
        # DMI read round-trip gives the SBA time to complete.
        # SBCS will be reconfigured by the next SBA operation.
        self._check_error()
