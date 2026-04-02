# pyOCD debugger
# Copyright (c) 2021-2022 Chris Reed
# Copyright (c) 2025-2026 Arm Limited
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

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from time import sleep, monotonic
from typing import (cast, Dict, TYPE_CHECKING, Optional, Tuple, Union)

from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.ap import (APAddressBase, APv1Address, AccessPort, MEM_AP)
from ...probe.debug_probe import DebugProbe
from .delegates import DebugSequenceFunctionsDelegate
from .sequences import DebugSequenceRuntimeError

if TYPE_CHECKING:
    from ...coresight.dap import DebugPort

LOG = logging.getLogger(__name__)


@dataclass
class _Buffer:
    """@brief Simple container for sequence-local buffers."""

    data: bytearray


class _SequenceBufferManager:
    """@brief Manages per-sequence buffers stored on the root scope of the running sequence."""

    def __init__(self, get_sequence_scope_callback) -> None:
        self._get_sequence_scope = get_sequence_scope_callback

    def _store(self) -> Dict[int, _Buffer]:
        seq_scope = self._get_sequence_scope()
        buffers = getattr(seq_scope, "_buffers", None)
        if buffers is None:
            buffers = {}
            setattr(seq_scope, "_buffers", buffers)
        return cast(Dict[int, _Buffer], buffers)

    def get(self, id: int, create: bool = False) -> _Buffer:
        buffers = self._store()
        try:
            return buffers[id]
        except KeyError:
            if not create:
                raise DebugSequenceRuntimeError(f"buffer {id} does not exist")
            buffers[id] = _Buffer(bytearray())
            return buffers[id]

    @staticmethod
    def ensure_capacity(buffer: _Buffer, size: int) -> None:
        if size > len(buffer.data):
            buffer.data.extend(b"\x00" * (size - len(buffer.data)))

# Disable warnings for the non-standard methods names we use to match the sequences function
# names, since introspection is used to look up functions.
# pylint: disable=invalid_name

class DebugSequenceCommonFunctions(DebugSequenceFunctionsDelegate):
    """@brief Implements functions provided by the debug sequence environment."""

    APSEL_SHIFT = 24

    DP_ABORT = 0x00

    _FILLER = 0xFFFFFFFFFFFFFFFF

    def __init__(self) -> None:
        self._ap_cache: Dict[APAddressBase, MEM_AP] = {}
        self._flash_buffer: Optional[bytearray] = None
        self._flash_filler: int = self._FILLER
        self._placeholders_cache: Optional[Dict[str, str]] = None
        self._buffer_manager = _SequenceBufferManager(self._get_sequence_scope)

    @property
    def target(self) -> CoreSightTarget:
        return cast(CoreSightTarget, self.context.session.target)

    def restore_temp_ap_csw(self) -> None:
        """@brief Restore CSW on any temporary MEM-AP objects created during sequence execution."""
        for ap in self._ap_cache.values():
            ap.restore_original_csw_if_cached_modified()

    def set_flash_buffer(self, data: Union[bytes, bytearray], filler: Optional[int] = None) -> None:
        """@brief Provide flash buffer content for FlashBufferWrite()."""

        self._flash_buffer = bytearray(data)
        self._flash_filler = self._FILLER if filler is None else (filler & self._FILLER)

    def _get_sequence_scope(self):
        """@brief Return the scope associated with the currently running sequence."""

        scope = self.context.current_scope
        root_scope = self.context.delegate.get_root_scope(self.context)
        while scope.parent is not None and scope.parent is not root_scope:
            scope = scope.parent
        return scope

    @staticmethod
    def _check_alignment(value: int, alignment: int, name: str) -> None:
        if alignment and (value % alignment):
            raise DebugSequenceRuntimeError(f"{name} (0x{value:x}) must be {alignment}-byte aligned")

    @staticmethod
    def _decode_mode(mode: int) -> Tuple[int, bool]:
        increment = (mode & 1) != 0
        access_size_bits = mode & 0x1FE

        if access_size_bits not in (8, 16, 32, 64):
            raise DebugSequenceRuntimeError(f"unsupported access size {access_size_bits}")

        return access_size_bits // 8, increment

    def _read_value(self, ap: MEM_AP, addr: int, size: int) -> int:
        if size == 1:
            return ap.read8(addr)
        if size == 2:
            return ap.read16(addr)
        if size == 4:
            return ap.read32(addr)
        if size == 8:
            return ap.read64(addr)
        raise DebugSequenceRuntimeError(f"unsupported access size {size * 8}")

    def _write_value(self, ap: MEM_AP, addr: int, size: int, value: int) -> None:
        if size == 1:
            ap.write8(addr, value)
        elif size == 2:
            ap.write16(addr, value)
        elif size == 4:
            ap.write32(addr, value)
        elif size == 8:
            ap.write64(addr, value)
        else:
            raise DebugSequenceRuntimeError(f"unsupported access size {size * 8}")

    @staticmethod
    def _int_to_bytes(value: int, size: int) -> bytes:
        return int(value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")

    def _expand_path(self, raw_path: str) -> Path:
        """@brief Expand a path string from a debug sequence, replacing custom placeholders and environment variables."""
        # Lazy-initialize and cache placeholders since they don't change during a session
        if self._placeholders_cache is None:
            device = self.context.delegate.cmsis_pack_device
            pname = self.context.pname
            if hasattr(self.target, 'get_output'):
                output = self.target.get_output()
            else:
                output = {}

            out_file_path = next((f for f, (_, _, p) in output.items() if (pname is None) or (pname == p)), '')
            out_folder_path = str(Path(out_file_path).parent) if out_file_path else ''

            self._placeholders_cache = {
                '$P': getattr(device, 'proj_path', ''),
                '#P': getattr(device, 'proj_path_name', ''),
                '$L': out_folder_path,
                '%L': out_file_path,
                '$S': getattr(device, 'pack_path', ''),
                '$D': getattr(device, 'part_number', ''),
            }

        # Unescape double characters
        path_str = raw_path.replace("$$", "$").replace("##", "#").replace("%%", "%")

        # Replace custom placeholders using cached dictionary
        for placeholder, value in self._placeholders_cache.items():
            path_str = path_str.replace(placeholder, str(value))

        # Expand environment variables
        path_str = path_str.lstrip("\\/")
        path_str = os.path.expandvars(path_str)
        return Path(path_str).expanduser()

    def _get_ap_addr(self) -> APAddressBase:
        """@brief Return the AP address selected by __ap or __apid variables.

        If the DFP uses apids then the `__apid` variable takes precedence. Otherwise the `__ap` variable
        is used.
        """
        pack_device = self.context.delegate.cmsis_pack_device

        if pack_device.uses_apid:
            apid = self.context.get_variable('__apid')
            try:
                ap_addr = pack_device.apid_map[apid]
            except KeyError:
                raise DebugSequenceRuntimeError(f"__apid has invalid value ({apid})")
        else:
            # The __ap variable is only used to reference v1 APs.
            # TODO handle __dp being non-zero, when we support multiple DPs.
            ap_addr = APv1Address(self.context.get_variable('__ap'))

            dp_num = self.context.get_variable('__dp')
            if dp_num != 0:
                raise DebugSequenceRuntimeError(f"currently only __dp==0 is supported ({dp_num} specified)")

        return ap_addr

    def _get_mem_ap(self) -> MEM_AP:
        """@brief Return the current MEM_AP object.

        Normally, the AP object created during discovery is returned from the target's dict of APs. However,
        sequences can be run prior to discovery, and are allowed to perform memory accesses. Therefore we must
        handle the case of there not being a readily available AP object by creating a temporary one here.

        A cache dict is used to prevent repeatedly recreating the same AP when multiple memory transfers
        appear in a sequence. The cache is _only_ used for temporary AP objects; the target's AP dict always
        takes priority and is checked first.
        """
        ap_addr = self._get_ap_addr()

        # Try to get an existing AP from the target.
        try:
            ap = self.target.aps[ap_addr]
            if not isinstance(ap, MEM_AP):
                raise DebugSequenceRuntimeError(f"AP at address {ap_addr} is not a MEM-AP")
            return ap
        except KeyError:
            pass

        # The AP doesn't exist or we haven't performed discovery yet, but we still need to support memory
        # transfers for debug sequences. So attempt to create a temporary one.
        # TODO can this only be done prior to discovery?

        # Check if we have already created and cached this AP.
        try:
            return self._ap_cache[ap_addr]
        except KeyError:
            pass

        # Haven't encountered this AP yet. Create and cache it.
        # This call will raise exceptions.TargetError if there is no AP with the requested address.
        ap = AccessPort.create(self.target.dp, ap_addr)

        # Make sure this is a MEM-AP.
        if not isinstance(ap, MEM_AP):
            raise DebugSequenceRuntimeError(f"AP at address {ap_addr} is not a MEM-AP")

        # Save in the cache.
        self._ap_cache[ap_addr] = ap

        return ap

    def _get_dp(self, ignore_apid: bool = False) -> DebugPort:
        """@brief Get the DebugPort object specified by the __dp or __apid variable."""
        pack_device = self.context.delegate.cmsis_pack_device
        if not pack_device.uses_apid or ignore_apid:
            dp_num = self.context.get_variable('__dp')
        else:
            apid = self.context.get_variable('__apid')
            try:
                ap_addr = pack_device.apid_map[apid]
            except KeyError:
                raise DebugSequenceRuntimeError(f"__apid has invalid value ({apid})")
            else:
                dp_num = ap_addr.dp_index

        if dp_num != 0:
            raise DebugSequenceRuntimeError(f"currently only __dp==0 is supported ({dp_num} specified)")

        # In any case, for now we always return the only DebugPort object we have.
        return self.target.dp

    def _get_ignore_errors(self) -> bool:
        """@brief Whether the debug sequence has set __errorcontrol to ignore faults."""
        errcontrol = self.context.get_variable('__errorcontrol')
        return (errcontrol & 1) == 1

    def sequence(self, name: str) -> None:
        # This call will raise if the named sequence is invalid. However, we should have already
        # verified the sequence name is valid during semantic checking.
        #
        # The pname from the current context is passed in order to match a pname-specific
        # sequence; a matching sequence with no pname will also be found.
        seq = self.context.delegate.get_sequence_with_name(name, pname=self.context.pname)

        if self.context.pname:
            LOG.debug("Running debug sub-sequence '%s' (%s)", name, self.context.pname)
        else:
            LOG.debug("Running debug sub-sequence '%s'", name)

        # Run the sequence.
        subsequence_scope = seq.execute(self.context)

        # Copy the result to parent sequence.
        if subsequence_scope is not None:
            result_value = subsequence_scope.get('__Result')
            LOG.debug("Sub-sequence '%s' result = %d", name, result_value)
            self.context.current_scope.set('__Result', result_value)

    def read8(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read8(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read8(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def read16(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read16(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read16(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def read32(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read32(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read32(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def read64(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read64(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read64(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def readap(self, addr: int) -> int:
        try:
            ap_addr = self._get_ap_addr()
            reg_addr = ap_addr.address | addr
            return self._get_dp().read_ap(reg_addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("ReadAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def readaccessap(self, addr: int) -> int:
        try:
            dp = self._get_dp(True)
            apacc = dp.apacc_memory_interface
            return apacc.read32(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("ReadAccessAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def readdp(self, addr: int) -> int:
        try:
            return self._get_dp(True).read_dp(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("ReadDP(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def write8(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write8(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write8(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def write16(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write16(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write16(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def write32(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write32(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write32(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def write64(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write64(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write64(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def writeap(self, addr: int, val: int) -> None:
        try:
            ap_addr = self._get_ap_addr()
            reg_addr = ap_addr.address | addr
            self._get_dp().write_ap(reg_addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("WriteAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def writeaccessap(self, addr: int, val: int) -> None:
        try:
            dp = self._get_dp(True)
            apacc = dp.apacc_memory_interface
            apacc.write32(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("WriteAccessAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def writedp(self, addr: int, val: int) -> None:
        try:
            self._get_dp(True).write_dp(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("WriteDP(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def flashwritebuffer(self, addr: int, offset: int, length: int, mode: int) -> None:
        if self._flash_buffer is None:
            raise DebugSequenceRuntimeError("FlashWriteBuffer called without a flash buffer")

        access_size, increment = self._decode_mode(mode)
        self._check_alignment(addr, access_size, "addr")
        self._check_alignment(offset, access_size, "offset")
        self._check_alignment(length, access_size, "length")

        ap = self._get_mem_ap()
        while length > 0:
            data_bytes = self._flash_buffer[offset:offset + access_size]
            if len(data_bytes) < access_size:
                filler_bytes = self._flash_filler.to_bytes(8, "little")
                data_bytes = bytes(data_bytes) + filler_bytes[len(data_bytes):access_size]
            value = int.from_bytes(data_bytes, "little")
            self._write_value(ap, addr, access_size, value)
            if increment:
                addr += access_size
            offset += access_size
            length -= access_size

        self.target.flush()

    def dap_delay(self, delay: int) -> None:
        # Flush before sleeping, in case there are any outstanding transactions.
        self.target.flush()

        # TODO This is really expected to be sent to the target via the CMSIS-DAP command, but for most
        # cases this will work fine. However, it would fail for atomic sequences.
        sleep(delay / 1e6)

    def dap_writeabort(self, value: int) -> None:
        assert self.context.session.probe
        mode = self.context.session.probe.wire_protocol
        if mode == DebugProbe.Protocol.SWD:
            self._get_dp().write_reg(self.DP_ABORT, value)
        elif mode == DebugProbe.Protocol.JTAG:
            # On a JTAG-DP, for the AP Abort Register:
            # bit [0], DAPABORT, is the only bit that is defined
            value &= 1
            self._get_dp().write_reg(self.DP_ABORT, value)
        self.target.flush()

    def dap_swj_pins(self, pinout: int, pinselect: int, pinwait: int) -> int:
        """
        Pin bits:
        - Bit 0: SWCLK/TCK
        - Bit 1: SWDIO/TMS
        - Bit 2: TDI
        - Bit 3: TDO
        - Bit 5: nTRST
        - Bit 7: nRESET

        Must return 0xFFFFFFFF if the pins cannot be read.
        """
        from ...probe.cmsis_dap_probe import CMSISDAPProbe

        probe = self.context.session.probe
        assert probe
        if DebugProbe.Capability.PIN_ACCESS not in probe.capabilities:
            return 0xFFFFFFFF

        # Write pins if any were selected to be modified, wait if needed, then read
        # all available pins.
        if pinselect != 0:
            probe.write_pins(DebugProbe.PinGroup.PROTOCOL_PINS,
                    CMSISDAPProbe.from_cmsis_dap_pins(pinselect),
                    CMSISDAPProbe.from_cmsis_dap_pins(pinout))
        if pinwait > 0:
            sleep(pinwait / 1e9)
        result = CMSISDAPProbe.to_cmsis_dap_pins(
                probe.read_pins(DebugProbe.PinGroup.PROTOCOL_PINS,
                                DebugProbe.ProtocolPin.ALL_PINS))

        return result

    def dap_swj_clock(self, val: int) -> None:
        assert self.context.session.probe
        self.context.session.probe.set_clock(val)

    def dap_swj_sequence(self, cnt: int, val: int) -> None:
        probe = self.context.session.probe
        assert probe
        if DebugProbe.Capability.SWJ_SEQUENCE not in probe.capabilities:
            raise DebugSequenceRuntimeError(
                    "debug sequence called DAP_SWJ_Sequence, but debug probe does not support this operation")
        probe.swj_sequence(cnt, val)

    def dap_jtag_sequence(self, cnt: int, tms: int, tdi: int) -> int:
        probe = self.context.session.probe
        assert probe
        if DebugProbe.Capability.JTAG_SEQUENCE not in probe.capabilities:
            raise DebugSequenceRuntimeError(
                "debug sequence called DAP_JTAG_Sequence, but debug probe does not support this operation")
        tdo = probe.jtag_sequence(cnt, tms, True, tdi)
        return tdo or 0

    def query(self, type: int, message: str, default: int) -> int:
        LOG.info(f"Query({type}): {message} [{default}]")
        # Just return the default value since we're running in "batch" mode.
        return default

    def queryvalue(self, message: str, default: int) -> int:
        LOG.info(f"QueryValue: {message} [{default}]")
        # Just return the default value since we're running in "batch" mode.
        return default

    _MESSAGE_LEVEL_MAP = {
        0: logging.INFO,
        1: logging.WARNING,
        2: logging.ERROR,
    }
    def message(self, type: int, format: str, *args: int) -> None:
        level = self._MESSAGE_LEVEL_MAP.get(type, 2) # default to error for invalid type
        LOG.log(level, format % args)

    def loaddebuginfo(self, file: str) -> int:
        # Return 1 to indicate failure.
        return 1

    def bufferset(self, id: int, offset: int, count: int, size: int, value: int) -> int:
        """
        @brief Fill a buffer with a specific value pattern. A new buffer of required size is created \
            if it does not exist. An existing buffer is extended if it is too small.

        @param id: Numeric buffer ID. Must be a constant number.
        @param offset: First byte in the buffer to start writing the specified value pattern. Must be a multiple of size.
        @param count: Number of size items to write with the specified value pattern.
        @param size: Size of a single item to set. Must be in the range of 1 - 8.
        @param value: Value pattern to set. The size least significant bytes of value are used as value pattern for writing the buffer.
        @return: Number of written bytes (written bytes * access size)
        """
        if not 1 <= size <= 8:
            raise DebugSequenceRuntimeError("BufferSet size must be in range 1..8")

        self._check_alignment(offset, size, "buffOffset")

        buffer = self._buffer_manager.get(id, create=True)
        written_bytes = count * size
        end = offset + written_bytes
        self._buffer_manager.ensure_capacity(buffer, end)

        pattern = self._int_to_bytes(value, size)
        for i in range(count):
            start = offset + (i * size)
            buffer.data[start:start + size] = pattern

        return written_bytes

    def bufferget(self, id: int, offset: int, size: int) -> int:
        """
        @brief Get a data item from the buffer.

        @param id: Numeric buffer ID. Must be a constant number. Function fails if buffer does not exist.
        @param offset: Buffer offset in bytes to get the data item from. Must be a multiple of size.
        @param size: Size of a single item to get. Must be in the range of 1 - 8.
        @return: Data value of specified size at buffer offset.
        """
        if not 1 <= size <= 8:
            raise DebugSequenceRuntimeError("BufferGet size must be in range 1..8")

        self._check_alignment(offset, size, "buffOffset")

        buffer = self._buffer_manager.get(id, create=False)
        if (offset + size) > len(buffer.data):
            raise DebugSequenceRuntimeError("BufferGet exceeds buffer size")

        return int.from_bytes(buffer.data[offset:offset + size], "little")

    def buffersize(self, id: int) -> int:
        """
        @brief Get the current size of a data buffer.

        @param id: Numeric buffer ID. Must be a constant number.
        @return: Current buffer size in bytes. Return value is 0 if a buffer does not exist.
        """
        try:
            buffer = self._buffer_manager.get(id, create=False)
        except DebugSequenceRuntimeError:
            return 0

        return len(buffer.data)

    def bufferread(self, id: int, offset: int, addr: int, length: int, mode: int) -> int:
        """
        @brief Read data from target memory into a data buffer.

        @param id: Numeric buffer ID. Must be a constant number.
        @param offset: First byte in the buffer to store the read data. Must be a multiple of \
            the number of bytes as specified by access size in mode.
        @param addr: Target address to start reading from. Must be a multiple of the number of bytes \
            as specified by access size in mode.
        @param length: Number of bytes to read from target. Must be a multiple of the number of bytes \
            as specified by access size in mode.
        @param mode: The target access mode. \
            - Bit 0..8: Debug access size. One of 8, 16, 32 and 64. Specified debug access size must be \
                supported by the target hardware. For example a DP register access must always be 32-Bit.
            - Bit 0: Additionally set this Bit to 1 to increment the target address after each debug read \
                access of the specified size.
        @return: Always 0. Function causes fatal error if not successful.
        """
        access_size, increment = self._decode_mode(mode)
        self._check_alignment(offset, access_size, "buffOffset")
        self._check_alignment(addr, access_size, "addr")
        self._check_alignment(length, access_size, "length")

        buffer = self._buffer_manager.get(id, create=True)
        end = offset + length
        self._buffer_manager.ensure_capacity(buffer, end)

        ap = self._get_mem_ap()
        while length > 0:
            value = self._read_value(ap, addr, access_size)
            buffer.data[offset:offset + access_size] = self._int_to_bytes(value, access_size)
            if increment:
                addr += access_size
            offset += access_size
            length -= access_size

        return 0

    def bufferwrite(self, id: int, offset: int, addr: int, length: int, mode: int) -> int:
        """
        @brief Write data from buffer into target.

        @param id: Numeric buffer ID. Must be a constant number. Function fails if buffer does not exist.
        @param offset: First byte in the buffer to transfer into target. Must be a multiple of the number \
            of bytes as specified by access size in mode.
        @param addr: Target address to start writing to. Must be a multiple of the number of bytes \
            as specified by access size in mode.
        @param length: Number of bytes to write to the target. Must be a multiple of the number of bytes \
            as specified by access size in mode. If size of valid buffer data is less than (buffOffset + length) \
                then the function ends early and returns the number of actually written bytes.
        @param mode: The target access mode. \
            - Bit 0..8: Debug access size. One of 8, 16, 32 and 64. Specified debug access size must be \
                supported by the target hardware. For example a DP register access must always be 32-Bit.
            - Bit 0: Additionally set this Bit to 1 to increment the target address after each debug write \
                access of the specified size.
        @return: Number of actually written bytes.
        """
        buffer = self._buffer_manager.get(id, create=False)

        access_size, increment = self._decode_mode(mode)
        self._check_alignment(offset, access_size, "buffOffset")
        self._check_alignment(addr, access_size, "addr")
        self._check_alignment(length, access_size, "length")

        available = len(buffer.data) - offset
        if available <= 0:
            return 0

        write_len = min(length, available)
        write_len -= write_len % access_size
        if write_len <= 0:
            return 0

        ap = self._get_mem_ap()
        remaining = write_len
        while remaining > 0:
            value = int.from_bytes(buffer.data[offset:offset + access_size], "little")
            self._write_value(ap, addr, access_size, value)
            if increment:
                addr += access_size
            offset += access_size
            remaining -= access_size

        self.target.flush()
        return write_len

    def bufferstreamin(self, id: int, offset: int, length: int, path: str, mode: int, timeout: int) -> int:
        """
        @brief Stream data from an external source, e.g. a file, into a buffer. A new buffer of required size \
            is created if it does not exist. An existing buffer is extended if it is too small.

        @param id: Numeric buffer ID. Must be a constant number.
        @param offset: First byte in the buffer to store the received data.
        @param length: Maximum number of bytes to stream in. Use value 0xFFFFFFFFFFFFFFFF to for example read \
            a complete file of unknown size.
        @param path: Constant string value representing the source from which to stream data in. Refer to character \
            sequences for path/file name place holders.
        @param mode: Specifies how to treat the data source in the specified mode.
            - Bit 0..3: Format of the data source: 0 - Binary File
            - Bit 4..7: Communication options for data source.
        @param timeout: Timeout in microseconds. If 0, then synchronously wait for the operation to finish.
        @return: Number of bytes streamed into buffer. Can be less than length if the data source signals its end.
        """
        fmt = mode & 0xF
        if fmt not in (0,):
            raise DebugSequenceRuntimeError("Only binary file streams (mode 0) are supported")

        file_path = self._expand_path(path)
        read_len = None if length == 0xFFFFFFFFFFFFFFFF else length

        data: Optional[bytes] = None
        exc: Optional[Exception] = None

        def _do_read() -> None:
            nonlocal data, exc
            try:
                with file_path.open('rb') as f:
                    data = f.read(read_len)
            except Exception as e:
                exc = e

        thread = threading.Thread(target=_do_read, daemon=True)
        thread.start()
        timeout_s = None if timeout == 0 else timeout / 1e6
        thread.join(timeout_s)
        if thread.is_alive():
            raise DebugSequenceRuntimeError(f"BufferStreamIn timed out after {timeout_s:.3f}s")
        if exc is not None:
            raise exc

        assert data is not None
        buffer = self._buffer_manager.get(id, create=True)
        end = offset + len(data)
        self._buffer_manager.ensure_capacity(buffer, end)
        buffer.data[offset:end] = data

        return len(data)

    def bufferstreamout(self, id: int, offset: int, length: int, path: str, mode: int, timeout: int) -> int:
        """
        @brief Stream data from a buffer to an external data sink, e.g. a file.

        @param id: Numeric buffer ID. Must be a constant number. Function fails if buffer does not exist.
        @param offset: First byte in the buffer to transfer to the external data sink.
        @param length: Maximum number of bytes to stream out.
        @param path: Constant string value representing the destination to which to stream data to. \
            Refer to character sequences for path/file name place holders.
        @param mode: Specifies how to treat the data source in the specified mode.
            - Bit 0..3: Format of the data source: 0 - Binary File
            - Bit 4..7: Communication options for data sink: 0 - Overwrite 1 - Append
        @param timeout: Timeout in microseconds. If 0, then synchronously wait for the operation to finish.
        @return: Number of bytes streamed to data sink.
        """
        fmt = mode & 0xF
        if fmt not in (0,):
            raise DebugSequenceRuntimeError("Only binary file streams (mode 0) are supported")

        buffer = self._buffer_manager.get(id, create=False)
        available = len(buffer.data) - offset
        if available <= 0:
            return 0

        write_len = min(length, available)
        data = bytes(buffer.data[offset:offset + write_len])

        file_path = self._expand_path(path)
        append = (mode & 0x10) != 0

        exc: Optional[Exception] = None

        def _do_write() -> None:
            nonlocal exc
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with file_path.open('ab' if append else 'wb') as f:
                    f.write(data)
            except Exception as e:
                exc = e

        thread = threading.Thread(target=_do_write, daemon=True)
        thread.start()
        timeout_s = None if timeout == 0 else timeout / 1e6
        thread.join(timeout_s)
        if thread.is_alive():
            raise DebugSequenceRuntimeError(f"BufferStreamOut timed out after {timeout_s:.3f}s")
        if exc is not None:
            raise exc

        return write_len

    def runapplication(self, path: str, args: str, workdir: str, timeout: int) -> int:
        """@brief Run an external application.

        @param path: Constant string representing the application path. Refer to character sequences \
            for path/file name place holders.
        @param args: Constant string with arguments to pass to the command line. Same placeholder character \
            sequences apply as for path.
        @param workdir: A constant string with the work directory for the command line tool. An empty string \
            means that the work directory is the current project folder. Same placeholder character sequences \
            apply as for path.
        @param timeout: Timeout in microseconds.
        @return: Application specific exit code.
        """
        app_path = self._expand_path(path)
        cwd = None if workdir == "" else str(self._expand_path(workdir))
        timeout_s = None if timeout == 0 else timeout / 1e6

        split_args = shlex.split(args.replace('\\"', '"'), posix=True) if args else []
        split_args = [str(self._expand_path(arg)) for arg in split_args]
        cmd = [str(app_path), *split_args]

        try:
            result = subprocess.run(cmd, cwd=cwd, timeout=timeout_s, check=False, capture_output=True)
            LOG.debug("Application stdout:\n%s", result.stdout.decode(errors='replace'))
            return int(result.returncode)
        except FileNotFoundError as err:
            raise DebugSequenceRuntimeError(f"failed to run application '{app_path}': {err}") from err
        except subprocess.TimeoutExpired as err:
            raise DebugSequenceRuntimeError(f"application '{app_path}' timed out after {timeout_s}s") from err

    def filepathexists(self, path: str, timeout: int) -> int:
        """@brief Check for existence of a file path.

        @param path: Constant string with the path to check. Refer to character sequences for path/file \
            name place holders.
        @param timeout: Timeout in microseconds: \
            If 0, then the path is checked and the function immediately returns. If other than 0, \
            check the path until it is valid or until the function times out. If timeout is hit while \
            executing a check and that check ends successfully, then the function returns success.
        @return: 0 - Path exists 1 - Path not found
        """
        target = self._expand_path(path)
        deadline = monotonic() + (timeout / 1e6)
        while not target.exists():
            if monotonic() > deadline:
                return 1
            sleep(0.05)
        return 0

# pylint: enable=invalid_name
