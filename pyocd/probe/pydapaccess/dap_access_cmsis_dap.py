# pyOCD debugger
# Copyright (c) 2006-2013,2018-2021 Arm Limited
# Copyright (c) 2020 Koji Kitayama
# Copyright (c) 2021-2022 Chris Reed
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

import re
import logging
import collections
import threading
from typing import (Any, Dict, Optional, Tuple, Union)

from .dap_settings import DAPSettings
from .dap_access_api import DAPAccessIntf
from .cmsis_dap_core import CMSISDAPProtocol
from .interface import (INTERFACE, USB_BACKEND, USB_BACKEND_V2)
from .interface.common import ARM_DAPLINK_ID
from .cmsis_dap_core import (
    Command,
    Pin,
    Capabilities,
    DAPSWOTransport,
    DAPSWOMode,
    DAPSWOControl,
    DAPTransferResponse,
    CMSISDAPVersion,
    )
from ...core import session
from ...utility.concurrency import locked

# NoneType was added in Python 3.10, but we need to support back to Python 3.6.
NoneType = type(None)

VersionTuple = Tuple[int, int, int]

# CMSIS-DAP values
AP_ACC = 1 << 0
DP_ACC = 0 << 0
READ = 1 << 1
WRITE = 0 << 1
VALUE_MATCH = 1 << 4
MATCH_MASK = 1 << 5

# SWO statuses.
class SWOStatus:
    DISABLED = 1
    CONFIGURED = 2
    RUNNING = 3
    ERROR = 4

class DAP_LED:
    DAP_DEBUGGER_CONNECTED = 0
    DAP_TARGET_RUNNING = 1

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

def _get_interfaces():
    """@brief Get the connected USB devices"""
    # Get CMSIS-DAPv1 interfaces.
    v1_interfaces = INTERFACE[USB_BACKEND].get_all_connected_interfaces()

    # Get CMSIS-DAPv2 interfaces.
    v2_interfaces = INTERFACE[USB_BACKEND_V2].get_all_connected_interfaces()

    # Prefer v2 over v1 if a device provides both, unless the 'cmsis_dap.prefer_v1' option is set.
    prefer_v1 = session.Session.get_current().options.get('cmsis_dap.prefer_v1')
    if prefer_v1:
        devices_in_both = [v2 for v2 in v2_interfaces for v1 in v1_interfaces
                            if _get_unique_id(v1) == _get_unique_id(v2)]
        for dev in devices_in_both:
            v2_interfaces.remove(dev)
    else:
        devices_in_both = [v1 for v1 in v1_interfaces for v2 in v2_interfaces
                            if _get_unique_id(v1) == _get_unique_id(v2)]
        for dev in devices_in_both:
            v1_interfaces.remove(dev)

    # Return the combined list.
    return v1_interfaces + v2_interfaces


def _get_unique_id(interface):
    """@brief Get the unique id from an interface"""
    return interface.get_serial_number()


class _Transfer(object):
    """@brief A wrapper object representing a command invoked by the layer above.

    The transfer class contains a logical register read or a block
    of reads to the same register.
    """

    def __init__(self, daplink, dap_index, transfer_count,
                 transfer_request, transfer_data):
        # Writes should not need a transfer object
        # since they don't have any response data
        assert isinstance(dap_index, int)
        assert isinstance(transfer_count, int)
        assert isinstance(transfer_request, int)
        assert transfer_request & READ
        self.daplink = daplink
        self.dap_index = dap_index
        self.transfer_count = transfer_count
        self.transfer_request = transfer_request
        self.transfer_data = transfer_data
        self._size_bytes = 0
        if transfer_request & READ:
            self._size_bytes = transfer_count * 4
        self._result = None
        self._error = None

    def get_data_size(self):
        """@brief Get the size in bytes of the return value of this transfer
        """
        return self._size_bytes

    def add_response(self, data):
        """@brief Add data read from the remote device to this object.

        The size of data added must match exactly the size
        that get_data_size returns.
        """
        assert len(data) == self._size_bytes
        result = []
        for i in range(0, self._size_bytes, 4):
            word = ((data[0 + i] << 0) | (data[1 + i] << 8) |
                    (data[2 + i] << 16) | (data[3 + i] << 24))
            result.append(word)
        self._result = result

    def add_error(self, error):
        """@brief Attach an exception to this transfer rather than data.
        """
        assert isinstance(error, Exception)
        self._error = error

    def get_result(self):
        """@brief Get the result of this transfer.
        """
        while self._result is None:
            if len(self.daplink._commands_to_read) > 0:
                self.daplink._read_packet()
            else:
                assert not self.daplink._crnt_cmd.get_empty()
                self.daplink.flush()

        if self._error is not None:
            # Pylint is confused and thinks self._error is None
            # since that is what it is initialized to.
            # Suppress warnings for this.
            # pylint: disable=raising-bad-type
            raise self._error

        assert self._result is not None
        return self._result

class _Command(object):
    """@brief Wrapper object representing a command sent to the layer below (ex. USB).

    This class wraps the physical commands DAP_Transfer and DAP_TransferBlock
    to provide a uniform way to build the command to most efficiently transfer
    the data supplied.  Register reads and writes individually or in blocks
    are added to a command object until it is full.  Once full, this class
    decides if it is more efficient to use DAP_Transfer or DAP_TransferBlock.
    The payload to send over the layer below is constructed with
    encode_data.  The response to the command is decoded with decode_data.
    """

    _command_counter = 0

    _UNSET_DAP_INDEX: int = -1

    def __init__(self, size):
        self._id = _Command._command_counter
        _Command._command_counter += 1
        self._size = size
        self._read_count = 0
        self._write_count = 0
        self._block_allowed = True
        self._block_request = None
        self._data = []
        self._dap_index = self._UNSET_DAP_INDEX
        self._data_encoded = False
        TRACE.debug("[cmd:%d] New _Command", self._id)

    @property
    def uid(self) -> int:
        return self._id

    def _get_free_transfers(self, blockAllowed, isRead):
        """@brief Return the number of available read or write transfers.
        """
        if blockAllowed:
            # DAP_TransferBlock request packet:
            #   BYTE | BYTE *****| SHORT**********| BYTE *************| WORD *********|
            # > 0x06 | DAP Index | Transfer Count | Transfer Request  | Transfer Data |
            #  ******|***********|****************|*******************|+++++++++++++++|
            send = self._size - 5 - 4 * self._write_count

            # DAP_TransferBlock response packet:
            #   BYTE | SHORT *********| BYTE *************| WORD *********|
            # < 0x06 | Transfer Count | Transfer Response | Transfer Data |
            #  ******|****************|*******************|+++++++++++++++|
            recv = self._size - 4 - 4 * self._read_count

            if isRead:
                return recv // 4
            else:
                return send // 4
        else:
            # DAP_Transfer request packet:
            #   BYTE | BYTE *****| BYTE **********| BYTE *************| WORD *********|
            # > 0x05 | DAP Index | Transfer Count | Transfer Request  | Transfer Data |
            #  ******|***********|****************|+++++++++++++++++++++++++++++++++++|
            send = self._size - 3 - 1 * self._read_count - 5 * self._write_count

            # DAP_Transfer response packet:
            #   BYTE | BYTE **********| BYTE *************| WORD *********|
            # < 0x05 | Transfer Count | Transfer Response | Transfer Data |
            #  ******|****************|*******************|+++++++++++++++|
            recv = self._size - 3 - 4 * self._read_count

            if isRead:
                # 1 request byte in request packet, 4 data bytes in response packet
                return min(send, recv // 4)
            else:
                # 1 request byte + 4 data bytes
                return send // 5

    def get_request_space(self, count, request, dap_index):
        assert self._data_encoded is False

        # Must create another command if the dap index is different.
        if self._dap_index != self._UNSET_DAP_INDEX and dap_index != self._dap_index:
            return 0

        # Block transfers must use the same request.
        blockAllowed = self._block_allowed
        if self._block_request is not None and request != self._block_request:
            blockAllowed = False

        # Compute the portion of the request that will fit in this packet.
        is_read = request & READ
        free = self._get_free_transfers(blockAllowed, is_read)
        size = min(count, free)

        # Non-block transfers only have 1 byte for request count.
        if not blockAllowed:
            max_count = self._write_count + self._read_count + size
            delta = max_count - 255
            size = min(size - delta, size)
            TRACE.debug("[cmd:%d] get_request_space(%d, %02x:%s)[wc=%d, rc=%d, ba=%d->%d] -> (sz=%d, free=%d, delta=%d)",
                    self.uid, count, request, 'r' if is_read else 'w', self._write_count, self._read_count,
                    self._block_allowed, blockAllowed, size, free, delta)
        else:
            TRACE.debug("[cmd:%d] get_request_space(%d, %02x:%s)[wc=%d, rc=%d, ba=%d->%d] -> (sz=%d, free=%d)",
                    self.uid, count, request, 'r' if is_read else 'w', self._write_count, self._read_count,
                    self._block_allowed, blockAllowed, size, free)

        # We can get a negative free count if the packet already contains more data than can be
        # sent by a DAP_Transfer command, but the new request forces DAP_Transfer. In this case,
        # just return 0 to force the DAP_Transfer_Block to be sent.
        return max(size, 0)

    def get_full(self):
        return (self._get_free_transfers(self._block_allowed, True) == 0) or \
            (self._get_free_transfers(self._block_allowed, False) == 0)

    def get_empty(self):
        """@brief Return True if no transfers have been added to this packet
        """
        return len(self._data) == 0

    def add(self, count, request, data, dap_index):
        """@brief Add a single or block register transfer operation to this command
        """
        assert self._data_encoded is False
        if self._dap_index == self._UNSET_DAP_INDEX:
            self._dap_index = dap_index
        assert self._dap_index == dap_index

        if self._block_request is None:
            self._block_request = request
        elif request != self._block_request:
            self._block_allowed = False
        assert not self._block_allowed or self._block_request == request

        if request & READ:
            self._read_count += count
        else:
            self._write_count += count
        self._data.append((count, request, data))

        TRACE.debug("[cmd:%d] add(%d, %02x:%s) -> [wc=%d, rc=%d, ba=%d]",
                self.uid, count, request, 'r' if (request & READ) else 'w', self._write_count, self._read_count,
                self._block_allowed)

    def _encode_transfer_data(self):
        """@brief Encode this command into a byte array that can be sent

        The data returned by this function is a bytearray in
        the format that of a DAP_Transfer CMSIS-DAP command.
        """
        assert self.get_empty() is False
        buf = bytearray(self._size)
        transfer_count = self._read_count + self._write_count
        pos = 0
        buf[pos] = Command.DAP_TRANSFER
        pos += 1
        buf[pos] = self._dap_index
        pos += 1
        buf[pos] = transfer_count
        pos += 1
        for count, request, write_list in self._data:
            assert write_list is None or len(write_list) <= count
            write_pos = 0
            for _ in range(count):
                buf[pos] = request
                pos += 1
                if not request & READ:
                    buf[pos] = (write_list[write_pos] >> (8 * 0)) & 0xff
                    pos += 1
                    buf[pos] = (write_list[write_pos] >> (8 * 1)) & 0xff
                    pos += 1
                    buf[pos] = (write_list[write_pos] >> (8 * 2)) & 0xff
                    pos += 1
                    buf[pos] = (write_list[write_pos] >> (8 * 3)) & 0xff
                    pos += 1
                    write_pos += 1
        return buf[:pos]

    def _check_response(self, response):
        """@brief Check the response status byte from CMSIS-DAP transfer commands.

        The ACK bits [2:0] and the protocol error bit are checked. If any error is indicated,
        the appropriate exception is raised. An exception is also raised for unrecognised ACK
        values.

        @param self
        @param response The "Transfer Response" byte from a DAP_Transfer or DAP_TransferBlock
            command.

        @exception DAPAccessIntf.TransferFaultError Raised for the ACK_FAULT response.
        @exception DAPAccessIntf.TransferTimeoutError Raised for ACK_WAIT response.
        @exception DAPAccessIntf.TransferError Raised for other, less common errors, including No
            ACK, SWD protocol error, and an unknown ACK value. A descriptive error message is used
            to indicate which of these errors was the cause.
        """
        ack = response & DAPTransferResponse.ACK_MASK
        if ack != DAPTransferResponse.ACK_OK:
            if ack == DAPTransferResponse.ACK_FAULT:
                raise DAPAccessIntf.TransferFaultError()
            elif ack == DAPTransferResponse.ACK_WAIT:
                raise DAPAccessIntf.TransferTimeoutError()
            elif ack == DAPTransferResponse.ACK_NO_ACK:
                raise DAPAccessIntf.TransferError("No ACK received")
            else:
                raise DAPAccessIntf.TransferError("Unexpected ACK value (%d) returned by probe" % ack)
        elif (response & DAPTransferResponse.PROTOCOL_ERROR_MASK) != 0:
            raise DAPAccessIntf.TransferError("SWD protocol error")

    def _decode_transfer_data(self, data):
        """@brief Take a byte array and extract the data from it

        Decode the response returned by a DAP_Transfer CMSIS-DAP command
        and return it as an array of bytes.
        """
        assert self.get_empty() is False
        if data[0] != Command.DAP_TRANSFER:
            TRACE.debug("[cmd:%d] response not DAP_TRANSFER", self.uid)
            raise DAPAccessIntf.TransferError(f'DAP_TRANSFER response error: response is for command {data[0]:02x}')

        # Check response and raise an exception on errors.
        self._check_response(data[2])

        # Check for count mismatch after checking for DAP_TRANSFER_FAULT
        # This allows TransferFaultError or TransferTimeoutError to get
        # thrown instead of TransferFaultError
        if data[1] != self._read_count + self._write_count:
            raise DAPAccessIntf.TransferError()

        return data[3:3 + 4 * self._read_count]

    def _encode_transfer_block_data(self):
        """@brief Encode this command into a byte array that can be sent

        The data returned by this function is a bytearray in
        the format that of a DAP_TransferBlock CMSIS-DAP command.
        """
        assert self.get_empty() is False
        buf = bytearray(self._size)
        transfer_count = self._read_count + self._write_count
        assert not (self._read_count != 0 and self._write_count != 0)
        assert self._block_request is not None
        pos = 0
        buf[pos] = Command.DAP_TRANSFER_BLOCK
        pos += 1
        buf[pos] = self._dap_index
        pos += 1
        buf[pos] = transfer_count & 0xff
        pos += 1
        buf[pos] = (transfer_count >> 8) & 0xff
        pos += 1
        buf[pos] = self._block_request
        pos += 1
        for count, request, write_list in self._data:
            assert write_list is None or len(write_list) <= count
            assert request == self._block_request
            write_pos = 0
            if not request & READ:
                for _ in range(count):
                    buf[pos] = (write_list[write_pos] >> (8 * 0)) & 0xff
                    pos += 1
                    buf[pos] = (write_list[write_pos] >> (8 * 1)) & 0xff
                    pos += 1
                    buf[pos] = (write_list[write_pos] >> (8 * 2)) & 0xff
                    pos += 1
                    buf[pos] = (write_list[write_pos] >> (8 * 3)) & 0xff
                    pos += 1
                    write_pos += 1
        return buf[:pos]

    def _decode_transfer_block_data(self, data):
        """@brief Take a byte array and extract the data from it

        Decode the response returned by a DAP_TransferBlock CMSIS-DAP command
        and return it as an array of bytes.
        """
        assert self.get_empty() is False
        if data[0] != Command.DAP_TRANSFER_BLOCK:
            TRACE.debug("[cmd:%d] response not DAP_TRANSFER_BLOCK", self.uid)
            raise DAPAccessIntf.TransferError(f'DAP_TRANSFER_BLOCK response error: response is for command {data[0]:02x}')

        # Check response and raise an exception on errors.
        self._check_response(data[3])

        # Check for count mismatch after checking for DAP_TRANSFER_FAULT
        # This allows TransferFaultError or TransferTimeoutError to get
        # thrown instead of TransferFaultError
        transfer_count = data[1] | (data[2] << 8)
        if transfer_count != self._read_count + self._write_count:
            raise DAPAccessIntf.TransferError()

        return data[4:4 + 4 * self._read_count]

    def encode_data(self):
        """@brief Encode this command into a byte array that can be sent

        The actual command this is encoded into depends on the data
        that was added.
        """
        assert self.get_empty() is False
        self._data_encoded = True
        if self._block_allowed:
            data = self._encode_transfer_block_data()
        else:
            data = self._encode_transfer_data()
        return data

    def decode_data(self, data):
        """@brief Decode the response data
        """
        assert self.get_empty() is False
        assert self._data_encoded is True
        if self._block_allowed:
            data = self._decode_transfer_block_data(data)
        else:
            data = self._decode_transfer_data(data)
        return data

class DAPAccessCMSISDAP(DAPAccessIntf):
    """@brief An implementation of the DAPAccessIntf layer for DAPLink boards

    @internal
    All methods that use the CMSISDAPProtocol instance must be locked and must flush the command queue
    prior to using methods of that object. Otherwise the command responses may be processed out of order.
    """

    # ------------------------------------------- #
    #          Static Functions
    # ------------------------------------------- #
    @staticmethod
    def get_connected_devices():
        """@brief Return an array of all mbed boards connected
        """
        all_daplinks = []
        all_interfaces = _get_interfaces()
        for interface in all_interfaces:
            try:
                new_daplink = DAPAccessCMSISDAP(None, interface=interface)
                all_daplinks.append(new_daplink)
            except DAPAccessIntf.TransferError:
                LOG.error('Failed to get unique id', exc_info=session.Session.get_current().log_tracebacks)
        return all_daplinks

    @staticmethod
    def get_device(device_id):
        assert isinstance(device_id, str)
        iface = DAPAccessCMSISDAP._lookup_interface_for_unique_id(device_id)
        if iface is not None:
            return DAPAccessCMSISDAP(device_id, iface)
        else:
            return None

    @staticmethod
    def set_args(arg_list):
        # Example: arg_list =['limit_packets=True']
        arg_pattern = re.compile("([^=]+)=(.*)")
        if arg_list:
            for arg in arg_list:
                match = arg_pattern.match(arg)
                # check if arguments have correct format
                if match:
                    attr = match.group(1)
                    if hasattr(DAPSettings, attr):
                        val = match.group(2)
                        # convert string to int or bool
                        if val.isdigit():
                            val = int(val)
                        elif val == "True":
                            val = True
                        elif val == "False":
                            val = False
                        setattr(DAPSettings, attr, val)

    @staticmethod
    def _lookup_interface_for_unique_id(unique_id):
        result_interface = None
        all_interfaces = _get_interfaces()
        for interface in all_interfaces:
            try:
                if _get_unique_id(interface) == unique_id:
                    # This assert could indicate that two boards
                    # had the same ID
                    assert result_interface is None, "More than one probes with ID {}".format(unique_id)
                    result_interface = interface
            except Exception:
                LOG.error('Failed to get unique id for open', exc_info=session.Session.get_current().log_tracebacks)
        return result_interface

    # ------------------------------------------- #
    #          CMSIS-DAP and Other Functions
    # ------------------------------------------- #
    def __init__(self, unique_id, interface=None):
        assert isinstance(unique_id, str) or (unique_id is None and interface is not None)
        super(DAPAccessCMSISDAP, self).__init__()

        # Search for a matching interface if one wasn't provided.
        if interface is None:
            interface = DAPAccessCMSISDAP._lookup_interface_for_unique_id(unique_id)
            if interface is None:
                raise self.DeviceError("no device with ID %s" % unique_id)

        if interface is not None:
            self._unique_id = _get_unique_id(interface)
            self._vendor_name = interface.vendor_name
            self._product_name = interface.product_name
            self._vidpid = (interface.vid, interface.pid)
        else:
            # Set default values for an unknown interface.
            self._unique_id = unique_id
            self._vendor_name = ""
            self._product_name = ""
            self._vidpid = (0, 0)

        self._lock = threading.RLock()
        self._interface = interface
        self._deferred_transfer = False
        self._protocol = CMSISDAPProtocol(self._interface)
        self._packet_count = None
        self._frequency = 1000000  # 1MHz default clock
        self._dap_port = None
        self._transfer_list = collections.deque()
        self._crnt_cmd = _Command(0)
        self._packet_size = None
        self._commands_to_read = collections.deque()
        self._command_response_buf = bytearray()
        self._swo_status = None
        self._cmsis_dap_version: VersionTuple = CMSISDAPVersion.V1_0_0
        self._fw_version: Optional[str] = None
        self._has_opened_once = False
        self._is_open: bool = False
        self._cached_info: Dict[DAPAccessIntf.ID, Any] = {}

    @property
    def protocol_version(self) -> VersionTuple:
        """@brief Tuple of CMSIS-DAP protocol version.
        @return 3-tuple consisting of (major, minor, micro) version of the CMSIS-DAP protocol implemented
            by the debug probe.
        """
        return self._cmsis_dap_version

    @property
    def firmware_version(self) -> Optional[str]:
        """@brief A string of the product firmware version, or None.

        Only probes supporting CMSIS-DAP protocol v2.1 or later can return their firmware version.
        """
        return self._fw_version

    @property
    def vendor_name(self):
        return self._vendor_name

    @property
    def product_name(self):
        return self._product_name

    @property
    def vidpid(self):
        """@brief A tuple of USB VID and PID, in that order."""
        return self._vidpid

    @property
    def board_names(self) -> Tuple[Optional[str], Optional[str]]:
        """@brief Bi-tuple of CMSIS-DAP v2.1 board vendor name and product name.

        If the CMSIS-DAP protocol does not support reading board names from DAP_Info, a pair of
        None will be returned. If either of the names are not returned from the device, then None
        is substituted.
        """
        if not self.supports_board_and_target_names:
            return (None, None)
        vendor = self.identify(self.ID.BOARD_VENDOR)
        name = self.identify(self.ID.BOARD_NAME)
        assert isinstance(vendor, (str, NoneType)) and isinstance(name, (str, NoneType))
        return (vendor, name)

    @property
    def target_names(self) -> Tuple[Optional[str], Optional[str]]:
        """@brief Bituple of CMSIS-DAP v2.1 target vendor name and part number.

        If the CMSIS-DAP protocol does not support reading target names from DAP_Info, a pair of
        None will be returned. If either of the names are not returned from the device, then None
        is substituted.
        """
        if not self.supports_board_and_target_names:
            return (None, None)
        vendor = self.identify(self.ID.DEVICE_VENDOR)
        name = self.identify(self.ID.DEVICE_NAME)
        assert isinstance(vendor, (str, NoneType)) and isinstance(name, (str, NoneType))
        return (vendor, name)

    @property
    def has_swd_sequence(self):
        return self._cmsis_dap_version >= CMSISDAPVersion.V1_2_0

    @property
    def supports_board_and_target_names(self) -> bool:
        """@brief Boolean of whether board_names and target_names are supported."""
        return ((self._cmsis_dap_version >= CMSISDAPVersion.V2_1_0)
                or ((self._cmsis_dap_version >= CMSISDAPVersion.V1_3_0)
                    and (self._cmsis_dap_version < CMSISDAPVersion.V2_0_0)))

    def lock(self):
        """@brief Lock the interface."""
        self._lock.acquire()

    def unlock(self):
        """@brief Unlock the interface."""
        self._lock.release()

    def _read_protocol_version(self):
        """Determine the CMSIS-DAP protocol version."""
        # The fallback version to use when version parsing fails depends on whether v2 bulk endpoints are used
        # (unfortunately conflating transport with protocol).
        fallback_protocol_version = (CMSISDAPVersion.V1_0_0, CMSISDAPVersion.V2_0_0)[self._interface.is_bulk]

        protocol_version_str = self.identify(self.ID.CMSIS_DAP_PROTOCOL_VERSION)
        assert isinstance(protocol_version_str, (str, NoneType))

        # Just in case we don't get a valid response, default to the lowest version (not including betas).
        if not protocol_version_str:
            self._cmsis_dap_version = fallback_protocol_version
        # Deal with DAPLink broken version number, where these versions of the firmware reported the DAPLink
        # version number for DAP_INFO_FW_VER instead of the CMSIS-DAP version, due to a misunderstanding
        # based on unclear documentation.
        elif (self._vidpid == ARM_DAPLINK_ID) and (protocol_version_str in ("0254", "0255")):
            self._cmsis_dap_version = CMSISDAPVersion.V2_0_0
        else:
            # Convert the version to a 3-tuple for easy comparison.
            # 1.2.3 will be converted to (1,2,3), 1.10 to (1,1,0), and so on.
            #
            # There are two version formats returned from the reference CMSIS-DAP code: 2-field and 3-field.
            # The older versions return versions like "1.07" and "1.10", while recent versions return "1.2.0"
            # or "2.0.0".
            #
            # Some CMSIS-DAP compatible debug probes from various vendors return the probe's firmware version
            # rather than protocol version (like DAPLink versions 0254 and 0255 do) due to a misunderstanding
            # based on unclear documentation. These cases are handled by the additional error checking below.
            #
            # Note that the exact version identified here is not that important, as it's not used much in
            # this code (so far at least). There are also DAP_Info Capability bits for availability of certain
            # commands that should be used instead of checking the version.
            try:
                fw_version = protocol_version_str.split('.')
                major = int(fw_version[0])
                # Handle version of the form "1.10" by treating the two digits after the dot as minor and patch.
                if (len(fw_version) == 2) and len(fw_version[1]) == 2:
                    minor = int(fw_version[1][0])
                    patch = int(fw_version[1][1])
                # All other forms.
                else:
                    minor = int(fw_version[1] if len(fw_version) > 1 else 0)
                    patch = int(fw_version[2] if len(fw_version) > 2 else 0)
                self._cmsis_dap_version = (major, minor, patch)
            except ValueError:
                # One of the protocol version fields had a non-numeric character, indicating it is not a valid
                # CMSIS-DAP version number. Default to the lowest version.
                LOG.debug("Error parsing CMSIS-DAP protocol version '%s'", protocol_version_str)
                self._cmsis_dap_version = fallback_protocol_version

            # Catch the beta release versions of CMSIS-DAP, 0.01 and 0.02, and raise them to 1.0.0.
            if self._cmsis_dap_version[:2] == (0, 0):
                self._cmsis_dap_version = CMSISDAPVersion.V1_0_0
            # Validate the version against known CMSIS-DAP major versions.
            elif self._cmsis_dap_version[0] not in CMSISDAPVersion.major_versions():
                LOG.debug("Unrecognised major version of CMSIS-DAP: protocol version %i.%i.%i",
                        *self._cmsis_dap_version)
                self._cmsis_dap_version = fallback_protocol_version

    @property
    def is_open(self) -> bool:
        """@brief Whether the probe's USB interface is open."""
        return self._is_open

    @locked
    def open(self):
        if self._interface is None:
            raise DAPAccessIntf.DeviceError("Unable to open device with no interface")
        if self._is_open:
            return

        self._interface.open()

        # If this probe has already been opened and examined previously, we don't need to examine it again.
        if self._has_opened_once:
            self._init_deferred_buffers()
            if self._has_swo_uart:
                self._swo_disable()
                self._swo_status = SWOStatus.DISABLED
            self._is_open = True
            return

        if session.Session.get_current().options['cmsis_dap.limit_packets'] or DAPSettings.limit_packets:
            self._packet_count = 1
            LOG.debug("Limiting packet count to %d", self._packet_count)
        else:
            self._packet_count = self.identify(self.ID.MAX_PACKET_COUNT)
            assert isinstance(self._packet_count, int)

        # Get the protocol version.
        self._read_protocol_version()

        # Read the firmware version if the protocol supports it.
        # THe PRODUCT_FW_VERSION ID was added in versions 1.3.0 (HID) and 2.1.0 (bulk).
        if (self._cmsis_dap_version >= CMSISDAPVersion.V2_1_0) or (self._cmsis_dap_version >= CMSISDAPVersion.V1_3_0
                and self._cmsis_dap_version < CMSISDAPVersion.V2_0_0):
            fw_version_value = self.identify(self.ID.PRODUCT_FW_VERSION)
            assert isinstance(fw_version_value, (str, NoneType))
            self._fw_version = fw_version_value

        # Major protocol version based on use of bulk endpoints.
        proto_major = (2 if self._interface.is_bulk else 1)

        # Log probe's firmware version.
        if self._fw_version:
            LOG.debug("CMSIS-DAP v%d probe %s: firmware version %s, protocol version %i.%i.%i",
                    proto_major, self._unique_id, self._fw_version, *self._cmsis_dap_version)
        else:
            LOG.debug("CMSIS-DAP v%d probe %s: protocol version %i.%i.%i",
                    proto_major, self._unique_id, *self._cmsis_dap_version)

        self._interface.set_packet_count(self._packet_count)
        self._packet_size = self.identify(self.ID.MAX_PACKET_SIZE)
        assert isinstance(self._packet_size, int)
        self._interface.set_packet_size(self._packet_size)
        self._capabilities = self.identify(self.ID.CAPABILITIES)
        assert isinstance(self._capabilities, int)
        self._has_swo_uart = (self._capabilities & Capabilities.SWO_UART) != 0
        if self._has_swo_uart:
            swo_buffer_size_value = self.identify(self.ID.SWO_BUFFER_SIZE)
            if isinstance(swo_buffer_size_value, int) and swo_buffer_size_value > 0:
                self._swo_buffer_size = swo_buffer_size_value
            else:
                LOG.debug("CMSIS-DAP probe %s reported invalid SWO_BUFFER_SIZE (%d)",
                        self._unique_id, swo_buffer_size_value)
                self._has_swo_uart = False
        else:
            self._swo_buffer_size = 0
        self._swo_status = SWOStatus.DISABLED

        self._init_deferred_buffers()

        self._has_opened_once = True
        self._is_open = True

    @locked
    def close(self):
        assert self._interface is not None
        if not self._is_open:
            return
        self.flush()
        self._interface.close()
        self._is_open = False
        self._crnt_cmd = _Command(0)

    def get_unique_id(self):
        return self._unique_id

    @locked
    def pin_access(self, mask: int, value: int) -> int:
        self.flush()
        return self._protocol.set_swj_pins(value, mask)

    @locked
    def assert_reset(self, asserted):
        self.flush()
        if asserted:
            self._protocol.set_swj_pins(0, Pin.nRESET)
        else:
            self._protocol.set_swj_pins(Pin.nRESET, Pin.nRESET)

    @locked
    def is_reset_asserted(self):
        self.flush()
        pins = self._protocol.set_swj_pins(0, Pin.NONE)
        return (pins & Pin.nRESET) == 0

    @locked
    def set_clock(self, frequency):
        self.flush()
        self._protocol.set_swj_clock(int(frequency))
        self._frequency = frequency

    def get_swj_mode(self):
        return self._dap_port

    def set_deferred_transfer(self, enable):
        """@brief Allow transfers to be delayed and buffered

        By default deferred transfers are turned on.  When off, all reads and
        writes will be completed by the time the function returns.

        When enabled packets are buffered and sent all at once, which
        increases speed.  When memory is written to, the transfer
        might take place immediately, or might take place on a future
        memory write.  This means that an invalid write could cause an
        exception to occur on a later, unrelated write.  To guarantee
        that previous writes are complete call the flush() function.
        """
        if self._deferred_transfer and not enable:
            self.flush()
        self._deferred_transfer = enable

    @locked
    def flush(self):
        if TRACE.isEnabledFor(logging.DEBUG):
            if self._crnt_cmd.get_empty() and len(self._commands_to_read):
                TRACE.debug("flush: reading %d outstanding (cmd:%d is empty)",
                        len(self._commands_to_read), self._crnt_cmd.uid)
            elif not self._crnt_cmd.get_empty():
                TRACE.debug("flush: sending cmd:%d; reading %d outstanding", self._crnt_cmd.uid, len(self._commands_to_read))

        # Send current packet
        self._send_packet()
        # Read all backlogged
        for _ in range(len(self._commands_to_read)):
            self._read_packet()

    @locked
    def identify(self, item: DAPAccessIntf.ID) -> Union[int, str, None]:
        assert isinstance(item, DAPAccessIntf.ID)

        # Check if this item has already been read and cached.
        if item in self._cached_info:
            return self._cached_info[item]

        # Check if buffers are inited before calling flush, so identify() can be called from open(), before
        # the initing the deferred buffers.
        if not self._crnt_cmd.get_empty() or len(self._commands_to_read):
            self.flush()
        value = self._protocol.dap_info(item)
        self._cached_info[item] = value
        return value

    @locked
    def vendor(self, index, data=None):
        if data is None:
            data = []
        self.flush()
        return self._protocol.vendor(index, data)

    # ------------------------------------------- #
    #             Target access functions
    # ------------------------------------------- #
    @locked
    def connect(self, port=DAPAccessIntf.PORT.DEFAULT):
        assert isinstance(port, DAPAccessIntf.PORT)
        actual_port = self._protocol.connect(port.value)
        self._dap_port = DAPAccessIntf.PORT(actual_port)
        # set clock frequency
        self._protocol.set_swj_clock(self._frequency)
        # configure transfer
        self._protocol.transfer_configure()

        # configure the selected protocol with defaults.
        if self._dap_port == DAPAccessIntf.PORT.SWD:
            self.configure_swd()
        elif self._dap_port == DAPAccessIntf.PORT.JTAG:
            self.configure_jtag()

        self._protocol.set_led(DAP_LED.DAP_DEBUGGER_CONNECTED, 1)
        self._protocol.set_led(DAP_LED.DAP_TARGET_RUNNING, 0)

    @locked
    def configure_swd(self, turnaround=1, always_send_data_phase=False):
        self.flush()
        self._protocol.swd_configure(turnaround, always_send_data_phase)

    @locked
    def configure_jtag(self, devices_irlen=None):
        self.flush()
        self._protocol.jtag_configure(devices_irlen)

    @locked
    def swj_sequence(self, length, bits):
        self.flush()
        self._protocol.swj_sequence(length, bits)

    @locked
    def swd_sequence(self, sequences):
        self.flush()
        return self._protocol.swd_sequence(sequences)

    @locked
    def jtag_sequence(self, cycles, tms, read_tdo, tdi):
        self.flush()
        return self._protocol.jtag_sequence(cycles, tms, read_tdo, tdi)

    @locked
    def disconnect(self):
        self.flush()
        self._protocol.set_led(DAP_LED.DAP_DEBUGGER_CONNECTED, 0)
        self._protocol.set_led(DAP_LED.DAP_TARGET_RUNNING, 0)
        self._protocol.disconnect()

    def has_swo(self):
        return self._has_swo_uart

    @locked
    def swo_configure(self, enabled, rate):
        self.flush()

        # Don't send any commands if the SWO commands aren't supported.
        if not self._has_swo_uart:
            return False

        # Before we attempt any configuration, we must explicitly disable SWO
        # (if SWO is enabled, setting any other configuration fails).
        self._swo_disable()

        try:
            if enabled:
                # Select the streaming SWO endpoint if available.
                if self._interface.has_swo_ep:
                    transport = DAPSWOTransport.DAP_SWO_EP
                else:
                    transport = DAPSWOTransport.DAP_SWO_DATA

                if self._protocol.swo_transport(transport) != 0:
                    self._swo_disable()
                    return False
                if self._protocol.swo_mode(DAPSWOMode.UART) != 0:
                    self._swo_disable()
                    return False
                if self._protocol.swo_baudrate(rate) == 0:
                    self._swo_disable()
                    return False
                self._swo_status = SWOStatus.CONFIGURED

            return True
        except DAPAccessIntf.CommandError as e:
            LOG.debug("Exception while configuring SWO: %s", e)
            self._swo_disable()
            return False

    # Doesn't need @locked because it is only called from swo_configure().
    def _swo_disable(self):
        try:
            self._protocol.swo_mode(DAPSWOMode.OFF)
            self._protocol.swo_transport(DAPSWOTransport.NONE)
        except DAPAccessIntf.CommandError as e:
            LOG.debug("Exception while disabling SWO: %s", e)
        finally:
            self._swo_status = SWOStatus.DISABLED

    @locked
    def swo_control(self, start):
        self.flush()

        # Don't send any commands if the SWO commands aren't supported.
        if not self._has_swo_uart:
            return False

        if start:
            self._protocol.swo_control(DAPSWOControl.START)
            if self._interface.has_swo_ep:
                self._interface.start_swo()
            self._swo_status = SWOStatus.RUNNING
        else:
            self._protocol.swo_control(DAPSWOControl.STOP)
            if self._interface.has_swo_ep:
                self._interface.stop_swo()
            self._swo_status = SWOStatus.CONFIGURED
        return True

    @locked
    def get_swo_status(self):
        return self._protocol.swo_status()

    def swo_read(self, count=None):
        # The separate SWO EP can be read without locking.
        if self._interface.has_swo_ep:
            return self._interface.read_swo()
        else:
            if count is None:
                count = self._packet_size
            # Must lock and flush the command queue since we're using the SWO read command that shares
            # the command EP.
            with self._lock:
                self.flush()
                status, count, data = self._protocol.swo_data(count)
                return bytearray(data)

    def write_reg(self, reg_id, value, dap_index=0):
        assert reg_id in self.REG
        assert isinstance(value, int)
        assert isinstance(dap_index, int)

        request = WRITE
        if reg_id.value < 4:
            request |= DP_ACC
        else:
            request |= AP_ACC
        request |= (reg_id.value % 4) * 4
        self._write(dap_index, 1, request, [value])

    def read_reg(self, reg_id, dap_index=0, now=True):
        assert reg_id in self.REG
        assert isinstance(dap_index, int)
        assert isinstance(now, bool)

        request = READ
        if reg_id.value < 4:
            request |= DP_ACC
        else:
            request |= AP_ACC
        request |= (reg_id.value % 4) << 2
        transfer = self._write(dap_index, 1, request, None)
        assert transfer is not None

        def read_reg_cb():
            res = transfer.get_result()
            assert len(res) == 1
            res = res[0]
            return res

        if now:
            return read_reg_cb()
        else:
            return read_reg_cb

    def reg_write_repeat(self, num_repeats, reg_id, data_array, dap_index=0):
        assert isinstance(num_repeats, int)
        assert num_repeats == len(data_array)
        assert reg_id in self.REG
        assert isinstance(dap_index, int)

        request = WRITE
        if reg_id.value < 4:
            request |= DP_ACC
        else:
            request |= AP_ACC
        request |= (reg_id.value % 4) * 4
        self._write(dap_index, num_repeats, request, data_array)

    def reg_read_repeat(self, num_repeats, reg_id, dap_index=0,
                        now=True):
        assert isinstance(num_repeats, int)
        assert reg_id in self.REG
        assert isinstance(dap_index, int)
        assert isinstance(now, bool)

        request = READ
        if reg_id.value < 4:
            request |= DP_ACC
        else:
            request |= AP_ACC
        request |= (reg_id.value % 4) * 4
        transfer = self._write(dap_index, num_repeats, request, None)
        assert transfer is not None

        def reg_read_repeat_cb():
            res = transfer.get_result()
            assert len(res) == num_repeats
            return res

        if now:
            return reg_read_repeat_cb()
        else:
            return reg_read_repeat_cb
    # ------------------------------------------- #
    #          Private functions
    # ------------------------------------------- #

    def _init_deferred_buffers(self):
        """@brief Initialize or reinitialize all the deferred transfer buffers

        Calling this method will drop all pending transactions
        so use with care.
        """
        # List of transfers that have been started, but
        # not completed (started by write_reg, read_reg,
        # reg_write_repeat and reg_read_repeat)
        self._transfer_list.clear()
        # The current packet - this can contain multiple
        # different transfers
        self._crnt_cmd = _Command(self._packet_size)
        # Packets that have been sent but not read
        self._commands_to_read.clear()
        # Buffer for data returned for completed commands.
        # This data will be added to transfers
        self._command_response_buf = bytearray()

    @locked
    def _read_packet(self):
        """@brief Reads and decodes a single packet

        Reads a single packet from the device and
        stores the data from it in the current Command
        object
        """
        # Grab command, send it and decode response
        cmd = self._commands_to_read.popleft()
        TRACE.debug("[cmd:%d] _read_packet: reading", cmd.uid)
        try:
            raw_data = self._interface.read()
            raw_data = bytearray(raw_data)
            decoded_data = cmd.decode_data(raw_data)
        except Exception as exception:
            TRACE.debug("[cmd:%d] _read_packet: got exception %r; aborting all transfers!", cmd.uid, exception)
            self._abort_all_transfers(exception)
            raise

        decoded_data = bytearray(decoded_data)
        self._command_response_buf.extend(decoded_data)

        # Attach data to transfers
        pos = 0
        while True:
            size_left = len(self._command_response_buf) - pos
            if size_left == 0:
                # If size left is 0 then the transfer list might
                # be empty, so don't try to access element 0
                break
            transfer = self._transfer_list[0]
            size = transfer.get_data_size()
            if size > size_left:
                break

            self._transfer_list.popleft()
            data = self._command_response_buf[pos:pos + size]
            pos += size
            transfer.add_response(data)

        # Remove used data from _command_response_buf
        if pos > 0:
            self._command_response_buf = self._command_response_buf[pos:]

    @locked
    def _send_packet(self):
        """@brief Send a single packet to the interface

        This function guarantees that the number of packets
        that are stored in daplink's buffer (the number of
        packets written but not read) does not exceed the
        number supported by the given device.
        """
        cmd = self._crnt_cmd
        if cmd.get_empty():
            return

        max_packets = self._interface.get_packet_count()
        if len(self._commands_to_read) >= max_packets:
            TRACE.debug("[cmd:%d] _send_packet: reading packet; outstanding=%d >= max=%d",
                    cmd.uid, len(self._commands_to_read), max_packets)
            self._read_packet()
        TRACE.debug("[cmd:%d] _send_packet: sending", cmd.uid)
        data = cmd.encode_data()
        try:
            self._interface.write(list(data))
        except Exception as exception:
            self._abort_all_transfers(exception)
            raise
        self._commands_to_read.append(cmd)
        self._crnt_cmd = _Command(self._packet_size)

    @locked
    def _write(self, dap_index, transfer_count,
               transfer_request, transfer_data):
        """@brief Write one or more commands
        """
        assert dap_index == 0  # dap index currently unsupported
        assert isinstance(transfer_count, int)
        assert isinstance(transfer_request, int)
        assert transfer_data is None or len(transfer_data) > 0

        # Create transfer and add to transfer list
        transfer = None
        if transfer_request & READ:
            transfer = _Transfer(self, dap_index, transfer_count,
                                 transfer_request, transfer_data)
            self._transfer_list.append(transfer)

        # Build physical packet by adding it to command
        cmd = self._crnt_cmd
        size_to_transfer = transfer_count
        trans_data_pos = 0
        while size_to_transfer > 0:
            # Get the size remaining in the current packet for the given request.
            size = cmd.get_request_space(size_to_transfer, transfer_request, dap_index)

            # This request doesn't fit in the packet so send it.
            if size == 0:
                TRACE.debug("_write: send packet [size==0]")
                self._send_packet()
                cmd = self._crnt_cmd
                continue

            # Add request to packet.
            if transfer_data is None:
                data = None
            else:
                data = transfer_data[trans_data_pos:trans_data_pos + size]
            cmd.add(size, transfer_request, data, dap_index)
            size_to_transfer -= size
            trans_data_pos += size

            # Packet has been filled so send it
            if cmd.get_full():
                TRACE.debug("_write: send packet [full]")
                self._send_packet()
                cmd = self._crnt_cmd

        if not self._deferred_transfer:
            self.flush()

        return transfer

    @locked
    def _abort_all_transfers(self, exception):
        """@brief Abort any ongoing transfers and clear all buffers
        """
        pending_reads = len(self._commands_to_read)
        TRACE.debug("aborting %d pending reads after exception %r", pending_reads, exception)
        # invalidate _transfer_list
        for transfer in self._transfer_list:
            transfer.add_error(exception)
        # clear all deferred buffers
        self._init_deferred_buffers()
        # finish all pending reads and ignore the data
        # Only do this if the error is a transfer error.
        # Otherwise this could cause another exception
        if isinstance(exception, DAPAccessIntf.TransferError):
            for _ in range(pending_reads):
                self._interface.read()
