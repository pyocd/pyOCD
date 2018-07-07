"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""


import re
import logging
import time
import collections
import six
from .dap_settings import DAPSettings
from .dap_access_api import DAPAccessIntf
from .cmsis_dap_core import CMSIS_DAP_Protocol
from .interface import INTERFACE, usb_backend, ws_backend
from .cmsis_dap_core import (COMMAND_ID, DAP_TRANSFER_OK,
                             DAP_TRANSFER_FAULT, DAP_TRANSFER_WAIT)

# CMSIS-DAP values
AP_ACC = 1 << 0
DP_ACC = 0 << 0
READ = 1 << 1
WRITE = 0 << 1
VALUE_MATCH = 1 << 4
MATCH_MASK = 1 << 5

# Set to True to enable logging of packet filling logic.
LOG_PACKET_BUILDS = False

def _get_interfaces():
    """Get the connected USB devices"""
    if DAPSettings.use_ws:
        return INTERFACE[ws_backend].getAllConnectedInterface(DAPSettings.ws_host, DAPSettings.ws_port)
    else:
        return INTERFACE[usb_backend].getAllConnectedInterface()


def _get_unique_id(interface):
    """Get the unique id from an interface"""
    return interface.getSerialNumber()


class _Transfer(object):
    """
    A wrapper object representing a command invoked by the layer above.

    The transfer class contains a logical register read or a block
    of reads to the same register.
    """

    def __init__(self, daplink, dap_index, transfer_count,
                 transfer_request, transfer_data):
        # Writes should not need a transfer object
        # since they don't have any response data
        assert isinstance(dap_index, six.integer_types)
        assert isinstance(transfer_count, six.integer_types)
        assert isinstance(transfer_request, six.integer_types)
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
        """
        Get the size in bytes of the return value of this transfer
        """
        return self._size_bytes

    def add_response(self, data):
        """
        Add data read from the remote device to this object.

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
        """
        Attach an exception to this transfer rather than data.
        """
        assert isinstance(error, Exception)
        self._error = error

    def get_result(self):
        """
        Get the result of this transfer.
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
            # Supress warnings for this.
            # pylint: disable=raising-bad-type
            raise self._error

        assert self._result is not None
        return self._result

class _Command(object):
    """
    A wrapper object representing a command send to the layer below (ex. USB).

    This class wraps the phyiscal commands DAP_Transfer and DAP_TransferBlock
    to provide a uniform way to build the command to most efficiently transfer
    the data supplied.  Register reads and writes individually or in blocks
    are added to a command object until it is full.  Once full, this class
    decides if it is more efficient to use DAP_Transfer or DAP_TransferBlock.
    The payload to send over the layer below is constructed with
    encode_data.  The response to the command is decoded with decode_data.
    """

    def __init__(self, size):
        self._size = size
        self._read_count = 0
        self._write_count = 0
        self._block_allowed = True
        self._block_request = None
        self._data = []
        self._dap_index = None
        self._data_encoded = False
        if LOG_PACKET_BUILDS:
            self._logger = logging.getLogger(__name__)
            self._logger.debug("New _Command")

    def _get_free_words(self, blockAllowed, isRead):
        """
        Return the number of words free in the transmit packet
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
        if self._dap_index is not None and dap_index != self._dap_index:
            return 0

        # Block transfers must use the same request.
        blockAllowed = self._block_allowed
        if self._block_request is not None and request != self._block_request:
            blockAllowed = False

        # Compute the portion of the request that will fit in this packet.
        is_read = request & READ
        free = self._get_free_words(blockAllowed, is_read)
        size = min(count, free)

        # Non-block transfers only have 1 byte for request count.
        if not blockAllowed:
            max_count = self._write_count + self._read_count + size
            delta = max_count - 255
            size = min(size - delta, size)
            if LOG_PACKET_BUILDS:
                self._logger.debug("get_request_space(%d, %02x:%s)[wc=%d, rc=%d, ba=%d->%d] -> (sz=%d, free=%d, delta=%d)" %
                    (count, request, 'r' if is_read else 'w', self._write_count, self._read_count, self._block_allowed, blockAllowed, size, free, delta))
        elif LOG_PACKET_BUILDS:
            self._logger.debug("get_request_space(%d, %02x:%s)[wc=%d, rc=%d, ba=%d->%d] -> (sz=%d, free=%d)" %
                (count, request, 'r' if is_read else 'w', self._write_count, self._read_count, self._block_allowed, blockAllowed, size, free))

        # We can get a negative free count if the packet already contains more data than can be
        # sent by a DAP_Transfer command, but the new request forces DAP_Transfer. In this case,
        # just return 0 to force the DAP_Transfer_Block to be sent.
        return max(size, 0)

    def get_full(self):
        return (self._get_free_words(self._block_allowed, True) == 0) or \
            (self._get_free_words(self._block_allowed, False) == 0)

    def get_empty(self):
        """
        Return True if no transfers have been added to this packet
        """
        return len(self._data) == 0

    def add(self, count, request, data, dap_index):
        """
        Add a single or block register transfer operation to this command
        """
        assert self._data_encoded is False
        if self._dap_index is None:
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

        if LOG_PACKET_BUILDS:
            self._logger.debug("add(%d, %02x:%s) -> [wc=%d, rc=%d, ba=%d]" %
                (count, request, 'r' if (request & READ) else 'w', self._write_count, self._read_count, self._block_allowed))

    def _encode_transfer_data(self):
        """
        Encode this command into a byte array that can be sent

        The data returned by this function is a bytearray in
        the format that of a DAP_Transfer CMSIS-DAP command.
        """
        assert self.get_empty() is False
        buf = bytearray(self._size)
        transfer_count = self._read_count + self._write_count
        pos = 0
        buf[pos] = COMMAND_ID['DAP_TRANSFER']
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
        return buf

    def _decode_transfer_data(self, data):
        """
        Take a byte array and extract the data from it

        Decode the response returned by a DAP_Transfer CMSIS-DAP command
        and return it as an array of bytes.
        """
        assert self.get_empty() is False
        if data[0] != COMMAND_ID['DAP_TRANSFER']:
            raise ValueError('DAP_TRANSFER response error')

        if data[2] != DAP_TRANSFER_OK:
            if data[2] == DAP_TRANSFER_FAULT:
                raise DAPAccessIntf.TransferFaultError()
            elif data[2] == DAP_TRANSFER_WAIT:
                raise DAPAccessIntf.TransferTimeoutError()
            raise DAPAccessIntf.TransferError()

        # Check for count mismatch after checking for DAP_TRANSFER_FAULT
        # This allows TransferFaultError or TransferTimeoutError to get
        # thrown instead of TransferFaultError
        if data[1] != self._read_count + self._write_count:
            raise DAPAccessIntf.TransferError()

        return data[3:3 + 4 * self._read_count]

    def _encode_transfer_block_data(self):
        """
        Encode this command into a byte array that can be sent

        The data returned by this function is a bytearray in
        the format that of a DAP_TransferBlock CMSIS-DAP command.
        """
        assert self.get_empty() is False
        buf = bytearray(self._size)
        transfer_count = self._read_count + self._write_count
        assert not (self._read_count != 0 and self._write_count != 0)
        assert self._block_request is not None
        pos = 0
        buf[pos] = COMMAND_ID['DAP_TRANSFER_BLOCK']
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
        return buf

    def _decode_transfer_block_data(self, data):
        """
        Take a byte array and extract the data from it

        Decode the response returned by a DAP_TransferBlock CMSIS-DAP command
        and return it as an array of bytes.
        """
        assert self.get_empty() is False
        if data[0] != COMMAND_ID['DAP_TRANSFER_BLOCK']:
            raise ValueError('DAP_TRANSFER_BLOCK response error')

        if data[3] != DAP_TRANSFER_OK:
            if data[3] == DAP_TRANSFER_FAULT:
                raise DAPAccessIntf.TransferFaultError()
            elif data[3] == DAP_TRANSFER_WAIT:
                raise DAPAccessIntf.TransferTimeoutError()
            raise DAPAccessIntf.TransferError()

        # Check for count mismatch after checking for DAP_TRANSFER_FAULT
        # This allows TransferFaultError or TransferTimeoutError to get
        # thrown instead of TransferFaultError
        transfer_count = data[1] | (data[2] << 8)
        if transfer_count != self._read_count + self._write_count:
            raise DAPAccessIntf.TransferError()

        return data[4:4 + 4 * self._read_count]

    def encode_data(self):
        """
        Encode this command into a byte array that can be sent

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
        """
        Decode the response data
        """
        assert self.get_empty() is False
        assert self._data_encoded is True
        if self._block_allowed:
            data = self._decode_transfer_block_data(data)
        else:
            data = self._decode_transfer_data(data)
        return data

class DAPAccessCMSISDAP(DAPAccessIntf):
    """
    An implementation of the DAPAccessIntf layer for DAPLINK boards
    """



    # ------------------------------------------- #
    #          Static Functions
    # ------------------------------------------- #
    @staticmethod
    def get_connected_devices():
        """
        Return an array of all mbed boards connected
        """
        all_daplinks = []
        all_interfaces = _get_interfaces()
        for interface in all_interfaces:
            try:
                unique_id = _get_unique_id(interface)
                new_daplink = DAPAccessCMSISDAP(unique_id)
                all_daplinks.append(new_daplink)
            except DAPAccessIntf.TransferError:
                logger = logging.getLogger(__name__)
                logger.error('Failed to get unique id', exc_info=True)
        return all_daplinks

    @staticmethod
    def get_device(device_id):
        assert isinstance(device_id, six.string_types)
        return DAPAccessCMSISDAP(device_id)

    @staticmethod
    def set_args(arg_list):
        # Example: arg_list =['use_ws=True', 'ws_host=localhost', 'ws_port=8081']
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


    # ------------------------------------------- #
    #          CMSIS-DAP and Other Functions
    # ------------------------------------------- #
    def __init__(self, unique_id):
        assert isinstance(unique_id, six.string_types)
        super(DAPAccessCMSISDAP, self).__init__()
        self._interface = None
        self._deferred_transfer = False
        self._protocol = None  # TODO, c1728p9 remove when no longer needed
        self._packet_count = None
        self._unique_id = unique_id
        self._frequency = 1000000  # 1MHz default clock
        self._dap_port = None
        self._transfer_list = None
        self._crnt_cmd = None
        self._packet_size = None
        self._commands_to_read = None
        self._command_response_buf = None
        self._logger = logging.getLogger(__name__)
        return

    def open(self):
        if self._interface is None:
            all_interfaces = _get_interfaces()
            for interface in all_interfaces:
                try:
                    unique_id = _get_unique_id(interface)
                    if self._unique_id == unique_id:
                        # This assert could indicate that two boards
                        # had the same ID
                        assert self._interface is None
                        self._interface = interface
                except Exception:
                    self._logger.error('Failed to get unique id for open', exc_info=True)
            if self._interface is None:
                raise DAPAccessIntf.DeviceError("Unable to open device")

        self._interface.open()
        self._protocol = CMSIS_DAP_Protocol(self._interface)

        if DAPSettings.limit_packets:
            self._packet_count = 1
            self._logger.debug("Limiting packet count to %d", self._packet_count)
        else:
            self._packet_count = self._protocol.dapInfo("PACKET_COUNT")

        self._interface.setPacketCount(self._packet_count)
        self._packet_size = self._protocol.dapInfo("PACKET_SIZE")
        self._interface.setPacketSize(self._packet_size)

        self._init_deferred_buffers()

    def close(self):
        assert self._interface is not None
        self.flush()
        self._interface.close()

    def get_unique_id(self):
        return self._unique_id

    def reset(self):
        self.flush()
        self._protocol.setSWJPins(0, 'nRESET')
        time.sleep(0.1)
        self._protocol.setSWJPins(0x80, 'nRESET')
        time.sleep(0.1)

    def assert_reset(self, asserted):
        self.flush()
        if asserted:
            self._protocol.setSWJPins(0, 'nRESET')
        else:
            self._protocol.setSWJPins(0x80, 'nRESET')

    def set_clock(self, frequency):
        self.flush()
        self._protocol.setSWJClock(frequency)
        self._frequency = frequency

    def get_swj_mode(self):
        return self._dap_port

    def set_deferred_transfer(self, enable):
        """
        Allow transfers to be delayed and buffered

        By default deferred transfers are turned off.  All reads and
        writes will be completed by the time the function returns.

        When enabled packets are buffered and sent all at once, which
        increases speed.  When memory is written to, the transfer
        might take place immediately, or might take place on a future
        memory write.  This means that an invalid write could cause an
        exception to occur on a later, unrelated write.  To guarantee
        that previous writes are complete call the flush() function.

        The behaviour of read operations is determined by the modes
        READ_START, READ_NOW and READ_END.  The option READ_NOW is the
        default and will cause the read to flush all previous writes,
        and read the data immediately.  To improve performance, multiple
        reads can be made using READ_START and finished later with READ_NOW.
        This allows the reads to be buffered and sent at once.  Note - All
        READ_ENDs must be called before a call using READ_NOW can be made.
        """
        if self._deferred_transfer and not enable:
            self.flush()
        self._deferred_transfer = enable

    def flush(self):
        # Send current packet
        self._send_packet()
        # Read all backlogged
        for _ in range(len(self._commands_to_read)):
            self._read_packet()

    def identify(self, item):
        assert isinstance(item, DAPAccessIntf.ID)
        return self._protocol.dapInfo(item.value)

    def vendor(self, index, data=None):
        if data is None:
            data = []
        return self._protocol.vendor(index, data)

    # ------------------------------------------- #
    #             Target access functions
    # ------------------------------------------- #
    def connect(self, port=DAPAccessIntf.PORT.DEFAULT):
        assert isinstance(port, DAPAccessIntf.PORT)
        actual_port = self._protocol.connect(port.value)
        self._dap_port = DAPAccessIntf.PORT(actual_port)
        # set clock frequency
        self._protocol.setSWJClock(self._frequency)
        # configure transfer
        self._protocol.transferConfigure()

    def swj_sequence(self):
        if self._dap_port == DAPAccessIntf.PORT.SWD:
            # configure swd protocol
            self._protocol.swdConfigure()
            # switch from jtag to swd
            self._jtag_to_swd()
        elif self._dap_port == DAPAccessIntf.PORT.JTAG:
            # configure jtag protocol
            self._protocol.jtagConfigure(4)
            # Test logic reset, run test idle
            self._protocol.swjSequence([0x1F])
        else:
            assert False

    def disconnect(self):
        self.flush()
        self._protocol.disconnect()

    def write_reg(self, reg_id, value, dap_index=0):
        assert reg_id in self.REG
        assert isinstance(value, six.integer_types)
        assert isinstance(dap_index, six.integer_types)

        request = WRITE
        if reg_id.value < 4:
            request |= DP_ACC
        else:
            request |= AP_ACC
        request |= (reg_id.value % 4) * 4
        self._write(dap_index, 1, request, [value])

    def read_reg(self, reg_id, dap_index=0, now=True):
        assert reg_id in self.REG
        assert isinstance(dap_index, six.integer_types)
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
        assert isinstance(num_repeats, six.integer_types)
        assert num_repeats == len(data_array)
        assert reg_id in self.REG
        assert isinstance(dap_index, six.integer_types)

        request = WRITE
        if reg_id.value < 4:
            request |= DP_ACC
        else:
            request |= AP_ACC
        request |= (reg_id.value % 4) * 4
        self._write(dap_index, num_repeats, request, data_array)

    def reg_read_repeat(self, num_repeats, reg_id, dap_index=0,
                        now=True):
        assert isinstance(num_repeats, six.integer_types)
        assert reg_id in self.REG
        assert isinstance(dap_index, six.integer_types)
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
        """
        Initialize or reinitalize all the deferred transfer buffers

        Calling this method will drop all pending transactions
        so use with care.
        """
        # List of transfers that have been started, but
        # not completed (started by write_reg, read_reg,
        # reg_write_repeat and reg_read_repeat)
        self._transfer_list = collections.deque()
        # The current packet - this can contain multiple
        # different transfers
        self._crnt_cmd = _Command(self._packet_size)
        # Packets that have been sent but not read
        self._commands_to_read = collections.deque()
        # Buffer for data returned for completed commands.
        # This data will be added to transfers
        self._command_response_buf = bytearray()

    def _read_packet(self):
        """
        Reads and decodes a single packet

        Reads a single packet from the device and
        stores the data from it in the current Command
        object
        """
        # Grab command, send it and decode response
        cmd = self._commands_to_read.popleft()
        try:
            raw_data = self._interface.read()
            raw_data = bytearray(raw_data)
            decoded_data = cmd.decode_data(raw_data)
        except Exception as exception:
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

    def _send_packet(self):
        """
        Send a single packet to the interface

        This function guarentees that the number of packets
        that are stored in daplink's buffer (the number of
        packets written but not read) does not exceed the
        number supported by the given device.
        """
        cmd = self._crnt_cmd
        if cmd.get_empty():
            return

        max_packets = self._interface.getPacketCount()
        if len(self._commands_to_read) >= max_packets:
            self._read_packet()
        data = cmd.encode_data()
        try:
            self._interface.write(list(data))
        except Exception as exception:
            self._abort_all_transfers(exception)
            raise
        self._commands_to_read.append(cmd)
        self._crnt_cmd = _Command(self._packet_size)

    def _write(self, dap_index, transfer_count,
               transfer_request, transfer_data):
        """
        Write one or more commands
        """
        assert dap_index == 0  # dap index currently unsupported
        assert isinstance(transfer_count, six.integer_types)
        assert isinstance(transfer_request, six.integer_types)
        assert transfer_data is None or len(transfer_data) > 0

        # Create transfer and add to transfer list
        transfer = None
        if transfer_request & READ:
            transfer = _Transfer(self, dap_index, transfer_count,
                                 transfer_request, transfer_data)
            self._transfer_list.append(transfer)

        # Build physical packet by adding it to command
        cmd = self._crnt_cmd
        is_read = transfer_request & READ
        size_to_transfer = transfer_count
        trans_data_pos = 0
        while size_to_transfer > 0:
            # Get the size remaining in the current packet for the given request.
            size = cmd.get_request_space(size_to_transfer, transfer_request, dap_index)

            # This request doesn't fit in the packet so send it.
            if size == 0:
                if LOG_PACKET_BUILDS:
                    self._logger.debug("_write: send packet [size==0]")
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
                if LOG_PACKET_BUILDS:
                    self._logger.debug("_write: send packet [full]")
                self._send_packet()
                cmd = self._crnt_cmd

        if not self._deferred_transfer:
            self.flush()

        return transfer

    def _jtag_to_swd(self):
        """
        Send the command to switch from SWD to jtag
        """
        data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        self._protocol.swjSequence(data)

        data = [0x9e, 0xe7]
        self._protocol.swjSequence(data)

        data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        self._protocol.swjSequence(data)

        data = [0x00]
        self._protocol.swjSequence(data)

    def _abort_all_transfers(self, exception):
        """
        Abort any ongoing transfers and clear all buffers
        """
        pending_reads = len(self._commands_to_read)
        # invalidate _transfer_list
        for transfer in self._transfer_list:
            transfer.add_error(exception)
        # clear all deferred buffers
        self._init_deferred_buffers()
        # finish all pending reads and ignore the data
        # Only do this if the error is a tranfer error.
        # Otherwise this could cause another exception
        if isinstance(exception, DAPAccessIntf.TransferError):
            for _ in range(pending_reads):
                self._interface.read()
