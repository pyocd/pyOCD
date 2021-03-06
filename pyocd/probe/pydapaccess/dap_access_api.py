# pyOCD debugger
# Copyright (c) 2006-2013,2018-2019 Arm Limited
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


from enum import Enum


class DAPAccessIntf(object):

    class PORT(Enum):
        """! @brief Physical access ports"""
        DEFAULT = 0
        SWD = 1
        JTAG = 2

    class REG(Enum):
        """! @brief Register for DAP access functions"""
        DP_0x0 = 0
        DP_0x4 = 1
        DP_0x8 = 2
        DP_0xC = 3
        AP_0x0 = 4
        AP_0x4 = 5
        AP_0x8 = 6
        AP_0xC = 7

    class ID(Enum):
        """! @brief Information ID used for call to identify"""
        VENDOR = 1
        PRODUCT = 2
        SER_NUM = 3
        FW_VER = 4
        DEVICE_VENDOR = 5
        DEVICE_NAME = 6
        CAPABILITIES = 0xf0
        TEST_DOMAIN_TIMER = 0xf1
        SWO_BUFFER_SIZE = 0xfd
        MAX_PACKET_COUNT = 0xfe
        MAX_PACKET_SIZE = 0xff

    class Error(Exception):
        """! @brief Parent of all error DAPAccess can raise"""
        pass

    class DeviceError(Error):
        """! @brief Error communicating with device"""
        pass

    class CommandError(DeviceError):
        """! @brief The host debugger reported failure for the given command"""
        pass

    class TransferError(CommandError):
        """! @brief Error occurred with a transfer over SWD or JTAG"""
        pass

    class TransferTimeoutError(TransferError):
        """! @brief A SWD or JTAG timeout occurred"""
        pass

    class TransferFaultError(TransferError):
        """! @brief A SWD Fault occurred"""
        pass

    class TransferProtocolError(TransferError):
        """! @brief A SWD protocol error occurred"""
        pass

    @staticmethod
    def get_connected_devices():
        """! @brief Return a list of DAPAccess devices"""
        raise NotImplementedError()

    @staticmethod
    def get_device(device_id):
        """! @brief Return the DAPAccess device with the give ID"""
        raise NotImplementedError()

    @staticmethod
    def set_args(arg_list):
        """! @brief Set arguments to configure behavior"""
        raise NotImplementedError()

    @property
    def protocol_version(self):
        """! @brief CMSIS-DAP protocol version.
        
        The version is represented as 3-tuple with elements, in order, of major version,
        minor version, and patch version.

        Not valid (returns None) until the device is opened.
        """
        raise NotImplementedError()

    @property
    def vendor_name(self):
        raise NotImplementedError()

    @property
    def product_name(self):
        raise NotImplementedError()
    
    @property
    def vidpid(self):
        """! @brief A tuple of USB VID and PID, in that order."""
        raise NotImplementedError()

    @property
    def has_swd_sequence(self):
        """! @brief Boolean indicating whether the DAP_SWD_Sequence command is supported.
        
        This property is only valid after the probe is opened. Until then, the value will be None.
        """
        raise NotImplementedError()

    # ------------------------------------------- #
    #          Host control functions
    # ------------------------------------------- #
    def open(self):
        """! @brief Open device and lock it for exclusive access"""
        raise NotImplementedError()

    def close(self):
        """! @brief Close device and unlock it"""
        raise NotImplementedError()

    def get_unique_id(self):
        """! @brief Get the unique ID of this device which can be used in get_device

        This function is safe to call before open is called.
        """
        raise NotImplementedError()

    def identify(self, item):
        """! @brief Return the requested information for this device"""
        raise NotImplementedError()

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, port=None):
        """! @brief Initialize DAP IO pins for JTAG or SWD"""
        raise NotImplementedError()

    def configure_swd(self, turnaround=1, always_send_data_phase=False):
        """! @brief Modify SWD configuration.
        
        @param self
        @param turnaround Number of turnaround phase clocks, from 1-4.
        @param always_send_data_phase Whether the data phase should always be transmitted on writes,
            even on a FAULT response. This is required for sticky overrun support.
        """
        raise NotImplementedError()
    
    def configure_jtag(self, devices_irlen=None):
        """! @brief Modify JTAG configuration.
        
        @param self
        @param devices_irlen Sequence of IR lengths for each device, thus also specifying the
            number of devices. If not passed, this will default to a single device with IRLen=4.
        """
        raise NotImplementedError()

    def swj_sequence(self, length, bits):
        """! @brief Send sequence to activate JTAG or SWD on the target.
        
        @param self
        @param length Number of bits to transfer on TCK/TMS.
        @param bits Integer with the bit values, sent LSB first.
        """
        raise NotImplementedError()

    def swd_sequence(self, sequences):
        """! @brief Send a sequences of bits on the SWDIO signal.
        
        This method sends the DAP_SWD_Sequence CMSIS-DAP command.
        
        Each sequence in the _sequences_ parameter is a tuple with 1 or 2 members:
        - 0: int: number of TCK cycles from 1-64
        - 1: int: the SWDIO bit values to transfer. The presence of this tuple member indicates the sequence is
            an output sequence; the absence means that the specified number of TCK cycles of SWDIO data will be
            read and returned.
        
        @param self
        @param sequences A sequence of sequence description tuples as described above.
        
        @return A 2-tuple of the response status, and a sequence of bytes objects, one for each input
            sequence. The length of the bytes object is (<TCK-count> + 7) / 8. Bits are in LSB first order.
        """

    def jtag_sequence(self, cycles, tms, read_tdo, tdi):
        """! @brief Send JTAG sequence.
        
        @param self
        @param cycles Number of TCK cycles, from 1-64.
        @param tms Fixed TMS value. Either 0 or 1.
        @param read_tdo Boolean indicating whether TDO should be read.
        @param tdi Integer with the TDI bit values to be transferred each TCK cycle. The LSB is
            sent first.
        
        @return Either an integer with TDI bit values, or None, if _read_tdo_ was false.
        """
        raise NotImplementedError()

    def disconnect(self):
        """! @brief Deinitialize the DAP I/O pins"""
        raise NotImplementedError()

    def set_clock(self, frequency):
        """! @brief Set the frequency for JTAG and SWD in Hz

        This function is safe to call before connect is called.
        """
        raise NotImplementedError()

    def get_swj_mode(self):
        """! @brief Return the current port type - SWD or JTAG"""
        raise NotImplementedError()

    def reset(self):
        """! @brief Reset the target"""
        raise NotImplementedError()

    def assert_reset(self, asserted):
        """! @brief Assert or de-assert target reset line"""
        raise NotImplementedError()
    
    def is_reset_asserted(self):
        """! @brief Returns True if the target reset line is asserted or False if de-asserted"""
        raise NotImplementedError()

    def set_deferred_transfer(self, enable):
        """! @brief Allow reads and writes to be buffered for increased speed"""
        raise NotImplementedError()

    def flush(self):
        """! @brief Write out all unsent commands"""
        raise NotImplementedError()

    def vendor(self, index, data=None):
        """! @brief Send a vendor specific command"""
        raise NotImplementedError()
    
    def has_swo(self):
        """! @brief Returns bool indicating whether the link supports SWO."""
        raise NotImplementedError()

    def swo_configure(self, enabled, rate):
        """! @brief Enable or disable SWO and set the baud rate."""
        raise NotImplementedError()

    def swo_control(self, start):
        """! @brief Pass True to start recording SWO data, False to stop."""
        raise NotImplementedError()

    def get_swo_status(self):
        """! @brief Returns a 2-tuple with a status mask at index 0, and the number of buffered
        SWO data bytes at index 1."""
        raise NotImplementedError()

    def swo_read(self, count=None):
        """! @brief Read buffered SWO data from the target.
        
        The count parameter is optional. If
        provided, it is the number of bytes to read, which must be less than the packet size.
        If count is not provided, the packet size will be used instead.
        
        Returns a 3-tuple containing the status mask at index 0, the number of buffered
        SWO data bytes at index 1, and a list of the received data bytes at index 2."""
        raise NotImplementedError()

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #
    def write_reg(self, reg_id, value, dap_index=0):
        """! @brief Write a single word to a DP or AP register"""
        raise NotImplementedError()

    def read_reg(self, reg_id, dap_index=0, now=True):
        """! @brief Read a single word to a DP or AP register"""
        raise NotImplementedError()

    def reg_write_repeat(self, num_repeats, reg_id, data_array, dap_index=0):
        """! @brief Write one or more words to the same DP or AP register"""
        raise NotImplementedError()

    def reg_read_repeat(self, num_repeats, reg_id, dap_index=0, now=True):
        """! @brief Read one or more words from the same DP or AP register"""
        raise NotImplementedError()
