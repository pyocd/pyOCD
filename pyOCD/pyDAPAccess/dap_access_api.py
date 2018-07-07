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


from enum import Enum


class DAPAccessIntf(object):

    class PORT(Enum):
        """Physical access ports"""
        DEFAULT = 0
        SWD = 1
        JTAG = 2

    class REG(Enum):
        """Register for DAP access functions"""
        DP_0x0 = 0
        DP_0x4 = 1
        DP_0x8 = 2
        DP_0xC = 3
        AP_0x0 = 4
        AP_0x4 = 5
        AP_0x8 = 6
        AP_0xC = 7

    class ID(Enum):
        """Information ID used for call to identify"""
        VENDOR = 1
        PRODUCT = 2
        SER_NUM = 3
        FW_VER = 4
        DEVICE_VENDOR = 5
        DEVICE_NAME = 6
        CAPABILITIES = 0xf0
        SWO_BUFFER_SIZE = 0xfd
        MAX_PACKET_COUNT = 0xfe
        MAX_PACKET_SIZE = 0xff

    class Error(Exception):
        """Parent of all error DAPAccess can raise"""
        pass

    class DeviceError(Error):
        """Error communicating with device"""
        pass

    class CommandError(DeviceError):
        """The host debugger reported failure for the given command"""
        pass

    class TransferError(CommandError):
        """Error ocurred with a transfer over SWD or JTAG"""
        pass

    class TransferTimeoutError(TransferError):
        """A SWD or JTAG timeout occurred"""
        pass

    class TransferFaultError(TransferError):
        """A SWD Fault occurred"""
        def __init__(self, faultAddress=None):
            super(DAPAccessIntf.TransferFaultError, self).__init__(faultAddress)
            self._address = faultAddress

        @property
        def fault_address(self):
            return self._address

        @fault_address.setter
        def fault_address(self, addr):
            self._address = addr

        def __str__(self):
            desc = "SWD/JTAG Transfer Fault"
            if self._address is not None:
                desc += " @ 0x%08x" % self._address
            return desc

    class TransferProtocolError(TransferError):
        """A SWD protocol error occurred"""
        pass

    @staticmethod
    def get_connected_devices():
        """Return a list of DAPAccess devices"""
        raise NotImplementedError()

    @staticmethod
    def get_device(device_id):
        """Return the DAPAccess device with the give ID"""
        raise NotImplementedError()

    @staticmethod
    def set_args(arg_list):
        """Set arguments to configure behavior"""
        raise NotImplementedError()



    # ------------------------------------------- #
    #          Host control functions
    # ------------------------------------------- #
    def open(self):
        """Open device and lock it for exclusive access"""
        raise NotImplementedError()

    def close(self):
        """Close device and unlock it"""
        raise NotImplementedError()

    def get_unique_id(self):
        """Get the unique ID of this device which can be used in get_device

        This function is safe to call before open is called.
        """
        raise NotImplementedError()

    def identify(self, item):
        """Return the requested information for this device"""
        raise NotImplementedError()

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, port=None):
        """Initailize DAP IO pins for JTAG or SWD"""
        raise NotImplementedError()

    def swj_sequence(self):
        """Send seqeunce to activate JTAG or SWD on the target"""
        raise NotImplementedError()

    def disconnect(self):
        """Deinitialize the DAP I/O pins"""
        raise NotImplementedError()

    def set_clock(self, frequency):
        """Set the frequency for JTAG and SWD in Hz

        This function is safe to call before connect is called.
        """
        raise NotImplementedError()

    def get_swj_mode(self):
        """Return the current port type - SWD or JTAG"""
        raise NotImplementedError()

    def reset(self):
        """Reset the target"""
        raise NotImplementedError()

    def assert_reset(self, asserted):
        """Assert or de-assert target reset line"""
        raise NotImplementedError()

    def set_deferred_transfer(self, enable):
        """Allow reads and writes to be buffered for increased speed"""
        raise NotImplementedError()

    def flush(self):
        """Write out all unsent commands"""
        raise NotImplementedError()

    def vendor(self, index, data=None):
        """Send a vendor specific command"""
        raise NotImplementedError()

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #
    def write_reg(self, reg_id, value, dap_index=0):
        """Write a single word to a DP or AP register"""
        raise NotImplementedError()

    def read_reg(self, reg_id, dap_index=0, now=True):
        """Read a single word to a DP or AP register"""
        raise NotImplementedError()

    def reg_write_repeat(self, num_repeats, reg_id, data_array, dap_index=0):
        """Write one or more words to the same DP or AP register"""
        raise NotImplementedError()

    def reg_read_repeat(self, num_repeats, reg_id, dap_index=0, now=True):
        """Read one or more words from the same DP or AP register"""
        raise NotImplementedError()
