# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

from . import STLinkException
from .constants import (Commands, Status, SWD_FREQ_MAP, JTAG_FREQ_MAP)
from ...core import exceptions
from ...coresight import dap
import logging
import struct
import six
from enum import Enum

log = logging.getLogger('stlink')

class STLink(object):
    """!
    @brief STLink V2 and V3 command-level interface.
    """
    class Protocol(Enum):
        """!
        @brief Protocol options to pass to STLink.enter_debug() method.
        """
        SWD = 1
        JTAG = 2
    
    ## Maximum number of bytes to send or receive for 32- and 16- bit transfers.
    #
    # 8-bit transfers have a maximum size of the maximum USB packet size (64 bytes for full speed).
    MAXIMUM_TRANSFER_SIZE = 1024
    
    ## Minimum required STLink firmware version.
    MIN_JTAG_VERSION = 24
    
    ## Firmware version that adds 16-bit transfers.
    MIN_JTAG_VERSION_16BIT_XFER = 26
    
    ## Firmware version that adds multiple AP support.
    MIN_JTAG_VERSION_MULTI_AP = 28
    
    ## Port number to use to indicate DP registers.
    DP_PORT = 0xffff

    def __init__(self, device):
        self._device = device
        self._hw_version = 0
        self._jtag_version = 0
        self._version_str = None
        self._target_voltage = 0
        self._protocol = None
    
    def open(self):
        self._device.open()
        self.get_version()
        self.get_target_voltage()

    def close(self):
        self.enter_idle()
        self._device.close()

    def get_version(self):
        # GET_VERSION response structure:
        #   Byte 0-1:
        #     [15:12] Major/HW version
        #     [11:6]  JTAG/SWD version
        #     [5:0]   SWIM or MSC version
        #   Byte 2-3: ST_VID
        #   Byte 4-5: STLINK_PID
        response = self._device.transfer([Commands.GET_VERSION], readSize=6)
        ver, = struct.unpack('>H', response[:2])
        dev_ver = self._device.version_name
        # TODO create version bitfield constants
        self._hw_version = (ver >> 12) & 0xf
        self._jtag_version = (ver >> 6) & 0x3f
        self._version_str = "%s v%dJ%d" % (dev_ver, self._hw_version, self._jtag_version)
        
        # For STLinkV3 we must use the extended get version command.
        if self._hw_version >= 3:
            # GET_VERSION_EXT response structure (byte offsets):
            #   0: HW version
            #   1: SWIM version
            #   2: JTAG/SWD version
            #   3: MSC/VCP version
            #   4: Bridge version
            #   5-7: reserved
            #   8-9: ST_VID
            #   10-11: STLINK_PID
            response = self._device.transfer([Commands.GET_VERSION_EXT], readSize=12)
            hw_vers, _, self._jtag_version = struct.unpack('<3B', response[0:3])

        # Check versions.
        if self._jtag_version == 0:
            raise STLinkException("%s firmware does not support JTAG/SWD. Please update"
                "to a firmware version that supports JTAG/SWD" % (self._version_str))
        if self._jtag_version < self.MIN_JTAG_VERSION:
            raise STLinkException("STLink %s is using an unsupported, older firmware version. "
                "Please update to the latest STLink firmware. Current version is %s, must be at least version v2J%d.)" 
                % (self.serial_number, self._version_str, self.MIN_JTAG_VERSION))

    @property
    def vendor_name(self):
        return self._device.vendor_name

    @property
    def product_name(self):
        return self._device.product_name + self._device.version_name

    @property
    def serial_number(self):
        return self._device.serial_number

    @property
    def hw_version(self):
        return self._hw_version

    @property
    def jtag_version(self):
        return self._jtag_version

    @property
    def version_str(self):
        return self._version_str

    @property
    def target_voltage(self):
        return self._target_voltage

    def get_target_voltage(self):
        response = self._device.transfer([Commands.GET_TARGET_VOLTAGE], readSize=8)
        a0, a1 = struct.unpack('<II', response[:8])
        self._target_voltage = 2 * a1 * 1.2 / a0 if a0 != 0 else None

    def enter_idle(self):
        response = self._device.transfer([Commands.GET_CURRENT_MODE], readSize=2)
        if response[0] == Commands.DEV_DFU_MODE:
            self._device.transfer([Commands.DFU_COMMAND, Commands.DFU_EXIT])
        elif response[0] == Commands.DEV_JTAG_MODE:
            self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_EXIT])
        elif response[0] == Commands.DEV_SWIM_MODE:
            self._device.transfer([Commands.SWIM_COMMAND, Commands.SWIM_EXIT])
        self._protocol = None

    def set_swd_frequency(self, freq=1800000):
        for f, d in SWD_FREQ_MAP.items():
            if freq >= f:
                response = self._device.transfer([Commands.JTAG_COMMAND, Commands.SWD_SET_FREQ, d], readSize=2)
                self._check_status(response)
                return
        raise STLinkException("Selected SWD frequency is too low")

    def set_jtag_frequency(self, freq=1120000):
        for f, d in JTAG_FREQ_MAP.items():
            if freq >= f:
                response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_SET_FREQ, d], readSize=2)
                self._check_status(response)
                return
        raise STLinkException("Selected JTAG frequency is too low")

    def enter_debug(self, protocol):
        self.enter_idle()
        
        if protocol == self.Protocol.SWD:
            protocolParam = Commands.JTAG_ENTER_SWD
        elif protocol == self.Protocol.JTAG:
            protocolParam = Commands.JTAG_ENTER_JTAG_NO_CORE_RESET
        response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_ENTER2, protocolParam, 0], readSize=2)
        self._check_status(response)
        self._protocol = protocol
    
    def open_ap(self, apsel):
        if self._jtag_version < self.MIN_JTAG_VERSION_MULTI_AP:
            return
        cmd = [Commands.JTAG_COMMAND, Commands.JTAG_INIT_AP, apsel, Commands.JTAG_AP_NO_CORE]
        response = self._device.transfer(cmd, readSize=2)
        self._check_status(response)
    
    def close_ap(self, apsel):
        if self._jtag_version < self.MIN_JTAG_VERSION_MULTI_AP:
            return
        cmd = [Commands.JTAG_COMMAND, Commands.JTAG_CLOSE_AP_DBG, apsel]
        response = self._device.transfer(cmd, readSize=2)
        self._check_status(response)

    def target_reset(self):
        response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_DRIVE_NRST, Commands.JTAG_DRIVE_NRST_PULSE], readSize=2)
        self._check_status(response)
    
    def drive_nreset(self, isAsserted):
        value = Commands.JTAG_DRIVE_NRST_LOW if isAsserted else Commands.JTAG_DRIVE_NRST_HIGH
        response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_DRIVE_NRST, value], readSize=2)
        self._check_status(response)
    
    def _check_status(self, response):
        status, = struct.unpack('<H', response)
        if status != Status.JTAG_OK:
            raise STLinkException("STLink error (%d): " % status + Status.MESSAGES.get(status, "Unknown error"))

    def _clear_sticky_error(self):
        if self._protocol == self.Protocol.SWD:
            self.write_dap_register(self.DP_PORT, dap.DP_ABORT, dap.ABORT_STKERRCLR)
        elif self._protocol == self.Protocol.JTAG:
            self.write_dap_register(self.DP_PORT, dap.DP_CTRL_STAT, dap.CTRLSTAT_STICKYERR)
    
    def _read_mem(self, addr, size, memcmd, max, apsel):
        result = []
        while size:
            thisTransferSize = min(size, max)
            
            cmd = [Commands.JTAG_COMMAND, memcmd]
            cmd.extend(six.iterbytes(struct.pack('<IHB', addr, thisTransferSize, apsel)))
            result += self._device.transfer(cmd, readSize=thisTransferSize)
            
            addr += thisTransferSize
            size -= thisTransferSize
            
            # Check status of this read.
            response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_GETLASTRWSTATUS2], readSize=12)
            status, _, faultAddr = struct.unpack('<HHI', response[0:8])
            if status in (Status.JTAG_UNKNOWN_ERROR, Status.SWD_AP_FAULT, Status.SWD_DP_FAULT):
                # Clear sticky errors.
                self._clear_sticky_error()
                
                exc = exceptions.TransferFaultError()
                exc.fault_address = faultAddr
                exc.fault_length = thisTransferSize - (faultAddr - addr)
                raise exc
            elif status != Status.JTAG_OK:
                raise STLinkException("STLink error ({}): {}".format(status, Status.MESSAGES.get(status, "Unknown error")))
        return result

    def _write_mem(self, addr, data, memcmd, max, apsel):
        while len(data):
            thisTransferSize = min(len(data), max)
            thisTransferData = data[:thisTransferSize]
            
            cmd = [Commands.JTAG_COMMAND, memcmd]
            cmd.extend(six.iterbytes(struct.pack('<IHB', addr, thisTransferSize, apsel)))
            self._device.transfer(cmd, writeData=thisTransferData)
            
            addr += thisTransferSize
            data = data[thisTransferSize:]
            
            # Check status of this write.
            response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_GETLASTRWSTATUS2], readSize=12)
            status, _, faultAddr = struct.unpack('<HHI', response[0:8])
            if status in (Status.JTAG_UNKNOWN_ERROR, Status.SWD_AP_FAULT, Status.SWD_DP_FAULT):
                # Clear sticky errors.
                self._clear_sticky_error()
                
                exc = exceptions.TransferFaultError()
                exc.fault_address = faultAddr
                exc.fault_length = thisTransferSize - (faultAddr - addr)
                raise exc
            elif status != Status.JTAG_OK:
                raise STLinkException("STLink error ({}): {}".format(status, Status.MESSAGES.get(status, "Unknown error")))

    def read_mem32(self, addr, size, apsel):
        assert (addr & 0x3) == 0 and (size & 0x3) == 0, "address and size must be word aligned"
        return self._read_mem(addr, size, Commands.JTAG_READMEM_32BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def write_mem32(self, addr, data, apsel):
        assert (addr & 0x3) == 0 and (len(data) & 3) == 0, "address and size must be word aligned"
        self._write_mem(addr, data, Commands.JTAG_WRITEMEM_32BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def read_mem16(self, addr, size, apsel):
        assert (addr & 0x1) == 0 and (size & 0x1) == 0, "address and size must be half-word aligned"

        if self._jtag_version < self.MIN_JTAG_VERSION_16BIT_XFER:
            # 16-bit r/w is only available from J26, so revert to 8-bit accesses.
            return self.read_mem8(addr, size, apsel)
        
        return self._read_mem(addr, size, Commands.JTAG_READMEM_16BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def write_mem16(self, addr, data, apsel):
        assert (addr & 0x1) == 0 and (len(data) & 1) == 0, "address and size must be half-word aligned"

        if self._jtag_version < self.MIN_JTAG_VERSION_16BIT_XFER:
            # 16-bit r/w is only available from J26, so revert to 8-bit accesses.
            self.write_mem8(addr, data, apsel)
            return
        
        self._write_mem(addr, data, Commands.JTAG_WRITEMEM_16BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def read_mem8(self, addr, size, apsel):
        return self._read_mem(addr, size, Commands.JTAG_READMEM_8BIT, self._device.max_packet_size, apsel)

    def write_mem8(self, addr, data, apsel):
        self._write_mem(addr, data, Commands.JTAG_WRITEMEM_8BIT, self._device.max_packet_size, apsel)
    
    def read_dap_register(self, port, addr):
        assert ((addr & 0xf0) == 0) or (port != self.DP_PORT), "banks are not allowed for DP registers"
        assert (addr >> 16) == 0, "register address must be 16-bit"
        
        cmd = [Commands.JTAG_COMMAND, Commands.JTAG_READ_DAP_REG]
        cmd.extend(six.iterbytes(struct.pack('<HH', port, addr)))
        response = self._device.transfer(cmd, readSize=8)
        self._check_status(response[:2])
        value, = struct.unpack('<I', response[4:8])
        return value
    
    def write_dap_register(self, port, addr, value):
        assert ((addr & 0xf0) == 0) or (port != self.DP_PORT), "banks are not allowed for DP registers"
        assert (addr >> 16) == 0, "register address must be 16-bit"
        cmd = [Commands.JTAG_COMMAND, Commands.JTAG_WRITE_DAP_REG]
        cmd.extend(six.iterbytes(struct.pack('<HHI', port, addr, value)))
        response = self._device.transfer(cmd, readSize=2)
        self._check_status(response)

