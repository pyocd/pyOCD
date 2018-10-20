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
from ...core import exceptions
import logging
import struct
import six
from enum import Enum

log = logging.getLogger('stlink')

## @brief STLink V2 and V3 command interface.
class STLink(object):
    class Protocol(Enum):
        SWD = 1
        JTAG = 2
    
    # Common commands.
    GET_VERSION = 0xf1
    JTAG_COMMAND = 0xf2
    DFU_COMMAND = 0xf3
    SWIM_COMMAND = 0xf4
    GET_CURRENT_MODE = 0xf5
    GET_TARGET_VOLTAGE = 0xf7
    GET_VERSION_EXT = 0xfb

    # Modes returned by GET_CURRENT_MODE.
    DEV_DFU_MODE = 0x00
    DEV_MASS_MODE = 0x01
    DEV_JTAG_MODE = 0x02
    DEV_SWIM_MODE = 0x03

    # Commands to exit other modes.
    DFU_EXIT = 0x07
    SWIM_EXIT = 0x01

    # JTAG commands.
    JTAG_READMEM_32BIT = 0x07
    JTAG_WRITEMEM_32BIT = 0x08
    JTAG_READMEM_8BIT = 0x0c
    JTAG_WRITEMEM_8BIT = 0x0d
    JTAG_EXIT = 0x21
    JTAG_ENTER2 = 0x30
    JTAG_GETLASTRWSTATUS2 = 0x3e # From V2J15
    JTAG_DRIVE_NRST = 0x3c
    SWV_START_TRACE_RECEPTION = 0x40
    SWV_STOP_TRACE_RECEPTION = 0x41
    SWV_GET_TRACE_NEW_RECORD_NB = 0x42
    SWD_SET_FREQ = 0x43 # From V2J20
    JTAG_SET_FREQ = 0x44 # From V2J24
    JTAG_READ_DAP_REG = 0x45 # From V2J24
    JTAG_WRITE_DAP_REG = 0x46 # From V2J24
    JTAG_READMEM_16BIT = 0x47 # From V2J26
    JTAG_WRITEMEM_16BIT = 0x48 # From V2J26
    JTAG_INIT_AP = 0x4b # From V2J28
    JTAG_CLOSE_AP_DBG = 0x4c # From V2J28
    SET_COM_FREQ = 0x61 # V3 only, replaces SWD/JTAG_SET_FREQ
    GET_COM_FREQ = 0x62 # V3 only
    
    # Parameters for JTAG_ENTER2.
    JTAG_ENTER_SWD = 0xa3
    JTAG_ENTER_JTAG_NO_CORE_RESET = 0xa3

    # Parameters for JTAG_DRIVE_NRST.
    JTAG_DRIVE_NRST_LOW = 0x00
    JTAG_DRIVE_NRST_HIGH = 0x01
    JTAG_DRIVE_NRST_PULSE = 0x02
    
    # Parameters for JTAG_INIT_AP and JTAG_CLOSE_AP_DBG.
    JTAG_AP_NO_CORE = 0x00
    JTAG_AP_CORTEXM_CORE = 0x01
    
    # Parameters for SET_COM_FREQ and GET_COM_FREQ.
    JTAG_STLINK_SWD_COM = 0x00
    JTAG_STLINK_JTAG_COM = 0x01
    
    # Status codes.
    JTAG_OK = 0x80
    JTAG_UNKNOWN_ERROR = 0x01
    JTAG_SPI_ERROR = 0x02
    JTAG_DMA_ERROR = 0x03
    JTAG_UNKNOWN_JTAG_CHAIN = 0x04
    JTAG_NO_DEVICE_CONNECTED = 0x05
    JTAG_INTERNAL_ERROR = 0x06
    JTAG_CMD_WAIT = 0x07
    JTAG_CMD_ERROR = 0x08
    JTAG_GET_IDCODE_ERROR = 0x09
    JTAG_ALIGNMENT_ERROR = 0x0a
    JTAG_DBG_POWER_ERROR = 0x0b
    JTAG_WRITE_ERROR = 0x0c
    JTAG_WRITE_VERIF_ERROR = 0x0d
    JTAG_ALREADY_OPENED_IN_OTHER_MODE = 0x0e
    SWD_AP_WAIT = 0x10
    SWD_AP_FAULT = 0x11
    SWD_AP_ERROR = 0x12
    SWD_AP_PARITY_ERROR = 0x13
    SWD_DP_WAIT = 0x14
    SWD_DP_FAULT = 0x15
    SWD_DP_ERROR = 0x16
    SWD_DP_PARITY_ERROR = 0x17
    SWD_AP_WDATA_ERROR = 0x18
    SWD_AP_STICKY_ERROR = 0x19
    SWD_AP_STICKYORUN_ERROR = 0x1a
    SWV_NOT_AVAILABLE = 0x20
    JTAG_FREQ_NOT_SUPPORTED = 0x41
    JTAG_UNKNOWN_CMD = 0x42
    
    STATUS_MESSAGES = {
        JTAG_UNKNOWN_ERROR : "Unknown error",
        JTAG_SPI_ERROR : "SPI error",
        JTAG_DMA_ERROR : "DMA error",
        JTAG_UNKNOWN_JTAG_CHAIN : "Unknown JTAG chain",
        JTAG_NO_DEVICE_CONNECTED : "No device connected",
        JTAG_INTERNAL_ERROR : "Internal error",
        JTAG_CMD_WAIT : "Command wait",
        JTAG_CMD_ERROR : "Command error",
        JTAG_GET_IDCODE_ERROR : "Get IDCODE error",
        JTAG_ALIGNMENT_ERROR : "Alignment error",
        JTAG_DBG_POWER_ERROR : "Debug power error",
        JTAG_WRITE_ERROR : "Write error",
        JTAG_WRITE_VERIF_ERROR : "Write verification error",
        JTAG_ALREADY_OPENED_IN_OTHER_MODE : "Already opened in another mode",
        SWD_AP_WAIT : "AP wait",
        SWD_AP_FAULT : "AP fault",
        SWD_AP_ERROR : "AP error",
        SWD_AP_PARITY_ERROR : "AP parity error",
        SWD_DP_WAIT : "DP wait",
        SWD_DP_FAULT : "DP fault",
        SWD_DP_ERROR : "DP error",
        SWD_DP_PARITY_ERROR : "DP parity error",
        SWD_AP_WDATA_ERROR : "AP WDATA error",
        SWD_AP_STICKY_ERROR : "AP sticky error",
        SWD_AP_STICKYORUN_ERROR : "AP sticky overrun error",
        SWV_NOT_AVAILABLE : "SWV not available",
        JTAG_FREQ_NOT_SUPPORTED : "Frequency not supported",
        JTAG_UNKNOWN_CMD : "Unknown command",
    }

    SWD_FREQ_MAP = {
        4600000 :   0,
        1800000 :   1, # Default
        1200000 :   2,
        950000 :    3,
        650000 :    5,
        480000 :    7,
        400000 :    9,
        360000 :    10,
        240000 :    15,
        150000 :    25,
        125000 :    31,
        100000 :    40,
    }
    
    JTAG_FREQ_MAP = {
        18000000 :  2,
        9000000 :   4,
        4500000 :   8,
        2250000 :   16,
        1120000 :   32, # Default
        560000 :    64,
        280000 :    128,
        140000 :    256,
    }

    MAXIMUM_TRANSFER_SIZE = 1024
    
    MIN_JTAG_VERSION = 24
    
    # Port number to use to indicate DP registers.
    DP_PORT = 0xffff

    def __init__(self, device):
        self._device = device
        self._hw_version = 0
        self._jtag_version = 0
        self._version_str = None
        self._target_voltage = 0
    
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
        response = self._device.transfer([self.GET_VERSION], readSize=6)
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
            response = self._device.transfer([self.GET_VERSION_EXT], readSize=12)
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
        response = self._device.transfer([self.GET_TARGET_VOLTAGE], readSize=8)
        a0, a1 = struct.unpack('<II', response[:8])
        self._target_voltage = 2 * a1 * 1.2 / a0 if a0 != 0 else None

    def enter_idle(self):
        response = self._device.transfer([self.GET_CURRENT_MODE], readSize=2)
        if response[0] == self.DEV_DFU_MODE:
            self._device.transfer([self.DFU_COMMAND, self.DFU_EXIT])
        elif response[0] == self.DEV_JTAG_MODE:
            self._device.transfer([self.JTAG_COMMAND, self.JTAG_EXIT])
        elif response[0] == self.DEV_SWIM_MODE:
            self._device.transfer([self.SWIM_COMMAND, self.SWIM_EXIT])

    def set_swd_frequency(self, freq=1800000):
        if self._jtag_version < 20:
            return
        for f, d in self.SWD_FREQ_MAP.items():
            if freq >= f:
                response = self._device.transfer([self.JTAG_COMMAND, self.SWD_SET_FREQ, d], readSize=2)
                self._check_status(response)
                return
        raise STLinkException("Selected SWD frequency is too low")

    def set_jtag_frequency(self, freq=1120000):
        if self._jtag_version < 24:
            return
        for f, d in self.JTAG_FREQ_MAP.items():
            if freq >= f:
                response = self._device.transfer([self.JTAG_COMMAND, self.JTAG_SET_FREQ, d], readSize=2)
                self._check_status(response)
                return
        raise STLinkException("Selected JTAG frequency is too low")

    def enter_debug(self, protocol):
        self.enter_idle()
        
        if protocol == self.Protocol.SWD:
            protocolParam = self.JTAG_ENTER_SWD
        elif protocol == self.Protocol.JTAG:
            protocolParam = self.JTAG_ENTER_JTAG_NO_CORE_RESET
        response = self._device.transfer([self.JTAG_COMMAND, self.JTAG_ENTER2, protocolParam, 0], readSize=2)
        self._check_status(response)
    
    def open_ap(self, apsel):
        if self._jtag_version < 28:
            return
        cmd = [self.JTAG_COMMAND, self.JTAG_INIT_AP, apsel, self.JTAG_AP_NO_CORE]
        response = self._device.transfer(cmd, readSize=2)
        self._check_status(response)
    
    def close_ap(self, apsel):
        if self._jtag_version < 28:
            return
        cmd = [self.JTAG_COMMAND, self.JTAG_CLOSE_AP_DBG, apsel]
        response = self._device.transfer(cmd, readSize=2)
        self._check_status(response)

    def target_reset(self):
        response = self._device.transfer([self.JTAG_COMMAND, self.JTAG_DRIVE_NRST, JTAG_DRIVE_NRST_PULSE], readSize=2)
        self._check_status(response)
    
    def drive_nreset(self, isAsserted):
        value = self.JTAG_DRIVE_NRST_LOW if isAsserted else self.JTAG_DRIVE_NRST_HIGH
        response = self._device.transfer([self.JTAG_COMMAND, self.JTAG_DRIVE_NRST, value], readSize=2)
        self._check_status(response)
    
    def _check_status(self, response):
        status, = struct.unpack('<H', response)
        if status != self.JTAG_OK:
            raise STLinkException("STLink error (%d): " % status + self.STATUS_MESSAGES.get(status, "Unknown error"))

    def _read_mem(self, addr, size, memcmd, max, apsel):
        result = []
        while size:
            thisTransferSize = min(size, max)
            
            cmd = [self.JTAG_COMMAND, memcmd]
            cmd.extend(six.iterbytes(struct.pack('<IHB', addr, thisTransferSize, apsel)))
            result += self._device.transfer(cmd, readSize=thisTransferSize)
            
            addr += thisTransferSize
            size -= thisTransferSize
            
            # Check status of this read.
            response = self._device.transfer([self.JTAG_COMMAND, self.JTAG_GETLASTRWSTATUS2], readSize=12)
            status, _, faultAddr = struct.unpack('<HHI', response[0:8])
            if status in (self.JTAG_UNKNOWN_ERROR, self.SWD_AP_FAULT, self.SWD_DP_FAULT):
                exc = exceptions.TransferFaultError()
                exc.fault_address = faultAddr
                exc.fault_length = thisTransferSize - (faultAddr - addr)
                raise exc
            elif status != self.JTAG_OK:
                raise STLinkException("STLink error: " + self.STATUS_MESSAGES.get(status, "Unknown error"))
        return result

    def _write_mem(self, addr, data, memcmd, max, apsel):
        while len(data):
            thisTransferSize = min(len(data), max)
            thisTransferData = data[:thisTransferSize]
            
            cmd = [self.JTAG_COMMAND, memcmd]
            cmd.extend(six.iterbytes(struct.pack('<IHB', addr, thisTransferSize, apsel)))
            self._device.transfer(cmd, writeData=thisTransferData)
            
            addr += thisTransferSize
            data = data[thisTransferSize:]
            
            # Check status of this write.
            response = self._device.transfer([self.JTAG_COMMAND, self.JTAG_GETLASTRWSTATUS2], readSize=12)
            status, _, faultAddr = struct.unpack('<HHI', response[0:8])
            if status in (self.JTAG_UNKNOWN_ERROR, self.SWD_AP_FAULT, self.SWD_DP_FAULT):
                exc = exceptions.TransferFaultError()
                exc.fault_address = faultAddr
                exc.fault_length = thisTransferSize - (faultAddr - addr)
                raise exc
            elif status != self.JTAG_OK:
                raise STLinkException("STLink error (%x): " % status + self.STATUS_MESSAGES.get(status, "Unknown error"))

    def read_mem32(self, addr, size, apsel):
        assert (addr & 0x3) == 0 and (size & 0x3) == 0, "address and size must be word aligned"
        return self._read_mem(addr, size, self.JTAG_READMEM_32BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def write_mem32(self, addr, data, apsel):
        assert (addr & 0x3) == 0 and (len(data) & 3) == 0, "address and size must be word aligned"
        self._write_mem(addr, data, self.JTAG_WRITEMEM_32BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def read_mem16(self, addr, size, apsel):
        assert (addr & 0x1) == 0 and (size & 0x1) == 0, "address and size must be half-word aligned"

        if self._jtag_version < 26:
            # 16-bit r/w is only available from J26, so revert to 8-bit accesses.
            return self.read_mem8(addr, size, apsel)
        
        return self._read_mem(addr, size, self.JTAG_READMEM_16BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def write_mem16(self, addr, data, apsel):
        assert (addr & 0x1) == 0 and (len(data) & 1) == 0, "address and size must be half-word aligned"

        if self._jtag_version < 26:
            # 16-bit r/w is only available from J26, so revert to 8-bit accesses.
            self.write_mem8(addr, data, apsel)
            return
        
        self._write_mem(addr, data, self.JTAG_WRITEMEM_16BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def read_mem8(self, addr, size, apsel):
        return self._read_mem(addr, size, self.JTAG_READMEM_8BIT, self._device.max_packet_size, apsel)

    def write_mem8(self, addr, data, apsel):
        self._write_mem(addr, data, self.JTAG_WRITEMEM_8BIT, self._device.max_packet_size, apsel)
    
    def read_dap_register(self, port, addr):
        assert ((addr & 0xf0) == 0) or (port != self.DP_PORT), "banks are not allowed for DP registers"
        assert (addr >> 16) == 0, "register address must be 16-bit"
        
        cmd = [self.JTAG_COMMAND, self.JTAG_READ_DAP_REG]
        cmd.extend(six.iterbytes(struct.pack('<HH', port, addr)))
        response = self._device.transfer(cmd, readSize=8)
        self._check_status(response[:2])
        value, = struct.unpack('<I', response[4:8])
        return value
    
    def write_dap_register(self, port, addr, value):
        assert ((addr & 0xf0) == 0) or (port != self.DP_PORT), "banks are not allowed for DP registers"
        assert (addr >> 16) == 0, "register address must be 16-bit"
        cmd = [self.JTAG_COMMAND, self.JTAG_WRITE_DAP_REG]
        cmd.extend(six.iterbytes(struct.pack('<HHI', port, addr, value)))
        response = self._device.transfer(cmd, readSize=2)
        self._check_status(response)

