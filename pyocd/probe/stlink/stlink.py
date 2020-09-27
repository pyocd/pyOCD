# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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

from .constants import (Commands, Status, SWD_FREQ_MAP, JTAG_FREQ_MAP)
from ...core import exceptions
from ...coresight import dap
from ...utility import conversion
from ...utility.mask import bfx
import logging
import struct
import six
import threading
from enum import Enum

LOG = logging.getLogger(__name__)

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
    
    ## Minimum required STLink firmware version (hw version 2).
    MIN_JTAG_VERSION = 24
    
    ## Firmware version that adds 16-bit transfers (hw version 2).
    MIN_JTAG_VERSION_16BIT_XFER = 26
    
    ## Firmware version that adds multiple AP support (hw version 2).
    MIN_JTAG_VERSION_MULTI_AP = 28
    
    ## Firmware version that adds DP bank support.
    #
    # Keys are the hardware version, value is the minimum JTAG version.
    MIN_JTAG_VERSION_DPBANKSEL = {2: 32, 3: 2}
    
    ## Port number to use to indicate DP registers.
    DP_PORT = 0xffff

    ## Map to convert from STLink error response codes to exception classes.
    _ERROR_CLASSES = {
        # AP protocol errors
        Status.SWD_AP_WAIT: exceptions.TransferTimeoutError,
        Status.SWD_AP_FAULT: exceptions.TransferFaultError,
        Status.SWD_AP_ERROR: exceptions.TransferError,
        Status.SWD_AP_PARITY_ERROR: exceptions.TransferError,
        
        # DP protocol errors
        Status.SWD_DP_WAIT: exceptions.TransferTimeoutError,
        Status.SWD_DP_FAULT: exceptions.TransferFaultError,
        Status.SWD_DP_ERROR: exceptions.TransferError,
        Status.SWD_DP_PARITY_ERROR: exceptions.TransferError,
        
        # High level transaction errors
        Status.SWD_AP_WDATA_ERROR: exceptions.TransferFaultError,
        Status.SWD_AP_STICKY_ERROR: exceptions.TransferError,
        Status.SWD_AP_STICKYORUN_ERROR: exceptions.TransferError,
        }
    
    ## These errors indicate a memory fault.
    _MEM_FAULT_ERRORS = (
        Status.JTAG_UNKNOWN_ERROR, # Returned in some cases by older STLink firmware.
        Status.SWD_AP_FAULT,
        Status.SWD_DP_FAULT,
        Status.SWD_AP_WDATA_ERROR,
        Status.SWD_AP_STICKY_ERROR,
        )

    def __init__(self, device):
        self._device = device
        self._hw_version = 0
        self._jtag_version = 0
        self._version_str = None
        self._target_voltage = 0
        self._protocol = None
        self._lock = threading.RLock()
    
    def open(self):
        with self._lock:
            self._device.open()
            self.enter_idle()
            self.get_version()
            self.get_target_voltage()

    def close(self):
        with self._lock:
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
        # TODO create version bitfield constants
        self._hw_version = bfx(ver, 15, 12)
        self._jtag_version = bfx(ver, 11, 6)
        self._msc_version = bfx(ver, 5, 0)
        
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
            hw_vers, _, self._jtag_version, self._msc_version = struct.unpack('<4B', response[0:4])

        self._version_str = "V%dJ%dM%d" % (self._hw_version, self._jtag_version, self._msc_version)
        LOG.debug("STLink probe %s firmware version: %s", self.serial_number, self._version_str)

        # Check versions.
        if self._jtag_version == 0:
            raise exceptions.ProbeError("%s firmware does not support JTAG/SWD. Please update"
                "to a firmware version that supports JTAG/SWD" % (self._version_str))
        if not self._check_version(self.MIN_JTAG_VERSION):
            raise exceptions.ProbeError("STLink %s is using an unsupported, older firmware version. "
                "Please update to the latest STLink firmware. Current version is %s, must be at least version v2J%d.)" 
                % (self.serial_number, self._version_str, self.MIN_JTAG_VERSION))

    def _check_version(self, min_version):
        return (self._hw_version >= 3) or (self._jtag_version >= min_version)
    
    @property
    def vendor_name(self):
        return self._device.vendor_name

    @property
    def product_name(self):
        return self._device.product_name

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
    
    @property
    def supports_banked_dp(self):
        """! @brief Whether the firmware version supports accessing banked DP registers.
        
        This property is not valid until the connection is opened.
        """
        return self._jtag_version >= self.MIN_JTAG_VERSION_DPBANKSEL[self._hw_version]

    def get_target_voltage(self):
        response = self._device.transfer([Commands.GET_TARGET_VOLTAGE], readSize=8)
        a0, a1 = struct.unpack('<II', response[:8])
        self._target_voltage = 2 * a1 * 1.2 / a0 if a0 != 0 else None

    def enter_idle(self):
        with self._lock:
            response = self._device.transfer([Commands.GET_CURRENT_MODE], readSize=2)
            if response[0] == Commands.DEV_DFU_MODE:
                self._device.transfer([Commands.DFU_COMMAND, Commands.DFU_EXIT])
            elif response[0] == Commands.DEV_JTAG_MODE:
                self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_EXIT])
            elif response[0] == Commands.DEV_SWIM_MODE:
                self._device.transfer([Commands.SWIM_COMMAND, Commands.SWIM_EXIT])
            self._protocol = None

    def set_swd_frequency(self, freq=1800000):
        with self._lock:
            if self._hw_version >= 3:
                self.set_com_frequency(self.Protocol.JTAG, freq)
            else:
                for f, d in SWD_FREQ_MAP.items():
                    if freq >= f:
                        response = self._device.transfer([Commands.JTAG_COMMAND, Commands.SWD_SET_FREQ, d], readSize=2)
                        self._check_status(response)
                        return
                raise exceptions.ProbeError("Selected SWD frequency is too low")

    def set_jtag_frequency(self, freq=1120000):
        with self._lock:
            if self._hw_version >= 3:
                self.set_com_frequency(self.Protocol.JTAG, freq)
            else:
                for f, d in JTAG_FREQ_MAP.items():
                    if freq >= f:
                        response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_SET_FREQ, d], readSize=2)
                        self._check_status(response)
                        return
                raise exceptions.ProbeError("Selected JTAG frequency is too low")
    
    def get_com_frequencies(self, protocol):
        assert self._hw_version >= 3
        
        with self._lock:
            cmd = [Commands.JTAG_COMMAND, Commands.GET_COM_FREQ, protocol.value - 1]
            response = self._device.transfer(cmd, readSize=52)
            self._check_status(response[0:2])
        
            freqs = conversion.byte_list_to_u32le_list(response[4:52])
            currentFreq = freqs.pop(0)
            freqCount = freqs.pop(0)
            return currentFreq, freqs[:freqCount]
    
    def set_com_frequency(self, protocol, freq):
        assert self._hw_version >= 3
        
        with self._lock:
            cmd = [Commands.JTAG_COMMAND, Commands.SET_COM_FREQ, protocol.value - 1, 0]
            cmd.extend(conversion.u32le_list_to_byte_list([freq // 1000]))
            response = self._device.transfer(cmd, readSize=8)
            self._check_status(response[0:2])
        
            freqs = conversion.byte_list_to_u32le_list(response[4:8])
            return freqs[0]

    def enter_debug(self, protocol):
        with self._lock:
            self.enter_idle()
        
            if protocol == self.Protocol.SWD:
                protocolParam = Commands.JTAG_ENTER_SWD
            elif protocol == self.Protocol.JTAG:
                protocolParam = Commands.JTAG_ENTER_JTAG_NO_CORE_RESET
            response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_ENTER2, protocolParam, 0], readSize=2)
            self._check_status(response)
            self._protocol = protocol
    
    def open_ap(self, apsel):
        with self._lock:
            if not self._check_version(self.MIN_JTAG_VERSION_MULTI_AP):
                return
            cmd = [Commands.JTAG_COMMAND, Commands.JTAG_INIT_AP, apsel, Commands.JTAG_AP_NO_CORE]
            response = self._device.transfer(cmd, readSize=2)
            self._check_status(response)
    
    def close_ap(self, apsel):
        with self._lock:
            if not self._check_version(self.MIN_JTAG_VERSION_MULTI_AP):
                return
            cmd = [Commands.JTAG_COMMAND, Commands.JTAG_CLOSE_AP_DBG, apsel]
            response = self._device.transfer(cmd, readSize=2)
            self._check_status(response)

    def target_reset(self):
        with self._lock:
            response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_DRIVE_NRST, Commands.JTAG_DRIVE_NRST_PULSE], readSize=2)
            self._check_status(response)
    
    def drive_nreset(self, isAsserted):
        with self._lock:
            value = Commands.JTAG_DRIVE_NRST_LOW if isAsserted else Commands.JTAG_DRIVE_NRST_HIGH
            response = self._device.transfer([Commands.JTAG_COMMAND, Commands.JTAG_DRIVE_NRST, value], readSize=2)
            self._check_status(response)
    
    def _check_status(self, response):
        status, = struct.unpack('<H', response)
        
        if status != Status.JTAG_OK:
            error_message = Status.get_error_message(status)
            if status in self._ERROR_CLASSES:
                raise self._ERROR_CLASSES[status](error_message)
            else:
                raise exceptions.ProbeError(error_message)

    def _clear_sticky_error(self):
        with self._lock:
            if self._protocol == self.Protocol.SWD:
                self.write_dap_register(self.DP_PORT, dap.DP_ABORT,
                    dap.ABORT_ORUNERRCLR | dap.ABORT_WDERRCLR | dap.ABORT_STKERRCLR | dap.ABORT_STKCMPCLR)
            elif self._protocol == self.Protocol.JTAG:
                self.write_dap_register(self.DP_PORT, dap.DP_CTRL_STAT,
                    dap.CTRLSTAT_STICKYERR | dap.CTRLSTAT_STICKYCMP | dap.CTRLSTAT_STICKYORUN)
    
    def _read_mem(self, addr, size, memcmd, max, apsel):
        with self._lock:
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

                # Handle transfer faults specially so we can assign the address info.
                if status != Status.JTAG_OK:
                    error_message = Status.get_error_message(status)
                    if status in self._MEM_FAULT_ERRORS:
                        # Clear sticky errors.
                        self._clear_sticky_error()
                
                        exc = exceptions.TransferFaultError("read")
                        exc.fault_address = faultAddr
                        exc.fault_length = thisTransferSize - (faultAddr - addr)
                        raise exc
                    elif status in self._ERROR_CLASSES:
                        raise self._ERROR_CLASSES[status](error_message)
                    elif status != Status.JTAG_OK:
                        raise exceptions.ProbeError(error_message)
            return result

    def _write_mem(self, addr, data, memcmd, max, apsel):
        with self._lock:
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
                
                # Handle transfer faults specially so we can assign the address info.
                if status != Status.JTAG_OK:
                    error_message = Status.get_error_message(status)
                    if status in self._MEM_FAULT_ERRORS:
                        # Clear sticky errors.
                        self._clear_sticky_error()
                
                        exc = exceptions.TransferFaultError("write")
                        exc.fault_address = faultAddr
                        exc.fault_length = thisTransferSize - (faultAddr - addr)
                        raise exc
                    elif status in self._ERROR_CLASSES:
                        raise self._ERROR_CLASSES[status](error_message)
                    elif status != Status.JTAG_OK:
                        raise exceptions.ProbeError(error_message)

    def read_mem32(self, addr, size, apsel):
        assert (addr & 0x3) == 0 and (size & 0x3) == 0, "address and size must be word aligned"
        return self._read_mem(addr, size, Commands.JTAG_READMEM_32BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def write_mem32(self, addr, data, apsel):
        assert (addr & 0x3) == 0 and (len(data) & 3) == 0, "address and size must be word aligned"
        self._write_mem(addr, data, Commands.JTAG_WRITEMEM_32BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def read_mem16(self, addr, size, apsel):
        assert (addr & 0x1) == 0 and (size & 0x1) == 0, "address and size must be half-word aligned"

        if not self._check_version(self.MIN_JTAG_VERSION_16BIT_XFER):
            # 16-bit r/w is only available from J26, so revert to 8-bit accesses.
            return self.read_mem8(addr, size, apsel)
        
        return self._read_mem(addr, size, Commands.JTAG_READMEM_16BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def write_mem16(self, addr, data, apsel):
        assert (addr & 0x1) == 0 and (len(data) & 1) == 0, "address and size must be half-word aligned"

        if not self._check_version(self.MIN_JTAG_VERSION_16BIT_XFER):
            # 16-bit r/w is only available from J26, so revert to 8-bit accesses.
            self.write_mem8(addr, data, apsel)
            return
        
        self._write_mem(addr, data, Commands.JTAG_WRITEMEM_16BIT, self.MAXIMUM_TRANSFER_SIZE, apsel)

    def read_mem8(self, addr, size, apsel):
        return self._read_mem(addr, size, Commands.JTAG_READMEM_8BIT, self._device.max_packet_size, apsel)

    def write_mem8(self, addr, data, apsel):
        self._write_mem(addr, data, Commands.JTAG_WRITEMEM_8BIT, self._device.max_packet_size, apsel)
    
    def _check_dp_bank(self, port, addr):
        """! @brief Check if attempting to access a banked DP register with a firmware version that
                doesn't support that.
        """
        if ((port == self.DP_PORT) and ((addr & 0xf0) != 0) and not self.supports_banked_dp):
            raise exceptions.ProbeError("this STLinkV%d firmware version does not support accessing"
                    " banked DP registers; please upgrade to the latest STLinkV%d firmware release",
                    self._hw_version, self._hw_version)
    
    def read_dap_register(self, port, addr):
        assert (addr >> 16) == 0, "register address must be 16-bit"
        
        self._check_dp_bank(port, addr)
        
        with self._lock:
            cmd = [Commands.JTAG_COMMAND, Commands.JTAG_READ_DAP_REG]
            cmd.extend(six.iterbytes(struct.pack('<HH', port, addr)))
            response = self._device.transfer(cmd, readSize=8)
            self._check_status(response[:2])
            value, = struct.unpack('<I', response[4:8])
            return value
    
    def write_dap_register(self, port, addr, value):
        assert (addr >> 16) == 0, "register address must be 16-bit"

        self._check_dp_bank(port, addr)

        with self._lock:
            cmd = [Commands.JTAG_COMMAND, Commands.JTAG_WRITE_DAP_REG]
            cmd.extend(six.iterbytes(struct.pack('<HHI', port, addr, value)))
            response = self._device.transfer(cmd, readSize=2)
            self._check_status(response)

    def swo_start(self, baudrate):
        with self._lock:
            bufferSize = 4096
            cmd = [Commands.JTAG_COMMAND, Commands.SWV_START_TRACE_RECEPTION]
            cmd.extend(six.iterbytes(struct.pack('<HI', bufferSize, baudrate)))
            response = self._device.transfer(cmd, readSize=2)
            self._check_status(response)

    def swo_stop(self):
        with self._lock:
            cmd = [Commands.JTAG_COMMAND, Commands.SWV_STOP_TRACE_RECEPTION]
            response = self._device.transfer(cmd, readSize=2)
            self._check_status(response)
    
    def swo_read(self):
        with self._lock:
            response = None
            bytesAvailable = None
            try:
                cmd = [Commands.JTAG_COMMAND, Commands.SWV_GET_TRACE_NEW_RECORD_NB]
                response = self._device.transfer(cmd, readSize=2)
                bytesAvailable, = struct.unpack('<H', response)
                if bytesAvailable:
                    return self._device.read_swv(bytesAvailable)
                else:
                    return bytearray()
            except KeyboardInterrupt:
                # If we're interrupted after sending the SWV_GET_TRACE_NEW_RECORD_NB command,
                # we have to read the queued SWV data before any other commands can be sent.
                if response is not None:
                    if bytesAvailable is None:
                        bytesAvailable, = struct.unpack('<H', response)
                    if bytesAvailable:
                        self._device.read_swv(bytesAvailable)
