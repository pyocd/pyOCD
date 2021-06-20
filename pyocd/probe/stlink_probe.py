# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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

from time import sleep

from .debug_probe import DebugProbe
from ..core.memory_interface import MemoryInterface
from ..core.plugin import Plugin
from ..coresight.ap import (APVersion, APSEL, APSEL_SHIFT)
from .stlink.usb import STLinkUSBInterface
from .stlink.stlink import STLink
from .stlink.detect.factory import create_mbed_detector
from ..board.mbed_board import MbedBoard
from ..board.board_ids import BOARD_ID_TO_INFO
from ..utility import conversion

class StlinkProbe(DebugProbe):
    """! @brief Wraps an STLink as a DebugProbe."""
        
    @classmethod
    def get_all_connected_probes(cls, unique_id=None, is_explicit=False):
        return [cls(dev) for dev in STLinkUSBInterface.get_all_connected_devices()]
    
    @classmethod
    def get_probe_with_id(cls, unique_id, is_explicit=False):
        for dev in STLinkUSBInterface.get_all_connected_devices():
            if dev.serial_number == unique_id:
                return cls(dev)
        return None

    def __init__(self, device):
        super(StlinkProbe, self).__init__()
        self._link = STLink(device)
        self._is_open = False
        self._is_connected = False
        self._nreset_state = False
        self._memory_interfaces = {}
        self._mbed_info = None
        self._board_id = None
        self._caps = set()
        
        # Try to detect associated board info via the STLinkV2-1 MSD volume.
        detector = create_mbed_detector()
        for info in detector.list_mbeds():
            if info['target_id_usb_id'] == self._link.serial_number:
                self._mbed_info = info
                
                # Some STLink probes provide an MSD volume, but not the mbed.htm file.
                # We can live without the board ID, so just ignore any error.
                try:
                    self._board_id = info['target_id_mbed_htm'][0:4]
                except KeyError:
                    pass
                break
        
    @property
    def description(self):
        try:
            board_info = BOARD_ID_TO_INFO[self._board_id]
        except KeyError:
            return self.product_name
        else:
            return "{0} [{1}]".format(board_info.name, board_info.target)
    
    @property
    def vendor_name(self):
        return self._link.vendor_name
    
    @property
    def product_name(self):
        return self._link.product_name

    @property
    def supported_wire_protocols(self):
        return [DebugProbe.Protocol.DEFAULT, DebugProbe.Protocol.SWD, DebugProbe.Protocol.JTAG]

    @property
    def unique_id(self):
        return self._link.serial_number

    @property
    def wire_protocol(self):
        return DebugProbe.Protocol.SWD if self._is_connected else None
    
    @property
    def is_open(self):
        return self._is_open
    
    @property
    def capabilities(self):
        return self._caps

    def create_associated_board(self):
        assert self.session is not None
        if self._board_id is not None:
            return MbedBoard(self.session, board_id=self._board_id)
        else:
            return None
    
    def open(self):
        self._link.open()
        self._is_open = True
        
        # Update capabilities.
        self._caps = {
                self.Capability.SWO,
                self.Capability.MANAGED_AP_SELECTION,
                self.Capability.MANAGED_DPBANKSEL,
                }
        if self._link.supports_banked_dp:
            self._caps.add(self.Capability.BANKED_DP_REGISTERS)
    
    def close(self):
        self._link.close()
        self._is_open = False

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        self._link.enter_debug(STLink.Protocol.SWD)
        self._is_connected = True

    def disconnect(self):
        # TODO Close the APs. When this is attempted, we get an undocumented 0x1d error. Doesn't
        #      seem to be necessary, anyway.
        self._memory_interfaces = {}
        
        self._link.enter_idle()
        self._is_connected = False

    def set_clock(self, frequency):
        self._link.set_swd_frequency(frequency)

    def reset(self):
        self._link.drive_nreset(True)
        sleep(self.session.options.get('reset.hold_time'))
        self._link.drive_nreset(False)
        sleep(self.session.options.get('reset.post_delay'))

    def assert_reset(self, asserted):
        self._link.drive_nreset(asserted)
        self._nreset_state = asserted
    
    def is_reset_asserted(self):
        return self._nreset_state

    def flush(self):
        pass

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #
    
    def read_dp(self, addr, now=True):
        result = self._link.read_dap_register(STLink.DP_PORT, addr)
        
        def read_dp_result_callback():
            return result
        
        return result if now else read_dp_result_callback

    def write_dp(self, addr, data):
        self._link.write_dap_register(STLink.DP_PORT, addr, data)

    def read_ap(self, addr, now=True):
        apsel = (addr & APSEL) >> APSEL_SHIFT
        result = self._link.read_dap_register(apsel, addr & 0xffff)
        
        def read_ap_result_callback():
            return result
        
        return result if now else read_ap_result_callback

    def write_ap(self, addr, data):
        apsel = (addr & APSEL) >> APSEL_SHIFT
        self._link.write_dap_register(apsel, addr & 0xffff, data)

    def read_ap_multiple(self, addr, count=1, now=True):
        results = [self.read_ap(addr, now=True) for n in range(count)]
        
        def read_ap_multiple_result_callback():
            return results
        
        return results if now else read_ap_multiple_result_callback

    def write_ap_multiple(self, addr, values):
        for v in values:
            self.write_ap(addr, v)

    def get_memory_interface_for_ap(self, ap_address):
        assert self._is_connected
        # STLink memory access commands only support an 8-bit APSEL.
        if ap_address.ap_version != APVersion.APv1:
            return None
        apsel = ap_address.apsel
        if apsel not in self._memory_interfaces:
            self._link.open_ap(apsel)
            self._memory_interfaces[apsel] = STLinkMemoryInterface(self._link, apsel)
        return self._memory_interfaces[apsel]

    def swo_start(self, baudrate):
        self._link.swo_start(baudrate)

    def swo_stop(self):
        self._link.swo_stop()

    def swo_read(self):
        return self._link.swo_read()

class STLinkMemoryInterface(MemoryInterface):
    """! @brief Concrete memory interface for a single AP."""
    
    def __init__(self, link, apsel):
        self._link = link
        self._apsel = apsel

    def write_memory(self, addr, data, transfer_size=32):
        """! @brief Write a single memory location.
        
        By default the transfer size is a word.
        """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            self._link.write_mem32(addr, conversion.u32le_list_to_byte_list([data]), self._apsel)
        elif transfer_size == 16:
            self._link.write_mem16(addr, conversion.u16le_list_to_byte_list([data]), self._apsel)
        elif transfer_size == 8:
            self._link.write_mem8(addr, [data], self._apsel)
        
    def read_memory(self, addr, transfer_size=32, now=True):
        """! @brief Read a memory location.
        
        By default, a word will be read.
        """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            result = conversion.byte_list_to_u32le_list(self._link.read_mem32(addr, 4, self._apsel))[0]
        elif transfer_size == 16:
            result = conversion.byte_list_to_u16le_list(self._link.read_mem16(addr, 2, self._apsel))[0]
        elif transfer_size == 8:
            result = self._link.read_mem8(addr, 1, self._apsel)[0]
        
        def read_callback():
            return result
        return result if now else read_callback

    def write_memory_block32(self, addr, data):
        addr &= 0xffffffff
        self._link.write_mem32(addr, conversion.u32le_list_to_byte_list(data), self._apsel)

    def read_memory_block32(self, addr, size):
        addr &= 0xffffffff
        return conversion.byte_list_to_u32le_list(self._link.read_mem32(addr, size * 4, self._apsel))

class StlinkProbePlugin(Plugin):
    """! @brief Plugin class for StlLinkProbe."""
    
    def should_load(self):
        # TODO only load the plugin when libusb is available
        return True
    
    def load(self):
        return StlinkProbe
    
    @property
    def name(self):
        return "stlink"
    
    @property
    def description(self):
        return "STMicro STLinkV2 and STLinkV3 debug probe"
