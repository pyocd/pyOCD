# pyOCD debugger
# Copyright (c) 2018-2020,2022 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
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

from time import sleep
from typing import (Any, Callable, Dict, List, Optional, Sequence, Union, TYPE_CHECKING)

from .debug_probe import DebugProbe
from ..core.memory_interface import MemoryInterface
from ..core.plugin import Plugin
from ..core.options import OptionInfo
from ..coresight.ap import (APVersion, APSEL, APSEL_SHIFT, APv1Address)
from .stlink.usb import STLinkUSBInterface
from .stlink.stlink import STLink
from .stlink.detect.factory import create_mbed_detector
from ..board.mbed_board import MbedBoard
from ..board.board_ids import BOARD_ID_TO_INFO
from ..utility import conversion

if TYPE_CHECKING:
    from ..board.board_ids import BoardInfo

class StlinkProbe(DebugProbe):
    """@brief Wraps an STLink as a DebugProbe."""

    _board_id: Optional[str]

    # Shared cache for the STLink Mbed board IDs read from MSD volumes.
    # The dict maps the serial number to 4-character board ID, or None if no ID is available.
    _mbed_board_id_cache: Dict[str, Optional[str]] = {}

    @classmethod
    def get_all_connected_probes(cls, unique_id: Optional[str] = None,
            is_explicit: bool = False) -> List[StlinkProbe]:
        return [cls(dev) for dev in STLinkUSBInterface.get_all_connected_devices()]

    @classmethod
    def get_probe_with_id(cls, unique_id: str, is_explicit: bool = False) -> Optional[StlinkProbe]:
        for dev in STLinkUSBInterface.get_all_connected_devices():
            if dev.serial_number == unique_id:
                return cls(dev)
        return None

    def __init__(self, device: STLinkUSBInterface) -> None:
        super().__init__()
        self._link = STLink(device)
        self._is_open = False
        self._is_connected = False
        self._nreset_state = False
        self._memory_interfaces = {}
        self._board_id = None
        self._caps = set()

    @property
    def board_id(self) -> Optional[str]:
        """@brief Lazily loaded 4-character board ID."""
        if self._board_id is None:
            self._board_id = self._get_board_id()
        return self._board_id

    def _get_board_id(self) -> Optional[str]:
        # Try to get the board ID first by sending a command, since it is much faster. This requires
        # opening the USB device, however, and requires a recent STLink firmware version.
        board_id = self._link.get_board_id()
        if board_id is None:
            # Check the cache.
            if self._link.serial_number in self._mbed_board_id_cache:
                board_id = StlinkProbe._mbed_board_id_cache[self._link.serial_number]
            else:
                # Try to detect associated board info via the STLinkV2-1 MSD volume.
                detector = create_mbed_detector()
                if detector is not None:
                    for info in detector.list_mbeds():
                        usb_id = info['target_id_usb_id']

                        # Some STLink probes provide an MSD volume, but not the mbed.htm file.
                        # We can live without the board ID, so just ignore any error.
                        try:
                            this_board_id = info['target_id_mbed_htm'][0:4]
                        except KeyError:
                            # No board ID is available for this board.
                            StlinkProbe._mbed_board_id_cache[usb_id] = None
                        else:
                            # Populate the cache with the ID.
                            StlinkProbe._mbed_board_id_cache[usb_id] = this_board_id

                            # Use this ID if it's for our board.
                            if usb_id == self._link.serial_number:
                                board_id = this_board_id
                                break
        return board_id

    @property
    def description(self) -> str:
        return self.product_name

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

    @property
    def associated_board_info(self) -> Optional[BoardInfo]:
        if (self.board_id is not None) and (self.board_id in BOARD_ID_TO_INFO):
            return BOARD_ID_TO_INFO[self.board_id]
        else:
            return None

    def create_associated_board(self):
        assert self.session is not None
        board_info = self.associated_board_info
        if board_info or self.board_id:
            return MbedBoard(self.session, board_info=board_info, board_id=self.board_id)
        else:
            return None

    def open(self):
        assert self.session is not None

        self._link.open()
        self._is_open = True

        # This call is ignored if the STLink is not V3.
        prescaler = self.session.options.get('stlink.v3_prescaler')
        if prescaler not in (1, 2, 4):
            prescaler = self.session.options.get_default('stlink.v3_prescaler')
        self._link.set_prescaler(prescaler)

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
        assert self.session
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
        assert isinstance(ap_address, APv1Address)
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
    """@brief Concrete memory interface for a single AP."""

    def __init__(self, link, apsel):
        self._link = link
        self._apsel = apsel

    def write_memory(self, addr: int, data: int, transfer_size: int=32, **attrs: Any) -> None:
        """@brief Write a single memory location.

        By default the transfer size is a word.
        """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        csw = attrs.get('csw', 0)
        if transfer_size == 32:
            self._link.write_mem32(addr, conversion.u32le_list_to_byte_list([data]), self._apsel, csw)
        elif transfer_size == 16:
            self._link.write_mem16(addr, conversion.u16le_list_to_byte_list([data]), self._apsel, csw)
        elif transfer_size == 8:
            self._link.write_mem8(addr, [data], self._apsel, csw)

    def read_memory(self, addr: int, transfer_size: int=32, now: bool=True, **attrs: Any) \
            -> Union[int, Callable[[], int]]:
        """@brief Read a memory location.

        By default, a word will be read.
        """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        csw = attrs.get('csw', 0)
        if transfer_size == 32:
            result = conversion.byte_list_to_u32le_list(self._link.read_mem32(addr, 4, self._apsel, csw))[0]
        elif transfer_size == 16:
            result = conversion.byte_list_to_u16le_list(self._link.read_mem16(addr, 2, self._apsel, csw))[0]
        elif transfer_size == 8:
            result = self._link.read_mem8(addr, 1, self._apsel, csw)[0]

        def read_callback():
            return result
        return result if now else read_callback

    def write_memory_block32(self, addr: int, data: Sequence[int], **attrs: Any) -> None:
        addr &= 0xffffffff
        csw = attrs.get('csw', 0)
        self._link.write_mem32(addr, conversion.u32le_list_to_byte_list(data), self._apsel, csw)

    def read_memory_block32(self, addr: int, size: int, **attrs: Any) -> Sequence[int]:
        addr &= 0xffffffff
        csw = attrs.get('csw', 0)
        return conversion.byte_list_to_u32le_list(self._link.read_mem32(addr, size * 4, self._apsel, csw))

    def read_memory_block8(self, addr: int, size: int, **attrs: Any) -> Sequence[int]:
        addr &= 0xffffffff
        csw = attrs.get('csw', 0)
        res = []

        # Transfers are handled in 3 phases:
        #   1. read 8-bit chunks until the first aligned address is reached,
        #   2. read 32-bit chunks from all aligned addresses,
        #   3. read 8-bit chunks from the remaining unaligned addresses.
        # If the requested size is so small that phase-1 would not even reach
        # aligned address, go straight to phase-3.

        # 1. read leading unaligned bytes
        unaligned_count = 3 & (4 - addr)
        if (size > unaligned_count > 0):
            res += self._link.read_mem8(addr, unaligned_count, self._apsel, csw)
            size -= unaligned_count
            addr += unaligned_count

        # 2. read aligned block of 32 bits
        if (size >= 4):
            aligned_size = size & ~3
            res += self._link.read_mem32(addr, aligned_size, self._apsel, csw)
            size -= aligned_size
            addr += aligned_size

        # 3. read trailing unaligned bytes
        if (size > 0):
            res += self._link.read_mem8(addr, size, self._apsel, csw)

        return res

    def write_memory_block8(self, addr: int, data: Sequence[int], **attrs: Any) -> None:
        addr &= 0xffffffff
        csw = attrs.get('csw', 0)
        size = len(data)
        idx = 0

        # write leading unaligned bytes
        unaligned_count = 3 & (4 - addr)
        if (size > unaligned_count > 0):
            self._link.write_mem8(addr, data[:unaligned_count], self._apsel, csw)
            size -= unaligned_count
            addr += unaligned_count
            idx += unaligned_count

        # write aligned block of 32 bits
        if (size >= 4):
            aligned_size = size & ~3
            self._link.write_mem32(addr, data[idx:idx + aligned_size], self._apsel, csw)
            size -= aligned_size
            addr += aligned_size
            idx += aligned_size

        # write trailing unaligned bytes
        if (size > 0):
            self._link.write_mem8(addr, data[idx:], self._apsel, csw)

class StlinkProbePlugin(Plugin):
    """@brief Plugin class for StlLinkProbe."""

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

    @property
    def options(self) -> List[OptionInfo]:
        return [
            OptionInfo('stlink.v3_prescaler', int, 1,
                    "Sets the HCLK prescaler of an STLinkV3, changing performance versus power tradeoff. "
                    "The value must be one of 1=high performance (default), 2=normal, or 4=low power.")
        ]
