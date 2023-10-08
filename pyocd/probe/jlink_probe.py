# pyOCD debugger
# Copyright (c) 2020 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
# Copyright (c) 2023 Marian Muller Rebeyrol
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

import six
import logging
from time import sleep
import pylink
from pylink.enums import JLinkInterfaces
from pylink.errors import (JLinkException, JLinkWriteException, JLinkReadException)
from typing import (TYPE_CHECKING, Optional, Tuple, Any, Sequence, Union, Callable)

from .debug_probe import DebugProbe
from ..core.memory_interface import MemoryInterface
from ..core import exceptions
from ..core.plugin import Plugin
from ..core.options import OptionInfo
from ..utility import conversion

if TYPE_CHECKING:
    from pylink.structs import JLinkHardwareStatus

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.WARNING)

## @brief Wraps a JLink as a DebugProbe.
class JLinkProbe(DebugProbe):

    # Address of DP's SELECT register.
    DP_SELECT = 0x8

    # Bitmasks for AP register address fields.
    A32 = 0x0000000c
    APBANKSEL = 0x000000f0
    APSEL = 0xff000000
    APSEL_APBANKSEL = APSEL | APBANKSEL

    @classmethod
    def _get_jlink(cls) -> Optional[pylink.JLink]:
        # TypeError is raised by pylink if the JLink DLL cannot be found.
        try:
            return pylink.JLink(
                    log=TRACE.info,
                    detailed_log=TRACE.debug,
                    error=TRACE.error,
                    warn=TRACE.warn,
                    )
        except TypeError:
            return None

    @classmethod
    def _format_serial_number(cls, serial_number):
        return "{:d}".format(serial_number)

    @classmethod
    def get_all_connected_probes(cls, unique_id=None, is_explicit=False):
        try:
            jlink = cls._get_jlink()
            if jlink is None:
                return []
            return [cls(cls._format_serial_number(info.SerialNumber)) for info in jlink.connected_emulators()]
        except JLinkException as exc:
            raise cls._convert_exception(exc) from exc

    @classmethod
    def get_probe_with_id(cls, unique_id, is_explicit=False):
        try:
            jlink = cls._get_jlink()
            if jlink is None:
                return None
            for info in jlink.connected_emulators():
                sn = cls._format_serial_number(info.SerialNumber)
                if sn == unique_id:
                    return cls(sn)
            return None
        except JLinkException as exc:
            raise cls._convert_exception(exc) from exc

    @classmethod
    def _get_probe_info(cls, serial_number, jlink):
        """@brief Look up and return a JLinkConnectInfo for the probe with matching serial number.
        @param cls The class object.
        @param serial_number String serial number. Must be the full serial number.
        @return JLinkConnectInfo object or None if there was no match.
        """
        try:
            for info in jlink.connected_emulators():
                if cls._format_serial_number(info.SerialNumber) == serial_number:
                    return info
            return None
        except JLinkException as exc:
            raise cls._convert_exception(exc) from exc

    def __init__(self, serial_number):
        """@brief Constructor.
        @param self The object.
        @param serial_number String. The J-Link's serial number.
        """
        super().__init__()
        link = self._get_jlink()
        if link is None:
            raise exceptions.ProbeError("unable to open JLink DLL")
        self._link = link

        info = self._get_probe_info(serial_number, self._link)
        if info is None:
            raise exceptions.ProbeError("could not find JLink probe with serial number '{}'".format(serial_number))

        self._serial_number = serial_number
        self._serial_number_int = int(serial_number, base=10)
        self._supported_protocols = None
        self._protocol = None
        self._default_protocol = None
        self._is_open = False
        self._product_name = six.ensure_str(info.acProduct)
        self._memory_interfaces = {}

    @property
    def description(self):
        return self.vendor_name + " " + self.product_name

    @property
    def vendor_name(self):
        return "Segger"

    @property
    def product_name(self):
        return self._product_name

    ## @brief Only valid after opening.
    @property
    def supported_wire_protocols(self):
        return self._supported_protocols

    @property
    def unique_id(self):
        return self._serial_number

    @property
    def wire_protocol(self):
        return self._protocol

    @property
    def is_open(self):
        return self._link.opened

    @property
    def capabilities(self):
        return {
                self.Capability.SWO,
                self.Capability.BANKED_DP_REGISTERS,
                self.Capability.APv2_ADDRESSES,
                self.Capability.PIN_ACCESS,
                }

    def get_accessible_pins(self, group: DebugProbe.PinGroup) -> Tuple[int, int]:
        """@brief Return masks of pins accessible via the .read_pins()/.write_pins() methods.

        @return Tuple of pin masks for (0) readable, (1) writable pins. See DebugProbe.Pin for mask
        values for those pins that have constants.
        """
        if group is DebugProbe.PinGroup.PROTOCOL_PINS:
            return (self.ProtocolPin.ALL_PINS, self.ProtocolPin.ALL_PINS)
        else:
            return (0, 0)

    def open(self):
        assert self.session

        try:
            # Configure UI usage. We must do this here rather than in the ctor because the ctor
            # doesn't have access to the session.
            if self.session.options.get('jlink.non_interactive'):
                self._link.disable_dialog_boxes()

            self._link.open(self._serial_number_int)
            self._is_open = True

            # Get available wire protocols.
            ifaces = self._link.supported_tifs()
            self._supported_protocols = [DebugProbe.Protocol.DEFAULT]
            if ifaces & (1 << JLinkInterfaces.JTAG):
                self._supported_protocols.append(DebugProbe.Protocol.JTAG)
            if ifaces & (1 << JLinkInterfaces.SWD):
                self._supported_protocols.append(DebugProbe.Protocol.SWD)
            if not len(self._supported_protocols) >= 2: # default + 1
                raise exceptions.ProbeError("J-Link probe {} does not support any known wire protocols".format(
                        self.unique_id))

            # Select default protocol, preferring SWD over JTAG.
            if DebugProbe.Protocol.SWD in self._supported_protocols:
                self._default_protocol = DebugProbe.Protocol.SWD
            else:
                self._default_protocol = DebugProbe.Protocol.JTAG
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def close(self):
        try:
            self._link.close()
            self._is_open = False
            self._memory_interfaces = {}
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        """@brief Connect to the target via JTAG or SWD."""
        assert self.session

        # Handle default protocol.
        if (protocol is None) or (protocol == DebugProbe.Protocol.DEFAULT):
            protocol = self._default_protocol

        # Validate selected protocol.
        assert self._supported_protocols is not None
        if protocol not in self._supported_protocols:
            raise ValueError("unsupported wire protocol %s" % protocol)

        # Convert protocol to port enum.
        if protocol == DebugProbe.Protocol.SWD:
            iface = JLinkInterfaces.SWD
        elif protocol == DebugProbe.Protocol.JTAG:
            iface = JLinkInterfaces.JTAG
        else:
            raise exceptions.InternalError(f"unknown wire protocol ({protocol})")

        try:
            self._link.set_tif(iface)
            if self.session.options.get('jlink.power'):
                self._link.power_on()

            # Connect if a device name was supplied.
            device_name = self.session.options.get('jlink.device')
            if device_name is not None:
                self._link.connect(device_name)

            self._link.coresight_configure()
            self._protocol = protocol
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def swj_sequence(self, length, bits):
        for chunk in range((length + 31) // 32):
            chunk_word = bits & 0xffffffff
            chunk_len = min(length, 32)

            if chunk_len == 32:
                self._link.swd_write32(chunk_len, chunk_word)
            else:
                self._link.swd_write(0, chunk_word, chunk_len)

            bits >>= 32
            length -= 32

        self._link.swd_sync()

    def disconnect(self):
        """@brief Disconnect from the target."""
        assert self.session
        try:
            if self.session.options.get('jlink.power'):
                self._link.power_off()
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

        self._protocol = None

    def set_clock(self, frequency):
        try:
            self._link.set_speed(int(frequency) // 1000)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def reset(self):
        assert self.session
        try:
            self._link.set_reset_pin_low()
            sleep(self.session.options.get('reset.hold_time'))
            self._link.set_reset_pin_high()
            sleep(self.session.options.get('reset.post_delay'))
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def assert_reset(self, asserted):
        try:
            if asserted:
                self._link.set_reset_pin_low()
            else:
                self._link.set_reset_pin_high()
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def is_reset_asserted(self):
        try:
            status = self._link.hardware_status
            return status.tres == 0
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def read_pins(self, group: DebugProbe.PinGroup, mask: int) -> int:
        """@brief Read values of selected debug probe pins.

        See DebugProbe.ProtocolPin for mask values.

        @param self
        @param group Select the pin group to read.
        @param mask Bit mask indicating which pins will be read. The return value will contain only
            bits set in this mask.
        @return Bit mask with the current value of selected pins at each pin's relevant bit position.
       """
        try:
            if group is DebugProbe.PinGroup.PROTOCOL_PINS:
                status = self._link.hardware_status
                return self.from_jlink_pins(status) & mask
            else:
                return 0
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def write_pins(self, group: DebugProbe.PinGroup, mask: int, value: int) -> None:
        """@brief Set values of selected debug probe pins.

        See DebugProbe.ProtocolPin for mask values.

        @param self
        @param group Select the pin group to read.
        @param mask Bit mask indicating which pins will be written.
        @param value Mask containing the bit value of to written for selected pins at each pin's
            relevant bit position..
        """
        assert self._link
        try:
            if group is not DebugProbe.PinGroup.PROTOCOL_PINS:
                return
            if mask & DebugProbe.ProtocolPin.SWCLK_TCK:
                if value & DebugProbe.ProtocolPin.SWCLK_TCK:
                    self._link.set_tck_pin_high()
                else:
                    self._link.set_tck_pin_low()
            if mask & DebugProbe.ProtocolPin.SWDIO_TMS:
                if value & DebugProbe.ProtocolPin.SWDIO_TMS:
                    self._link.set_tms_pin_high()
                else:
                    self._link.set_tms_pin_low()
            if mask & DebugProbe.ProtocolPin.TDI:
                if value & DebugProbe.ProtocolPin.TDI:
                    self._link.set_tdi_pin_high()
                else:
                    self._link.set_tdi_pin_low()
            if mask & DebugProbe.ProtocolPin.nRESET:
                if value & DebugProbe.ProtocolPin.nRESET:
                    self._link.set_reset_pin_high()
                else:
                    self._link.set_reset_pin_low()
            if mask & DebugProbe.ProtocolPin.nTRST:
                if value & DebugProbe.ProtocolPin.nTRST:
                    self._link.set_trst_pin_high()
                else:
                    self._link.set_trst_pin_low()
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    @staticmethod
    def from_jlink_pins(status: "JLinkHardwareStatus") -> int:
        # JLinkHardwareStatus attributes:
        # - tck: measured state of TCK pin.
        # - tdi: measured state of TDI pin.
        # - tdo: measured state of TDO pin.
        # - tms: measured state of TMS pin.
        # - tres: measured state of TRES pin.
        # - trst: measured state of TRST pin.
        result = 0
        if status.tck:
            result |= DebugProbe.ProtocolPin.SWCLK_TCK
        if status.tms:
            result |= DebugProbe.ProtocolPin.SWDIO_TMS
        if status.tdi:
            result |= DebugProbe.ProtocolPin.TDI
        if status.tdo:
            result |= DebugProbe.ProtocolPin.TDO
        if status.tres:
            result |= DebugProbe.ProtocolPin.nRESET
        if status.trst:
            result |= DebugProbe.ProtocolPin.nTRST
        return result

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #

    def read_dp(self, addr, now=True):
        try:
            value = self._link.coresight_read(addr // 4, ap=False)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc
        else:
            def read_reg_cb():
                return value

            return value if now else read_reg_cb

    def write_dp(self, addr, data):
        try:
            self._link.coresight_write(addr // 4, data, ap=False)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def read_ap(self, addr, now=True):
        assert isinstance(addr, int)
        try:
            value = self._link.coresight_read((addr & self.A32) // 4, ap=True)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc
        else:
            def read_reg_cb():
                return value

            return value if now else read_reg_cb

    def write_ap(self, addr, data):
        assert isinstance(addr, int)
        try:
            self._link.coresight_write((addr & self.A32) // 4, data, ap=True)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def read_ap_multiple(self, addr, count=1, now=True):
        results = [self.read_ap(addr, now=True) for n in range(count)]

        def read_ap_multiple_result_callback():
            return results

        return results if now else read_ap_multiple_result_callback

    def write_ap_multiple(self, addr, values):
        for v in values:
            self.write_ap(addr, v)

    def get_memory_interface_for_ap(self, ap_address):
        assert self._is_open
        # JLink memory access commands only support AP 0
        if ap_address.apsel != 0:
            return None
        # JLink memory access commands require to be conneected to the target
        if not self._link.target_connected():
            return None
        apsel = ap_address.apsel
        if apsel not in self._memory_interfaces:
            self._memory_interfaces[apsel] = JLinkMemoryInterface(self._link, apsel)
        return self._memory_interfaces[apsel]

    def swo_start(self, baudrate):
        try:
            self._link.swo_start(int(baudrate))
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def swo_stop(self):
        try:
            self._link.swo_stop()
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def swo_read(self):
        try:
            return self._link.swo_read(0, self._link.swo_num_bytes(), True)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    @staticmethod
    def _convert_exception(exc):
        if isinstance(exc, JLinkException):
            # J-Link returns this unhelpful error when it's really a transfer fault. The JLinkWriteException
            # and JLinkReadException exceptions checked below seem to only be returned for the higher level
            # read/write APIs.
            if str(exc) == "Unspecified error.":
                return exceptions.TransferFaultError(str(exc))
            else:
                return exceptions.ProbeError(str(exc))
        elif isinstance(exc, (JLinkWriteException, JLinkReadException)):
            return exceptions.TransferFaultError(str(exc))
        else:
            return exc

class JLinkMemoryInterface(MemoryInterface):
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
        if transfer_size == 32:
            self._link.memory_write32(addr, [data])
        elif transfer_size == 16:
            self._link.memory_write16(addr, [data])
        elif transfer_size == 8:
            self._link.memory_write8(addr, [data])

    def read_memory(self, addr: int, transfer_size: int=32, now: bool=True, **attrs: Any) \
            -> Union[int, Callable[[], int]]:
        """@brief Read a memory location.

        By default, a word will be read.
        """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            result = self._link.memory_read32(addr, 1)[0]
        elif transfer_size == 16:
            result = self._link.memory_read16(addr, 1)[0]
        elif transfer_size == 8:
            result = self._link.memory_read8(addr, 1)[0]

        def read_callback():
            return result
        return result if now else read_callback

    def write_memory_block32(self, addr: int, data: Sequence[int], **attrs: Any) -> None:
        addr &= 0xffffffff
        self._link.memory_write32(addr, data)

    def read_memory_block32(self, addr: int, size: int, **attrs: Any) -> Sequence[int]:
        addr &= 0xffffffff
        return self._link.memory_read32(addr, size)

    def read_memory_block8(self, addr: int, size: int, **attrs: Any) -> Sequence[int]:
        addr &= 0xffffffff
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
            res += self._link.memory_read8(addr, unaligned_count)
            size -= unaligned_count
            addr += unaligned_count

        # 2. read aligned block of 32 bits
        if (size >= 4):
            aligned_size = size & ~3
            res += conversion.u32le_list_to_byte_list(self._link.memory_read32(addr, aligned_size//4))
            size -= aligned_size
            addr += aligned_size

        # 3. read trailing unaligned bytes
        if (size > 0):
            res += self._link.memory_read8(addr, size)

        return res

    def write_memory_block8(self, addr: int, data: Sequence[int], **attrs: Any) -> None:
        addr &= 0xffffffff
        size = len(data)
        idx = 0

        # write leading unaligned bytes
        unaligned_count = 3 & (4 - addr)
        if (size > unaligned_count > 0):
            self._link.memory_write8(addr, data[:unaligned_count])
            size -= unaligned_count
            addr += unaligned_count
            idx += unaligned_count

        # write aligned block of 32 bits
        if (size >= 4):
            aligned_size = size & ~3
            self._link.memory_write32(addr, conversion.byte_list_to_u32le_list(data[idx:idx + aligned_size]))
            size -= aligned_size
            addr += aligned_size
            idx += aligned_size

        # write trailing unaligned bytes
        if (size > 0):
            self._link.memory_write8(addr, data[idx:])

class JLinkProbePlugin(Plugin):
    """@brief Plugin class for JLinkProbe."""

    def should_load(self):
        """@brief Load the J-Link plugin if the J-Link library is available."""
        return JLinkProbe._get_jlink() is not None

    def load(self):
        return JLinkProbe

    @property
    def name(self):
        return "jlink"

    @property
    def description(self):
        return "SEGGER J-Link debug probe"

    @property
    def options(self):
        """@brief Returns J-Link probe options."""
        return [
            OptionInfo('jlink.device', str, None,
                "If this option is set to a supported J-Link device name, then the J-Link will be asked connect "
                "using this name. Otherwise, the J-Link is configured for only the low-level CoreSight operations "
                "required by pyOCD. Ordinarily, it does not need to be set."),
            OptionInfo('jlink.power', bool, True,
                "Enable target power when connecting via a JLink probe, and disable power when "
                "disconnecting. Default is True."),
            OptionInfo('jlink.non_interactive', bool, True,
                "Controls whether the J-Link DLL is allowed to present UI dialog boxes and its control "
                "panel. Note that dialog boxes will actually still be visible, but the default option "
                "will be chosen automatically after 5 seconds. Default is True."),
            ]
