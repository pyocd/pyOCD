# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import six
import logging
from time import sleep
import pylink
from pylink.errors import (JLinkException, JLinkWriteException, JLinkReadException)

from .debug_probe import DebugProbe
from ..core import exceptions
from ..core.plugin import Plugin
from ..core.options import OptionInfo

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
    def _get_jlink(cls):
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
        """! @brief Look up and return a JLinkConnectInfo for the probe with matching serial number.
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
        """! @brief Constructor.
        @param self The object.
        @param serial_number String. The J-Link's serial number.
        """
        super(JLinkProbe, self).__init__()
        self._link = self._get_jlink()
        if self._link is None:
            raise exceptions.ProbeError("unable to open JLink DLL")

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
                }
    
    def open(self):
        try:
            self._link.open(self._serial_number_int)
            self._is_open = True
        
            # Get available wire protocols.
            ifaces = self._link.supported_tifs()
            self._supported_protocols = [DebugProbe.Protocol.DEFAULT]
            if ifaces & (1 << pylink.enums.JLinkInterfaces.JTAG):
                self._supported_protocols.append(DebugProbe.Protocol.JTAG)
            if ifaces & (1 << pylink.enums.JLinkInterfaces.SWD):
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
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        """! @brief Connect to the target via JTAG or SWD."""
        # Handle default protocol.
        if (protocol is None) or (protocol == DebugProbe.Protocol.DEFAULT):
            protocol = self._default_protocol
        
        # Validate selected protocol.
        if protocol not in self._supported_protocols:
            raise ValueError("unsupported wire protocol %s" % protocol)
        
        # Convert protocol to port enum.
        if protocol == DebugProbe.Protocol.SWD:
            iface = pylink.enums.JLinkInterfaces.SWD
        elif protocol == DebugProbe.Protocol.JTAG:
            iface = pylink.enums.JLinkInterfaces.JTAG
        
        try:
            self._link.set_tif(iface)
            if self.session.options.get('jlink.power'):
                self._link.power_on()
            device_name = self.session.options.get('jlink.device') or "Cortex-M4"
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
        """! @brief Disconnect from the target."""
        try:
            if self.session.options.get('jlink.power'):
                self._link.power_off()
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

        self._protocol = None

    def set_clock(self, frequency):
        try:
            self._link.set_speed(frequency // 1000)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def reset(self):
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
            status = self._link.hardware_status()
            return status.tres == 0
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

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

    def swo_start(self, baudrate):
        try:
            self._jlink.swo_start(baudrate)
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def swo_stop(self):
        try:
            self._jlink.swo_stop()
        except JLinkException as exc:
            raise self._convert_exception(exc) from exc

    def swo_read(self):
        try:
            return self._jlink.swo_read(0, self._jlink.swo_num_bytes(), True)
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

class JLinkProbePlugin(Plugin):
    """! @brief Plugin class for JLinkProbe."""
    
    def should_load(self):
        """! @brief Load the J-Link plugin if the J-Link library is available."""
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
        """! @brief Returns J-Link probe options."""
        return [
            OptionInfo('jlink.device', str, None,
                "Set the device name passed to the J-Link. Normally, it doesn't matter because pyOCD "
                "has its own device support, and \"Cortex-M4\" is used."),
            OptionInfo('jlink.power', bool, True,
                "Enable target power when connecting via a JLink probe, and disable power when "
                "disconnecting. Default is True."),
            ]
