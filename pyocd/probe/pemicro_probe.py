# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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
import .pemicro/pemicrounitacmp as pyPEMicro
from time import sleep

from .debug_probe import DebugProbe
from ..core import (exceptions, memory_interface)

LOG = logging.getLogger(__name__)



## @brief Wraps a PEMicro as a DebugProbe.
class JPEMicroProbe(DebugProbe):

    # Address of DP's SELECT register.
    DP_SELECT = 0x8

    # Bitmasks for AP register address fields.
    A32 = 0x0000000c
    APBANKSEL = 0x000000f0
    APSEL = 0xff000000
    APSEL_APBANKSEL = APSEL | APBANKSEL
    
    @classmethod
    def _get_pemicro(cls):
        # TypeError is raised by pylink if the JLink DLL cannot be found.
        try:
            return pyPEMicro.pemicroUnitAcmp()
        except ProbeError:
            return None
    
    @classmethod
    def get_all_connected_probes(cls):
        try:
            pemicro = cls._get_pemicro()
            if pemicro is None:
                return []
            return [cls(str(info["id"])) for info in pemicro.listPorts()]
        except ProbeError as exc:
            six.raise_from(cls._convert_exception(exc), exc)
    
    @classmethod
    def get_probe_with_id(cls, unique_id):
        try:
            pemicro = cls._get_pemicro()
            if pemicro is None:
                return None
            for info in pemicro.listPorts():
                if str(info["id"]) == unique_id:
                    return cls(str(info["id"]))
            else:
                return None
        except ProbeError as exc:
            six.raise_from(cls._convert_exception(exc), exc)

    def __init__(self, serial_number):
        super(JPEMicroProbe, self).__init__()
        self._pemicro = self._get_pemicro()
        if self._pemicro is None:
            raise exceptions.ProbeError("unable to open PEMicro DLL")

        self._serial_number = serial_number
        self._supported_protocols = None
        self._protocol = None
        self._default_protocol = None
        self._is_open = False
        self._dp_select = -1
        self._product_name = self._pemicro.version or "Unknown"
        
    @property
    def description(self):
        return self.vendor_name + " " + self.product_name
    
    @property
    def vendor_name(self):
        return "PEMicro"
    
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
        return self._pemicro.opened
    
    @property
    def capabilities(self):
        return {self.Capability.SWO}
    
    def open(self):
        try:
            self._pemicro.open(self._serial_number)
            self._is_open = True
        
            # Get available wire protocols.
            # ifaces = self._pemicro.supported_tifs()
            self._supported_protocols = [DebugProbe.Protocol.DEFAULT]
            # if ifaces & (1 << pylink.enums.JLinkInterfaces.JTAG):
            self._supported_protocols.append(DebugProbe.Protocol.JTAG)
            # if ifaces & (1 << pylink.enums.JLinkInterfaces.SWD):
            self._supported_protocols.append(DebugProbe.Protocol.SWD)
            assert len(self._supported_protocols) > 1
            
            # Select default protocol, preferring SWD over JTAG.
            if DebugProbe.Protocol.SWD in self._supported_protocols:
                self._default_protocol = DebugProbe.Protocol.SWD
            else:
                self._default_protocol = DebugProbe.Protocol.JTAG
        except ProbeError as exc:
            six.raise_from(self._convert_exception(exc), exc)
    
    def close(self):
        try:
            self._pemicro.close()
            self._is_open = False
        except ProbeError as exc:
            six.raise_from(self._convert_exception(exc), exc)

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
            iface = PEMicroInterfaces.SWD
        elif protocol == DebugProbe.Protocol.JTAG:
            iface = PEMicroInterfaces.JTAG
        
        try:
            if self.session.options.get('pemicro.power'):
                self._pemicro.power_on()
            
            if device_name = self.session.options.get('pemicro.device') is not None:
                if self._pemicro.set_device_name(device_name) is False:
                    LOG.warning("Set of PEMicro device name({name}) failed".format(name=device_name))

            self._pemicro.connect(iface, self.session.options.get("swv_clock"))            
            self._protocol = protocol
        except exceptions.ProbeError as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def swj_sequence(self, length, bits):
        raise NotImplementedError()
        # for chunk in range((length + 31) // 32):
        #     chunk_word = bits & 0xffffffff
        #     chunk_len = min(length, 32)
            
        #     if chunk_len == 32:
        #         self._pemicro.swd_write32(chunk_len, chunk_word)
        #     else:
        #         self._pemicro.swd_write(0, chunk_word, chunk_len)
            
        #     bits >>= 32
        #     length -= 32
            
        # self._pemicro.swd_sync()

    def disconnect(self):
        """! @brief Disconnect from the target."""
        self._protocol = None
        self._invalidate_cached_registers()

    # def set_clock(self, frequency):
    #     try:
    #         self._pemicro.set_speed(frequency // 1000)
    #     except JLinkException as exc:
    #         six.raise_from(self._convert_exception(exc), exc)

    def reset(self):
        try:
            self._invalidate_cached_registers()

            self._pemicro.set_reset_pin_low()
            sleep(self.session.options.get('reset.hold_time'))
            self._pemicro.set_reset_pin_high()
            sleep(self.session.options.get('reset.post_delay'))
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def assert_reset(self, asserted):
        try:
            self._invalidate_cached_registers()
            if asserted:
                self._pemicro.set_reset_pin_low()
            else:
                self._pemicro.set_reset_pin_high()
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)
    
    def is_reset_asserted(self):
        try:
            status = self._pemicro.hardware_status()
            return status.tres == 0
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #

    def read_dp(self, addr, now=True):
        try:
            value = self._pemicro.coresight_read(addr // 4, ap=False)
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)
        else:
            def read_reg_cb():
                return value
        
            return value if now else read_reg_cb

    def write_dp(self, addr, data):
        # Skip writing DP SELECT register if its value is not changing.
        if addr == self.DP_SELECT:
            if data == self._dp_select:
                return
            self._dp_select = data

        try:
            ack = self._pemicro.coresight_write(addr // 4, data, ap=False)
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def read_ap(self, addr, now=True):
        assert type(addr) in (six.integer_types)
        try:
            self.write_dp(self.DP_SELECT, addr & self.APSEL_APBANKSEL)
            value = self._pemicro.coresight_read((addr & self.A32) // 4, ap=True)
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)
        else:
            def read_reg_cb():
                return value
        
            return value if now else read_reg_cb

    def write_ap(self, addr, data):
        assert type(addr) in (six.integer_types)
        try:
            self.write_dp(self.DP_SELECT, addr & self.APSEL_APBANKSEL)
            ack = self._pemicro.coresight_write((addr & self.A32) // 4, data, ap=True)
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)

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
            six.raise_from(self._convert_exception(exc), exc)

    def swo_stop(self):
        try:
            self._jlink.swo_stop()
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def swo_read(self):
        try:
            return self._jlink.swo_read(0, self._jlink.swo_num_bytes(), True)
        except JLinkException as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def _invalidate_cached_registers(self):
        # Invalidate cached DP SELECT register.
        self._dp_select = -1

    @staticmethod
    def _convert_exception(exc):
        if isinstance(exc, JLinkException):
            return exceptions.ProbeError(str(exc))
        elif isinstance(exc, (JLinkWriteException, JLinkReadException)):
            return exceptions.TransferFaultError(str(exc))
        else:
            return exc
