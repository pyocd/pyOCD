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

from .debug_probe import DebugProbe
from ..core import exceptions
from .pydapaccess import DAPAccess
from ..board.mbed_board import MbedBoard
from ..board.board_ids import BOARD_ID_TO_INFO
import six

## @brief Wraps a pydapaccess link as a DebugProbe.
class CMSISDAPProbe(DebugProbe):

    # Masks for CMSIS-DAP capabilities.
    SWD_CAPABILITY_MASK = 1
    JTAG_CAPABILITY_MASK = 2

    # Map from DebugProbe protocol types to/from DAPAccess port types.
    PORT_MAP = {
        DebugProbe.Protocol.DEFAULT: DAPAccess.PORT.DEFAULT,
        DebugProbe.Protocol.SWD: DAPAccess.PORT.SWD,
        DebugProbe.Protocol.JTAG: DAPAccess.PORT.JTAG,
        DAPAccess.PORT.DEFAULT: DebugProbe.Protocol.DEFAULT,
        DAPAccess.PORT.SWD: DebugProbe.Protocol.SWD,
        DAPAccess.PORT.JTAG: DebugProbe.Protocol.JTAG,
        }
    
    # APnDP constants.
    DP = 0
    AP = 1
    
    # Bitmasks for AP register address fields.
    A32 = 0x0000000c
    APBANKSEL = 0x000000f0
    APSEL = 0xff000000
    APSEL_APBANKSEL = APSEL | APBANKSEL
    
    # Address of DP's SELECT register.
    DP_SELECT = 0x8
    
    # Map from AP/DP and 2-bit register address to the enums used by pydapaccess.
    REG_ADDR_TO_ID_MAP = {
        # APnDP A32
        ( 0,    0x0 ) : DAPAccess.REG.DP_0x0,
        ( 0,    0x4 ) : DAPAccess.REG.DP_0x4,
        ( 0,    0x8 ) : DAPAccess.REG.DP_0x8,
        ( 0,    0xC ) : DAPAccess.REG.DP_0xC,
        ( 1,    0x0 ) : DAPAccess.REG.AP_0x0,
        ( 1,    0x4 ) : DAPAccess.REG.AP_0x4,
        ( 1,    0x8 ) : DAPAccess.REG.AP_0x8,
        ( 1,    0xC ) : DAPAccess.REG.AP_0xC,
        }
    
    @classmethod
    def get_all_connected_probes(cls):
        try:
            return [cls(dev) for dev in DAPAccess.get_connected_devices()]
        except DAPAccess.Error as exc:
            six.raise_from(cls._convert_exception(exc), exc)
    
    @classmethod
    def get_probe_with_id(cls, unique_id):
        try:
            return cls(DAPAccess(unique_id))
        except DAPAccess.Error as exc:
            six.raise_from(cls._convert_exception(exc), exc)

    def __init__(self, device):
        self._link = device
        self._supported_protocols = None
        self._protocol = None
        self._is_open = False
        self._dp_select = -1
        
    @property
    def description(self):
        try:
            board_id = self.unique_id[0:4]
            board_info = BOARD_ID_TO_INFO[board_id]
        except KeyError:
            return self.vendor_name + " " + self.product_name
        else:
            return "{0} [{1}]".format(board_info.name, board_info.target)
    
    @property
    def vendor_name(self):
        return self._link.vendor_name
    
    @property
    def product_name(self):
        return self._link.product_name

    ## @brief Only valid after opening.
    @property
    def supported_wire_protocols(self):
        return self._supported_protocols

    @property
    def unique_id(self):
        return self._link.get_unique_id()

    @property
    def wire_protocol(self):
        return self._protocol
    
    @property
    def is_open(self):
        return self._is_open

    def create_associated_board(self, session):
        return MbedBoard(session)
    
    def open(self):
        try:
            self._link.open()
            self._is_open = True
            self._link.set_deferred_transfer(True)
        
            # Read CMSIS-DAP capabilities
            self._capabilities = self._link.identify(DAPAccess.ID.CAPABILITIES)
            self._supported_protocols = [DebugProbe.Protocol.DEFAULT]
            if self._capabilities & self.SWD_CAPABILITY_MASK:
                self._supported_protocols.append(DebugProbe.Protocol.SWD)
            if self._capabilities & self.JTAG_CAPABILITY_MASK:
                self._supported_protocols.append(DebugProbe.Protocol.JTAG)
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)
    
    def close(self):
        try:
            self._link.close()
            self._is_open = False
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        """Initialize DAP IO pins for JTAG or SWD"""
        # Convert protocol to port enum.
        if protocol is not None:
            port = self.PORT_MAP[protocol]
        else:
            port = DAPAccess.PORT.DEFAULT
        
        try:
            self._link.connect(port)
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)
        
        # Read the current mode and save it.
        actualMode = self._link.get_swj_mode()
        self._protocol = self.PORT_MAP[actualMode]
        
        self._invalidate_cached_registers()

    # TODO remove
    def swj_sequence(self):
        """Send sequence to activate JTAG or SWD on the target"""
        try:
            self._link.swj_sequence()
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def disconnect(self):
        """Deinitialize the DAP I/O pins"""
        try:
            self._link.disconnect()
            self._protocol = None
            self._invalidate_cached_registers()
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def set_clock(self, frequency):
        """Set the frequency for JTAG and SWD in Hz

        This function is safe to call before connect is called.
        """
        try:
            self._link.set_clock(frequency)
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def reset(self):
        """Reset the target"""
        try:
            self._invalidate_cached_registers()
            self._link.reset()
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def assert_reset(self, asserted):
        """Assert or de-assert target reset line"""
        try:
            self._invalidate_cached_registers()
            self._link.assert_reset(asserted)
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)
    
    def is_reset_asserted(self):
        """Returns True if the target reset line is asserted or False if de-asserted"""
        try:
            return self._link.is_reset_asserted()
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    def flush(self):
        """Write out all unsent commands"""
        try:
            self._link.flush()
        except DAPAccess.Error as exc:
            six.raise_from(self._convert_exception(exc), exc)

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #

    ## @brief Read a DP register.
    #
    # @param self
    # @param addr Integer register address being one of (0x0, 0x4, 0x8, 0xC).
    # @param now
    #
    # @todo Handle auto DPBANKSEL.
    def read_dp(self, addr, now=True):
        reg_id = self.REG_ADDR_TO_ID_MAP[self.DP, addr]
        
        try:
            result = self._link.read_reg(reg_id, now=now)
        except DAPAccess.Error as error:
            self._invalidate_cached_registers()
            six.raise_from(self._convert_exception(error), error)

        # Read callback returned for async reads.
        def read_dp_result_callback():
            try:
                return result()
            except DAPAccess.Error as error:
                self._invalidate_cached_registers()
                six.raise_from(self._convert_exception(error), error)

        return result if now else read_dp_result_callback

    def write_dp(self, addr, data):
        reg_id = self.REG_ADDR_TO_ID_MAP[self.DP, addr]
        
        # Skip writing DP SELECT register if its value is not changing.
        if addr == self.DP_SELECT:
            if data == self._dp_select:
                return
            self._dp_select = data

        # Write the DP register.
        try:
            self._link.write_reg(reg_id, data)
        except DAPAccess.Error as error:
            self._invalidate_cached_registers()
            six.raise_from(self._convert_exception(error), error)

        return True

    def read_ap(self, addr, now=True):
        assert type(addr) in (six.integer_types)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            self.write_dp(self.DP_SELECT, addr & self.APSEL_APBANKSEL)
            result = self._link.read_reg(ap_reg, now=now)
        except DAPAccess.Error as error:
            self._invalidate_cached_registers()
            six.raise_from(self._convert_exception(error), error)

        # Read callback returned for async reads.
        def read_ap_result_callback():
            try:
                return result()
            except DAPAccess.Error as error:
                self._invalidate_cached_registers()
                six.raise_from(self._convert_exception(error), error)

        return result if now else read_ap_result_callback

    def write_ap(self, addr, data):
        assert type(addr) in (six.integer_types)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        # Select the AP and bank.
        self.write_dp(self.DP_SELECT, addr & self.APSEL_APBANKSEL)

        # Perform the AP register write.
        try:
            self._link.write_reg(ap_reg, data)
        except DAPAccess.Error as error:
            self._invalidate_cached_registers()
            six.raise_from(self._convert_exception(error), error)

        return True

    def read_ap_multiple(self, addr, count=1, now=True):
        assert type(addr) in (six.integer_types)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]
        
        try:
            # Select the AP and bank.
            self.write_dp(self.DP_SELECT, addr & self.APSEL_APBANKSEL)
            
            result = self._link.reg_read_repeat(count, ap_reg, dap_index=0, now=now)
        except DAPAccess.Error as exc:
            self._invalidate_cached_registers()
            six.raise_from(self._convert_exception(exc), exc)

        # Need to wrap the deferred callback to convert exceptions.
        def read_ap_repeat_callback():
            try:
                return result()
            except DAPAccess.Error as exc:
                self._invalidate_cached_registers()
                six.raise_from(self._convert_exception(exc), exc)

        return result if now else read_ap_repeat_callback

    def write_ap_multiple(self, addr, values):
        assert type(addr) in (six.integer_types)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]
        
        try:
            # Select the AP and bank.
            self.write_dp(self.DP_SELECT, addr & self.APSEL_APBANKSEL)
            
            return self._link.reg_write_repeat(len(values), ap_reg, values, dap_index=0)
        except DAPAccess.Error as exc:
            self._invalidate_cached_registers()
            six.raise_from(self._convert_exception(exc), exc)

    def _invalidate_cached_registers(self):
        # Invalidate cached DP SELECT register.
        self._dp_select = -1

    @staticmethod
    def _convert_exception(exc):
        if isinstance(exc, DAPAccess.TransferFaultError):
            return exceptions.TransferFaultError()
        elif isinstance(exc, DAPAccess.TransferTimeoutError):
            return exceptions.TransferTimeoutError()
        elif isinstance(exc, DAPAccess.TransferError):
            return exceptions.TransferError()
        elif isinstance(exc, (DAPAccess.DeviceError, DAPAccess.CommandError)):
            return exceptions.ProbeError(str(exc))
        elif isinstance(exc, DAPAccess.Error):
            return exceptions.PyOCDError(str(exc))
        else:
            return exc

