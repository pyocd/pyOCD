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
import logging

from .debug_probe import DebugProbe
from ..core import exceptions
from ..core.plugin import Plugin
from .pydapaccess import DAPAccess
from ..board.mbed_board import MbedBoard
from ..board.board_ids import BOARD_ID_TO_INFO

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class CMSISDAPProbe(DebugProbe):
    """! @brief Wraps a pydapaccess link as a DebugProbe.
    
    Supports CMSIS-DAP v1 and v2.
    """

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
    
    ## USB VID and PID pair for DAPLink firmware.
    DAPLINK_VIDPID = (0x0d28, 0x0204)
    
    @classmethod
    def get_all_connected_probes(cls, unique_id=None, is_explicit=False):
        try:
            return [cls(dev) for dev in DAPAccess.get_connected_devices()]
        except DAPAccess.Error as exc:
            raise cls._convert_exception(exc) from exc
    
    @classmethod
    def get_probe_with_id(cls, unique_id, is_explicit=False):
        try:
            dap_access = DAPAccess.get_device(unique_id)
            if dap_access is not None:
                return cls(dap_access)
            else:
                return None
        except DAPAccess.Error as exc:
            raise cls._convert_exception(exc) from exc

    def __init__(self, device):
        super(CMSISDAPProbe, self).__init__()
        self._link = device
        self._supported_protocols = None
        self._protocol = None
        self._is_open = False
        self._caps = set()
    
    @property
    def board_id(self):
        """! @brief Unique identifier for the board.
        
        Only board IDs for DAPLink firmware are supported. We can't assume other
        CMSIS-DAP firmware is using the same serial number format, so we cannot reliably
        extract the board ID.
        
        @return Either a 4-character board ID string, or None if the probe doesn't have a board ID.
        """
        if self._link.vidpid == self.DAPLINK_VIDPID:
            return self.unique_id[0:4]
        else:
            return None

    @property
    def description(self):
        try:
            # self.board_id may be None.
            board_info = BOARD_ID_TO_INFO[self.board_id]
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

    @property
    def supported_wire_protocols(self):
        """! @brief Only valid after opening."""
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
    
    @property
    def capabilities(self):
        return self._caps

    def create_associated_board(self):
        assert self.session is not None
        
        # Only support associated Mbed boards for DAPLink firmware. We can't assume other
        # CMSIS-DAP firmware is using the same serial number format, so we cannot reliably
        # extract the board ID.
        if self.board_id is not None:
            return MbedBoard(self.session, board_id=self.board_id)
        else:
            return None
    
    def open(self):
        try:
            TRACE.debug("trace: open")
            
            self._link.open()
            self._is_open = True
            self._link.set_deferred_transfer(self.session.options.get('cmsis_dap.deferred_transfers'))
        
            # Read CMSIS-DAP capabilities
            self._capabilities = self._link.identify(DAPAccess.ID.CAPABILITIES)
            self._supported_protocols = [DebugProbe.Protocol.DEFAULT]
            if self._capabilities & self.SWD_CAPABILITY_MASK:
                self._supported_protocols.append(DebugProbe.Protocol.SWD)
            if self._capabilities & self.JTAG_CAPABILITY_MASK:
                self._supported_protocols.append(DebugProbe.Protocol.JTAG)
            
            self._caps = {
                self.Capability.SWJ_SEQUENCE,
                self.Capability.BANKED_DP_REGISTERS,
                self.Capability.APv2_ADDRESSES,
                self.Capability.JTAG_SEQUENCE,
                }
            if self._link.has_swd_sequence:
                self._caps.add(self.Capability.SWD_SEQUENCE)
            if self._link.has_swo():
                self._caps.add(self.Capability.SWO)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc
    
    def close(self):
        try:
            TRACE.debug("trace: close")
            
            self._link.close()
            self._is_open = False
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        TRACE.debug("trace: connect(%s)", protocol.name if (protocol is not None) else "None")
        
        # Convert protocol to port enum.
        if protocol is not None:
            port = self.PORT_MAP[protocol]
        else:
            port = DAPAccess.PORT.DEFAULT
        
        try:
            self._link.connect(port)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc
        
        # Read the current mode and save it.
        actualMode = self._link.get_swj_mode()
        self._protocol = self.PORT_MAP[actualMode]

    def swj_sequence(self, length, bits):
        TRACE.debug("trace: swj_sequence(length=%i, bits=%x)", length, bits)
        
        try:
            self._link.swj_sequence(length, bits)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def swd_sequence(self, sequences):
        TRACE.debug("trace: swd_sequence(sequences=%r)", sequences)
        
        try:
            self._link.swd_sequence(sequences)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def jtag_sequence(self, cycles, tms, read_tdo, tdi):
        TRACE.debug("trace: jtag_sequence(cycles=%i, tms=%x, read_tdo=%s, tdi=%x)", cycles, tms, read_tdo, tdi)
        
        try:
            self._link.jtag_sequence(cycles, tms, read_tdo, tdi)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def disconnect(self):
        TRACE.debug("trace: disconnect")
        
        try:
            self._link.disconnect()
            self._protocol = None
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def set_clock(self, frequency):
        TRACE.debug("trace: set_clock(freq=%i)", frequency)
        
        try:
            self._link.set_clock(frequency)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def reset(self):
        TRACE.debug("trace: reset")
        
        try:
            self._link.assert_reset(True)
            sleep(self.session.options.get('reset.hold_time'))
            self._link.assert_reset(False)
            sleep(self.session.options.get('reset.post_delay'))
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def assert_reset(self, asserted):
        TRACE.debug("trace: assert_reset(%s)", asserted)
        
        try:
            self._link.assert_reset(asserted)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc
    
    def is_reset_asserted(self):
        try:
            result = self._link.is_reset_asserted()
            TRACE.debug("trace: is_reset_asserted -> %s", result)
            return result
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def flush(self):
        TRACE.debug("trace: flush")
        
        try:
            self._link.flush()
        except DAPAccess.Error as exc:
            TRACE.debug("trace: error from flush: %r", exc)
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #

    def read_dp(self, addr, now=True):
        reg_id = self.REG_ADDR_TO_ID_MAP[self.DP, addr]
        
        try:
            if not now:
                TRACE.debug("trace: read_dp(addr=%#010x) -> ...", addr)
            result = self._link.read_reg(reg_id, now=now)
        except DAPAccess.Error as error:
            TRACE.debug("trace: read_dp(addr=%#010x) -> error(%s)", addr, error)
            raise self._convert_exception(error) from error

        # Read callback returned for async reads.
        def read_dp_result_callback():
            try:
                value = result()
                TRACE.debug("trace: ... read_dp(addr=%#010x) -> %#010x", addr, value)
                return value
            except DAPAccess.Error as error:
                TRACE.debug("trace: ... read_dp(addr=%#010x) -> error(%s)", addr, error)
                raise self._convert_exception(error) from error

        if now:
            TRACE.debug("trace: read_dp(addr=%#010x) -> %#010x", addr, result)
            return result
        else:
            return read_dp_result_callback

    def write_dp(self, addr, data):
        reg_id = self.REG_ADDR_TO_ID_MAP[self.DP, addr]
        
        # Write the DP register.
        try:
            self._link.write_reg(reg_id, data)
            TRACE.debug("trace: write_dp(addr=%#010x, data=%#010x)", addr, data)
        except DAPAccess.Error as error:
            TRACE.debug("trace: write_dp(addr=%#010x, data=%#010x) -> error(%s)", addr, data, error)
            raise self._convert_exception(error) from error

        return True

    def read_ap(self, addr, now=True):
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            if not now:
                TRACE.debug("trace: read_ap(addr=%#010x) -> ...", addr)
            result = self._link.read_reg(ap_reg, now=now)
        except DAPAccess.Error as error:
            raise self._convert_exception(error) from error

        # Read callback returned for async reads.
        def read_ap_result_callback():
            try:
                value = result()
                TRACE.debug("trace: ... read_ap(addr=%#010x) -> %#010x", addr, value)
                return value
            except DAPAccess.Error as error:
                TRACE.debug("trace: ... read_ap(addr=%#010x) -> error(%s)", addr, error)
                raise self._convert_exception(error) from error

        if now:
            TRACE.debug("trace: read_ap(addr=%#010x) -> %#010x", addr, result)
            return result
        else:
            return read_ap_result_callback

    def write_ap(self, addr, data):
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            # Perform the AP register write.
            self._link.write_reg(ap_reg, data)
            TRACE.debug("trace: write_ap(addr=%#010x, data=%#010x)", addr, data)
        except DAPAccess.Error as error:
            TRACE.debug("trace: write_ap(addr=%#010x, data=%#010x) -> error(%s)", addr, data, error)
            raise self._convert_exception(error) from error

        return True

    def read_ap_multiple(self, addr, count=1, now=True):
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]
        
        try:
            if not now:
                TRACE.debug("trace: read_ap_multi(addr=%#010x, count=%i) -> ...", addr, count)
            result = self._link.reg_read_repeat(count, ap_reg, dap_index=0, now=now)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

        # Need to wrap the deferred callback to convert exceptions.
        def read_ap_repeat_callback():
            try:
                values = result()
                TRACE.debug("trace: ... read_ap_multi(addr=%#010x, count=%i) -> [%s]", addr, count,
                        ", ".join(["%#010x" % v for v in values]))
                return values
            except DAPAccess.Error as exc:
                TRACE.debug("trace: ... read_ap_multi(addr=%#010x, count=%i) -> error(%s)",
                    addr, count, exc)
                raise self._convert_exception(exc) from exc

        if now:
            TRACE.debug("trace: read_ap_multi(addr=%#010x, count=%i) -> [%s]", addr, count,
                    ", ".join(["%#010x" % v for v in result]))
            return result
        else:
            return read_ap_repeat_callback

    def write_ap_multiple(self, addr, values):
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]
        
        try:
            self._link.reg_write_repeat(len(values), ap_reg, values, dap_index=0)
            TRACE.debug("trace: write_ap_multi(addr=%#010x, (%i)[%s])", addr, len(values),
                    ", ".join(["%#010x" % v for v in values]))
        except DAPAccess.Error as exc:
            TRACE.debug("trace: write_ap_multi(addr=%#010x, (%i)[%s]) -> error(%s)", addr, len(values),
                    ", ".join(["%#010x" % v for v in values]), exc)
            raise self._convert_exception(exc) from exc
    
    # ------------------------------------------- #
    #          SWO functions
    # ------------------------------------------- #

    def swo_start(self, baudrate):
        TRACE.debug("trace: swo_start(baud=%i)", baudrate)
        
        try:
            self._link.swo_configure(True, baudrate)
            self._link.swo_control(True)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def swo_stop(self):
        TRACE.debug("trace: swo_stop")
        
        try:
            self._link.swo_configure(False, 0)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def swo_read(self):
        try:
            data = self._link.swo_read()
            TRACE.debug("trace: swo_read -> %i bytes", len(data))
            return data
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    @staticmethod
    def _convert_exception(exc):
        if isinstance(exc, DAPAccess.TransferFaultError):
            return exceptions.TransferFaultError(*exc.args)
        elif isinstance(exc, DAPAccess.TransferTimeoutError):
            return exceptions.TransferTimeoutError(*exc.args)
        elif isinstance(exc, DAPAccess.TransferError):
            return exceptions.TransferError(*exc.args)
        elif isinstance(exc, (DAPAccess.DeviceError, DAPAccess.CommandError)):
            return exceptions.ProbeError(*exc.args)
        elif isinstance(exc, DAPAccess.Error):
            return exceptions.Error(*exc.args)
        else:
            return exc

class CMSISDAPProbePlugin(Plugin):
    """! @brief Plugin class for CMSISDAPProbe."""
    
    def load(self):
        return CMSISDAPProbe
    
    @property
    def name(self):
        return "cmsisdap"
    
    @property
    def description(self):
        return "CMSIS-DAP debug probe"
