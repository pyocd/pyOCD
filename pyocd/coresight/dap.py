# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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

from ..core import exceptions
from ..probe.debug_probe import DebugProbe
from .ap import (MEM_AP_CSW, APSEL, APBANKSEL, APREG_MASK, AccessPort)
from ..utility.sequencer import CallSequence
import logging
import logging.handlers
import os
import os.path
import six

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

# DP register addresses.
DP_IDCODE = 0x0 # read-only
DP_ABORT = 0x0 # write-only
DP_CTRL_STAT = 0x4 # read-write
DP_SELECT = 0x8 # write-only
DP_RDBUFF = 0xC # read-only

ABORT_DAPABORT = 0x00000001
ABORT_STKCMPCLR = 0x00000002
ABORT_STKERRCLR = 0x00000004
ABORT_WDERRCLR = 0x00000008
ABORT_ORUNERRCLR = 0x00000010

# DP Control / Status Register bit definitions
CTRLSTAT_ORUNDETECT = 0x00000001
CTRLSTAT_STICKYORUN = 0x00000002
CTRLSTAT_STICKYCMP = 0x00000010
CTRLSTAT_STICKYERR = 0x00000020
CTRLSTAT_READOK = 0x00000040
CTRLSTAT_WDATAERR = 0x00000080

DPIDR_MIN_MASK = 0x10000
DPIDR_VERSION_MASK = 0xf000
DPIDR_VERSION_SHIFT = 12
DPIDR_REVISION_MASK = 0xf0000000
DPIDR_REVISION_SHIFT = 28

CSYSPWRUPACK = 0x80000000
CDBGPWRUPACK = 0x20000000
CSYSPWRUPREQ = 0x40000000
CDBGPWRUPREQ = 0x10000000

TRNNORMAL = 0x00000000
MASKLANE = 0x00000f00

## APSEL is 8-bit, thus there are a maximum of 256 APs.
MAX_APSEL = 255

class DebugPort(object):
    """! @brief Represents the DebugPort (DP)."
    """
    
    ## Map from wire protocol setting name to debug probe constant.
    PROTOCOL_NAME_MAP = {
            'swd': DebugProbe.Protocol.SWD,
            'jtag': DebugProbe.Protocol.JTAG,
            'default': DebugProbe.Protocol.DEFAULT,
        }
    
    def __init__(self, probe, target):
        self._probe = probe
        self.target = target
        self.valid_aps = None
        self.aps = {}
        self._access_number = 0

    @property
    def probe(self):
        return self._probe

    @property
    def next_access_number(self):
        self._access_number += 1
        return self._access_number

    def init(self, protocol=None):
        """! @brief Connect to the target.
        
        This method causes the debug probe to connect using the wire protocol
        
        @param self
        @param protocol One of the @ref pyocd.probe.debug_probe.DebugProbe.Protocol
            "DebugProbe.Protocol" enums. If not provided, will default to the `protocol` setting.
        """
        protocol_name = self.target.session.options.get('dap_protocol').strip().lower()
        send_swj = self.target.session.options.get('dap_enable_swj') and self.probe.supports_swj_sequence
        use_deprecated = self.target.session.options.get('dap_use_deprecated_swj')

        # Convert protocol from setting if not passed as parameter.
        if protocol is None:
            protocol = self.PROTOCOL_NAME_MAP[protocol_name]
            if protocol not in self.probe.supported_wire_protocols:
                raise exceptions.DebugError("requested wire protocol %s not supported by the debug probe" % protocol.name)
        if protocol != DebugProbe.Protocol.DEFAULT:
            LOG.debug("Using %s wire protocol", protocol.name)
            
        # Connect using the selected protocol.
        self.probe.connect(protocol)

        # Log the actual protocol if selected was default.
        if protocol == DebugProbe.Protocol.DEFAULT:
            LOG.debug("Default wire protocol selected; using %s", self.probe.wire_protocol.name)
        
        # Multiple attempts to select protocol and read DP IDCODE.
        for attempt in range(4):
            try:
                if send_swj:
                    # Start off with not using dormant.
                    self._swj_sequence(use_deprecated)
                
                # Attempt to read the DP IDCODE register.
                self.read_id_code()
                
                LOG.info("DP IDR = 0x%08x (v%d%s rev%d)", self.dpidr, self.dp_version,
                    " MINDP" if self.is_mindp else "", self.dp_revision)
                
                break
            except exceptions.TransferError:
                # If not sending the SWJ sequence, just reraise; there's nothing more to do.
                if not send_swj:
                    raise
                
                # If the read of the DP IDCODE fails, retry SWJ sequence. The DP may have been
                # in a state where it thought the SWJ sequence was an invalid transfer. We also
                # try 
                LOG.debug("DP IDCODE read failed; resending SWJ sequence (use deprecated=%s)", use_deprecated)
                
                if attempt == 1:
                    # If already using dormant mode, just raise, we don't need to retry the same mode.
                    if not use_deprecated:
                        raise
                    
                    # After the second attempt, switch to enabling dormant mode.
                    use_deprecated = False
                elif attempt == 3:
                    # After 4 attempts, we let the exception propagate.
                    raise
        self.clear_sticky_err()

    def _swj_sequence(self, use_deprecated):
        """! @brief Send SWJ sequence to select chosen wire protocol."""
        # Not all probes support sending SWJ sequences.
        if self.probe.wire_protocol == DebugProbe.Protocol.SWD:
            self._switch_to_swd(use_deprecated)
        elif self.probe.wire_protocol == DebugProbe.Protocol.JTAG:
            self._switch_to_jtag(use_deprecated)
        else:
            assert False

    def _switch_to_swd(self, use_deprecated):
        """! @brief Send SWJ sequence to select SWD."""
        if not use_deprecated:
            LOG.debug("Sending SWJ sequence to select SWD; using dormant state")
            
            # Ensure current debug interface is in reset state
            self.probe.swj_sequence(51, 0xffffffffffffff)
            
            # Send all this in one transfer:
            # Select Dormant State (from JTAG), 0xb3bbbbbaff
            # 8 cycles SWDIO/TMS HIGH, 0xff
            # Alert Sequence, 0x19bc0ea2e3ddafe986852d956209f392
            # 4 cycles SWDIO/TMS LOW + 8-Bit SWD Activation Code (0x1A), 0x01a0
            self.probe.swj_sequence(188, 0x01a019bc0ea2e3ddafe986852d956209f392ffb3bbbbbaff)
           
            # Enter SWD Line Reset State
            self.probe.swj_sequence(51, 0xffffffffffffff)  # > 50 cycles SWDIO/TMS High
            self.probe.swj_sequence(8,  0x00)                # At least 2 idle cycles (SWDIO/TMS Low)
        else:
            LOG.debug("Sending deprecated SWJ sequence to select SWD")
            
            # Ensure current debug interface is in reset state
            self.probe.swj_sequence(51, 0xffffffffffffff)
            
            # Execute SWJ-DP Switch Sequence JTAG to SWD (0xE79E)
            # Change if SWJ-DP uses deprecated switch code (0xEDB6)
            self.probe.swj_sequence(16, 0xe79e)
            
            # Enter SWD Line Reset State
            self.probe.swj_sequence(51, 0xffffffffffffff)  # > 50 cycles SWDIO/TMS High
            self.probe.swj_sequence(8,  0x00)                # At least 2 idle cycles (SWDIO/TMS Low)
    
    def _switch_to_jtag(self, use_deprecated):
        """! @brief Send SWJ sequence to select JTAG."""
        if not use_deprecated:
            LOG.debug("Sending SWJ sequence to select JTAG ; using dormant state")
            
            # Ensure current debug interface is in reset state
            self.probe.swj_sequence(51, 0xffffffffffffff)
            
            # Select Dormant State (from SWD)
            # At least 8 cycles SWDIO/TMS HIGH, 0xE3BC
            # Alert Sequence, 0x19bc0ea2e3ddafe986852d956209f392
            # 4 cycles SWDIO/TMS LOW + 8-Bit JTAG Activation Code (0x0A), 0x00a0
            self.probe.swj_sequence(188, 0x00a019bc0ea2e3ddafe986852d956209f392ffe3bc)
           
            # Ensure JTAG interface is reset
            self.probe.swj_sequence(6, 0x3f)
        else:
            LOG.debug("Sending deprecated SWJ sequence to select JTAG")
            
            # Ensure current debug interface is in reset state
            self.probe.swj_sequence(51, 0xffffffffffffff)
            
            # Execute SWJ-DP Switch Sequence SWD to JTAG (0xE73C)
            # Change if SWJ-DP uses deprecated switch code (0xAEAE)
            self.probe.swj_sequence(16, 0xe73c)
            
            # Ensure JTAG interface is reset
            self.probe.swj_sequence(6, 0x3f)

    def read_id_code(self):
        """! @brief Read ID register and get DP version"""
        self.dpidr = self.read_reg(DP_IDCODE)
        self.dp_version = (self.dpidr & DPIDR_VERSION_MASK) >> DPIDR_VERSION_SHIFT
        self.dp_revision = (self.dpidr & DPIDR_REVISION_MASK) >> DPIDR_REVISION_SHIFT
        self.is_mindp = (self.dpidr & DPIDR_MIN_MASK) != 0
        return self.dpidr

    def flush(self):
        try:
            self.probe.flush()
        except exceptions.ProbeError as error:
            self._handle_error(error, self.next_access_number)
            raise

    def read_reg(self, addr, now=True):
        return self.read_dp(addr, now)

    def write_reg(self, addr, data):
        self.write_dp(addr, data)

    def power_up_debug(self):
        # select bank 0 (to access DRW and TAR)
        self.write_reg(DP_SELECT, 0)
        self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ)

        while True:
            r = self.read_reg(DP_CTRL_STAT)
            if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == (CDBGPWRUPACK | CSYSPWRUPACK):
                break

        self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ | TRNNORMAL | MASKLANE)
        self.write_reg(DP_SELECT, 0)

    def power_down_debug(self):
        # select bank 0 (to access DRW and TAR)
        self.write_reg(DP_SELECT, 0)
        self.write_reg(DP_CTRL_STAT, 0)

    def reset(self):
        for ap in self.aps.values():
            ap.reset_did_occur()
        self.probe.reset()

    def assert_reset(self, asserted):
        if asserted:
            for ap in self.aps.values():
                ap.reset_did_occur()
        self.probe.assert_reset(asserted)

    def is_reset_asserted(self):
        return self.probe.is_reset_asserted()

    def set_clock(self, frequency):
        self.probe.set_clock(frequency)
        
    def find_aps(self):
        """! @brief Find valid APs.
        
        Scans for valid APs starting at APSEL=0. The default behaviour is to stop the first time a
        0 is returned when reading the AP's IDR. If the `probe_all_aps` user option is set to True,
        then the scan will instead probe every APSEL from 0-255.
        
        Note that a few MCUs will lock up when accessing invalid APs. Those MCUs will have to
        modify the init call sequence to substitute a fixed list of valid APs. In fact, that
        is a major reason this method is separated from create_aps().
        """
        if self.valid_aps is not None:
            return
        apList = []
        ap_num = 0
        while ap_num < MAX_APSEL:
            try:
                isValid = AccessPort.probe(self, ap_num)
                if isValid:
                    apList.append(ap_num)
                elif not self.target.session.options.get('probe_all_aps'):
                    break
            except exceptions.Error as e:
                LOG.error("Exception while probing AP#%d: %s", ap_num, e)
                break
            ap_num += 1
        
        # Update the AP list once we know it's complete.
        self.valid_aps = apList

    def create_aps(self):
        """! @brief Init task that returns a call sequence to create APs.
        
        For each AP in the #valid_aps list, an AccessPort object is created. The new objects
        are added to the #aps dict, keyed by their AP number.
        """
        seq = CallSequence()
        for ap_num in self.valid_aps:
            seq.append(
                ('create_ap.{}'.format(ap_num), lambda ap_num=ap_num: self.create_1_ap(ap_num))
                )
        return seq
    
    def create_1_ap(self, ap_num):
        """! @brief Init task to create a single AP object."""
        try:
            ap = AccessPort.create(self, ap_num)
            self.aps[ap_num] = ap
        except exceptions.Error as e:
            LOG.error("Exception reading AP#%d IDR: %s", ap_num, e)
    
    def find_components(self):
        """! @brief Init task that generates a call sequence to ask each AP to find its components."""
        seq = CallSequence()
        for ap in [x for x in self.aps.values() if x.has_rom_table]:
            seq.append(
                ('init_ap.{}'.format(ap.ap_num), ap.find_components)
                )
        return seq

    def read_dp(self, addr, now=True):
        num = self.next_access_number

        try:
            result_cb = self.probe.read_dp(addr, now=False)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def read_dp_cb():
            try:
                result = result_cb()
                TRACE.debug("read_dp:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.ProbeError as error:
                self._handle_error(error, num)
                raise

        if now:
            return read_dp_cb()
        else:
            TRACE.debug("read_dp:%06d (addr=0x%08x) -> ...", num, addr)
            return read_dp_cb

    def write_dp(self, addr, data):
        num = self.next_access_number

        # Write the DP register.
        try:
            TRACE.debug("write_dp:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.probe.write_dp(addr, data)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        return True

    def write_ap(self, addr, data):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number

        try:
            TRACE.debug("write_ap:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.probe.write_ap(addr, data)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        return True

    def read_ap(self, addr, now=True):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number

        try:
            result_cb = self.probe.read_ap(addr, now=False)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def read_ap_cb():
            try:
                result = result_cb()
                TRACE.debug("read_ap:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.ProbeError as error:
                self._handle_error(error, num)
                raise

        if now:
            return read_ap_cb()
        else:
            TRACE.debug("read_ap:%06d (addr=0x%08x) -> ...", num, addr)
            return read_ap_cb

    def _handle_error(self, error, num):
        TRACE.debug("error:%06d %s", num, error)
        # Clear sticky error for fault errors.
        if isinstance(error, exceptions.TransferFaultError):
            self.clear_sticky_err()
        # For timeouts caused by WAIT responses, set DAPABORT to abort the transfer.
        elif isinstance(error, exceptions.TransferTimeoutError):
            self.write_reg(DP_ABORT, ABORT_DAPABORT)

    def clear_sticky_err(self):
        mode = self.probe.wire_protocol
        if mode == DebugProbe.Protocol.SWD:
            self.write_reg(DP_ABORT, ABORT_ORUNERRCLR | ABORT_WDERRCLR | ABORT_STKERRCLR | ABORT_STKCMPCLR)
        elif mode == DebugProbe.Protocol.JTAG:
            self.write_reg(DP_CTRL_STAT, CTRLSTAT_STICKYERR | CTRLSTAT_STICKYCMP | CTRLSTAT_STICKYORUN)
        else:
            assert False



