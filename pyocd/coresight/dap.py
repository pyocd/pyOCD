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

import logging
import six
from collections import namedtuple
from enum import Enum

from ..core import (exceptions, memory_interface)
from ..probe.debug_probe import DebugProbe
from ..probe.swj import SWJSequenceSender
from .ap import (MEM_AP_CSW, APSEL, APBANKSEL, APREG_MASK, AccessPort)
from ..utility.sequencer import CallSequence
from ..utility.timeout import Timeout

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

# DP register addresses. The DPBANKSEL value is encoded in bits [7:4].
DP_IDR = 0x00 # read-only
DP_IDR1 = 0x10 # read-only
DP_BASEPTR0 = 0x20 # read-only
DP_BASEPTR1 = 0x30 # read-only
DP_ABORT = 0x00 # write-only
DP_CTRL_STAT = 0x04 # read-write
DP_DLCR = 0x14 # read-write
DP_TARGETID = 0x24 # read-only
DP_DLPIDR = 0x34 # read-only
DP_EVENTSTAT = 0x44 # read-only
DP_SELECT1 = 0x54 # write-only
DP_SELECT = 0x8 # write-only
DP_RDBUFF = 0xC # read-only

# Mask and shift for extracting DPBANKSEL from our DP register address constants. These are not
# related to the SELECT.DPBANKSEL bitfield.
DPADDR_MASK = 0x0f
DPBANKSEL_MASK = 0xf0
DPBANKSEL_SHIFT = 4

DPIDR1_ASIZE_MASK = 0x00000007f
DPIDR1_ERRMODE_MASK = 0x00000080

BASEPTR0_VALID_MASK = 0x00000001
BASEPTR0_PTR_MASK = 0xfffff000
BASEPTR0_PTR_SHIFT = 12

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

SELECT_DPBANKSEL_MASK = 0x0000000f

DPIDR_REVISION_MASK = 0xf0000000
DPIDR_REVISION_SHIFT = 28
DPIDR_PARTNO_MASK = 0x0ff00000
DPIDR_PARTNO_SHIFT = 20
DPIDR_MIN_MASK = 0x00010000
DPIDR_VERSION_MASK = 0x0000f000
DPIDR_VERSION_SHIFT = 12

CSYSPWRUPACK = 0x80000000
CDBGPWRUPACK = 0x20000000
CSYSPWRUPREQ = 0x40000000
CDBGPWRUPREQ = 0x10000000

TRNNORMAL = 0x00000000
MASKLANE = 0x00000f00

## Arbitrary 5 second timeout for DP power up/down requests.
DP_POWER_REQUEST_TIMEOUT = 5.0

## @brief Class to hold fields from DP IDR register.
DPIDR = namedtuple('DPIDR', 'idr partno version revision mindp')

class ADIVersion(Enum):
    """! @brief Supported versions of the Arm Debug Interface."""
    ADIv5 = 5
    ADIv6 = 6

class DPConnector(object):
    """! @brief Establishes a connection to the DP for a given wire protocol.
    
    This class will ask the probe to connect using a given wire protocol. Then it makes multiple
    attempts at sending the SWJ sequence to select the wire protocol and read the DP IDR register.
    """
    
    def __init__(self, probe):
        self._probe = probe
        self._session = probe.session
        self._idr = None
    
    @property
    def idr(self):
        """! @brief DPIDR instance containing values read from the DP IDR register."""
        return self._idr
    
    def connect(self, protocol=None):
        """! @brief Establish a connection to the DP.
        
        This method causes the debug probe to connect using the wire protocol.
        
        @param self
        @param protocol One of the @ref pyocd.probe.debug_probe.DebugProbe.Protocol
            "DebugProbe.Protocol" enums. If not provided, will default to the `dap_protocol` setting.
        
        @exception DebugError
        @exception TransferError
        """
        protocol_name = self._session.options.get('dap_protocol').strip().lower()
        send_swj = self._session.options.get('dap_enable_swj') and self._probe.supports_swj_sequence
        use_deprecated = self._session.options.get('dap_use_deprecated_swj')

        # Convert protocol from setting if not passed as parameter.
        if protocol is None:
            protocol = DebugProbe.PROTOCOL_NAME_MAP[protocol_name]
            if protocol not in self._probe.supported_wire_protocols:
                raise exceptions.DebugError("requested wire protocol %s not supported by the debug probe" % protocol.name)
        if protocol != DebugProbe.Protocol.DEFAULT:
            LOG.debug("Using %s wire protocol", protocol.name)
            
        # Connect using the selected protocol.
        self._probe.connect(protocol)

        # Log the actual protocol if selected was default.
        if protocol == DebugProbe.Protocol.DEFAULT:
            protocol = self._probe.wire_protocol
            LOG.debug("Default wire protocol selected; using %s", protocol.name)
        
        # Create object to send SWJ sequences.
        swj = SWJSequenceSender(self._probe, use_deprecated)
        
        # Multiple attempts to select protocol and read DP IDR.
        for attempt in range(4):
            try:
                if send_swj:
                    swj.select_protocol(protocol)
                
                # Attempt to read the DP IDR register.
                self._idr = self.read_idr()
                
                # Successful connection so exit the loop.
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
                    swj.use_deprecated = False
                elif attempt == 3:
                    # After 4 attempts, we let the exception propagate.
                    raise

    def read_idr(self):
        """! @brief Read IDR register and get DP version"""
        dpidr = self._probe.read_dp(DP_IDR, now=True)
        dp_partno = (dpidr & DPIDR_PARTNO_MASK) >> DPIDR_PARTNO_SHIFT
        dp_version = (dpidr & DPIDR_VERSION_MASK) >> DPIDR_VERSION_SHIFT
        dp_revision = (dpidr & DPIDR_REVISION_MASK) >> DPIDR_REVISION_SHIFT
        is_mindp = (dpidr & DPIDR_MIN_MASK) != 0
        return DPIDR(dpidr, dp_partno, dp_version, dp_revision, is_mindp)

class DebugPort(object):
    """! @brief Represents the Arm Debug Interface (ADI) Debug Port (DP)."""
    
    def __init__(self, probe, target):
        self._probe = probe
        self.target = target
        self.valid_aps = None
        self.dpidr = None
        self.aps = {}
        self._access_number = 0
        self._cached_dpbanksel = None
        self._protocol = None
        
        # DPv3 attributes
        self._is_dpv3 = False
        self._addr_size = None
        self._addr_mask = None
        self._errmode = None
        self._base_addr = None
        self._apacc_mem_interface = None

    @property
    def probe(self):
        return self._probe
    
    @property
    def adi_version(self):
        return ADIVersion.ADIv6 if self._is_dpv3 else ADIVersion.ADIv5
    
    @property
    def base_address(self):
        """! @brief Base address of the first component for an ADIv6 system."""
        return self._base_addr
    
    @property
    def apacc_memory_interface(self):
        """! @brief Memory interface for performing APACC transactions."""
        if self._apacc_mem_interface is None:
            self._apacc_mem_interface = APAccessMemoryInterface(self)
        return self._apacc_mem_interface
    
    @property
    def next_access_number(self):
        self._access_number += 1
        return self._access_number

    def init(self, protocol=None):
        """! @brief Connect to the target.
        
        This method causes the debug probe to connect using the selected wire protocol.
        
        Unlike init_sequence(), this method is intended to be used when manually constructing a
        DebugPort instance. It simply calls init_sequence() and invokes the returned call sequence.
        
        @param self
        @param protocol One of the @ref pyocd.probe.debug_probe.DebugProbe.Protocol
            "DebugProbe.Protocol" enums. If not provided, will default to the `protocol` setting.
        """
        self._protocol = protocol
        self.init_sequence().invoke()

    def init_sequence(self):
        """! @brief Init task to connect to the target.
        
        Returns a @ref pyocd.utility.sequence.CallSequence CallSequence that will connect to the
        DP, power up debug and the system, check the DP version to identify whether the target uses
        ADI v5 or v6, then clears sticky errors.
        
        @param self
        """
        return CallSequence(
            ('connect',             self._connect),
            ('clear_sticky_err',    self.clear_sticky_err),
            ('power_up_debug',      self.power_up_debug),
            ('check_version',       self._check_version),
            )

    def _connect(self):
        # Attempt to connect.
        connector = DPConnector(self.probe)
        connector.connect(self._protocol)

        # Report on DP version.
        self.dpidr = connector.idr
        LOG.info("DP IDR = 0x%08x (v%d%s rev%d)", self.dpidr.idr, self.dpidr.version,
            " MINDP" if self.dpidr.mindp else "", self.dpidr.revision)
        
    def _check_version(self):
        self._is_dpv3 = (self.dpidr.version == 3)
        if self._is_dpv3:
            idr1 = self.read_reg(DP_IDR1)
            
            self._addr_size = idr1 & DPIDR1_ASIZE_MASK
            self._addr_mask = (1 << self._addr_size) - 1
            self._errmode_supported = (idr1 & DPIDR1_ERRMODE_MASK) != 0
            
            LOG.debug("DP IDR1 = 0x%08x (addr size=%d, errmode=%d)", idr1, self._addr_size, self._errmode_supported)
            
            # Read base system address.
            baseptr0 = self.read_reg(DP_BASEPTR0)
            valid = (baseptr0 & BASEPTR0_VALID_MASK) != 0
            if valid:
                base = (baseptr0 & BASEPTR0_PTR_MASK) >> BASEPTR0_PTR_SHIFT
                if self._addr_size > 32:
                    baseptr1 = self.read_reg(DP_BASEPTR1)
                    base |= baseptr1 << 32

                base &= self._addr_mask
                self._base_addr = base
                
                LOG.debug("DP BASEPTR = 0x%08x", self._base_addr)
            else:
                LOG.warning("DPv3 has no valid base address")

    def flush(self):
        try:
            self.probe.flush()
        except exceptions.TargetError as error:
            self._handle_error(error, self.next_access_number)
            raise

    def read_reg(self, addr, now=True):
        return self.read_dp(addr, now)

    def write_reg(self, addr, data):
        self.write_dp(addr, data)

    def power_up_debug(self):
        """! @brief Assert DP power requests.
        
        Request both debug and system power be enabled, and wait until the request is acked.
        There is a timeout for the request.
        
        @return Boolean indicating whether the power up request succeeded.
        """
        # Send power up request for system and debug.
        self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ | MASKLANE | TRNNORMAL)

        with Timeout(DP_POWER_REQUEST_TIMEOUT) as time_out:
            while time_out.check():
                r = self.read_reg(DP_CTRL_STAT)
                if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == (CDBGPWRUPACK | CSYSPWRUPACK):
                    break
            else:
                return False

        self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ | MASKLANE | TRNNORMAL)
        
        return True

    def power_down_debug(self):
        """! @brief Deassert DP power requests.
        
        ADIv6 says that we must not clear CSYSPWRUPREQ and CDBGPWRUPREQ at the same time.
        ADIv5 says CSYSPWRUPREQ must not be set to 1 while CDBGPWRUPREQ is set to 0. So we
        start with deasserting system power, then debug power. Each deassertion has its own
        timeout.
        
        @return Boolean indicating whether the power down request succeeded.
        """
        # Power down system first.
        self.write_reg(DP_CTRL_STAT, CDBGPWRUPREQ | MASKLANE | TRNNORMAL)
        
        with Timeout(DP_POWER_REQUEST_TIMEOUT) as time_out:
            while time_out.check():
                r = self.read_reg(DP_CTRL_STAT)
                if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == CDBGPWRUPACK:
                    break
            else:
                return False

        # Now power down debug.
        self.write_reg(DP_CTRL_STAT,  MASKLANE | TRNNORMAL)
        
        with Timeout(DP_POWER_REQUEST_TIMEOUT) as time_out:
            while time_out.check():
                r = self.read_reg(DP_CTRL_STAT)
                if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == 0:
                    break
            else:
                return False
        
        return True

    def reset(self):
        self._cached_dpbanksel = None
        for ap in self.aps.values():
            ap.reset_did_occur()
        self.probe.reset()

    def assert_reset(self, asserted):
        self._cached_dpbanksel = None
        if asserted:
            for ap in self.aps.values():
                ap.reset_did_occur()
        self.probe.assert_reset(asserted)

    def is_reset_asserted(self):
        return self.probe.is_reset_asserted()

    def set_clock(self, frequency):
        self.probe.set_clock(frequency)

    def _set_dpbanksel(self, addr):
        # SELECT and RDBUFF ignore DPBANKSEL.
        if (addr & DPADDR_MASK) not in (DP_SELECT, DP_RDBUFF):
            # Make sure the correct DP bank is selected.
            dpbanksel = addr & DPBANKSEL_MASK
            if dpbanksel != self._cached_dpbanksel:
                # Blow away any selected AP.
                select = dpbanksel >> DPBANKSEL_SHIFT
                self.write_dp(DP_SELECT, select)
                self._cached_dpbanksel = dpbanksel

    def read_dp(self, addr, now=True):
        num = self.next_access_number
        
        self._set_dpbanksel(addr)

        try:
            result_cb = self.probe.read_dp(addr & DPADDR_MASK, now=False)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def read_dp_cb():
            try:
                result = result_cb()
                TRACE.debug("read_dp:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.TargetError as error:
                self._handle_error(error, num)
                raise

        if now:
            return read_dp_cb()
        else:
            TRACE.debug("read_dp:%06d (addr=0x%08x) -> ...", num, addr)
            return read_dp_cb

    def write_dp(self, addr, data):
        num = self.next_access_number
        
        # Writing to ABORT ignores DPBANKSEL.
        if (addr & DPADDR_MASK) != DP_ABORT:
            self._set_dpbanksel(addr)

        # Write the DP register.
        try:
            TRACE.debug("write_dp:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.probe.write_dp(addr & DPADDR_MASK, data)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise

        return True

    def write_ap(self, addr, data):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number

        try:
            TRACE.debug("write_ap:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.probe.write_ap(addr, data)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise

        return True

    def read_ap(self, addr, now=True):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number

        try:
            result_cb = self.probe.read_ap(addr, now=False)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def read_ap_cb():
            try:
                result = result_cb()
                TRACE.debug("read_ap:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.TargetError as error:
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
            # This may put the AP that was aborted into an unpredictable state. Should consider
            # attempting to reset debug logic.
            self.write_reg(DP_ABORT, ABORT_DAPABORT)

    def clear_sticky_err(self):
        self._cached_dpbanksel = None
        mode = self.probe.wire_protocol
        if mode == DebugProbe.Protocol.SWD:
            self.write_reg(DP_ABORT, ABORT_ORUNERRCLR | ABORT_WDERRCLR | ABORT_STKERRCLR | ABORT_STKCMPCLR)
        elif mode == DebugProbe.Protocol.JTAG:
            self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ | TRNNORMAL | MASKLANE
                    | CTRLSTAT_STICKYERR | CTRLSTAT_STICKYCMP | CTRLSTAT_STICKYORUN)
        else:
            assert False

class APAccessMemoryInterface(memory_interface.MemoryInterface):
    """! @brief Memory interface for performing simple APACC transactions.
    
    This class allows the caller to generate Debug APB transactions from a DPv3. It simply
    adapts the MemoryInterface to APACC transactions.
    
    By default, it passes memory transaction addresses unmodified to the DP. But an instance can be
    constructed by passing an APAddress object to the constructor that offsets transaction addresses
    so they are relative to the APAddress base.
    
    Only 32-bit transfers are supported.
    """
    
    def __init__(self, dp, ap_address=None):
        """! @brief Constructor.
        
        @param self
        @param dp The DebugPort object.
        @param ap_address Optional instance of APAddress. If provided, all memory transaction
            addresses are offset by the base address of the APAddress.
        """
        self._dp = dp
        self._ap_address = ap_address
        if ap_address is not None:
            self._offset = ap_address.address
        else:
            self._offset = 0
    
    @property
    def dp(self):
        return self._dp
    
    @property
    def short_description(self):
        if self._ap_address is None:
            return "Root Component"
        else:
            return "Root Component ({})".format(self._ap_address)

    def write_memory(self, addr, data, transfer_size=32):
        """! @brief Write a single memory location.
        
        By default the transfer size is a word."""
        if transfer_size != 32:
            raise exceptions.DebugError("unsupported transfer size")
        
        return self._dp.write_ap(self._offset + addr, data)
        
    def read_memory(self, addr, transfer_size=32, now=True):
        """! @brief Read a memory location.
        
        By default, a word will be read."""
        if transfer_size != 32:
            raise exceptions.DebugError("unsupported transfer size")
        
        return self._dp.read_ap(self._offset + addr, now)

    def write_memory_block32(self, addr, data):
        """! @brief Write an aligned block of 32-bit words."""
        addr += self._offset
        for word in data:
            self._dp.write_ap(addr, data)
            addr += 4

    def read_memory_block32(self, addr, size):
        """! @brief Read an aligned block of 32-bit words."""
        addr += self._offset
        result_cbs = [self._dp.read_ap(addr + i * 4, now=False) for i in range(size)]
        result = [cb() for cb in result_cbs]
        return result

