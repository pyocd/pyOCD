# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

import logging
from collections import namedtuple
from enum import Enum

from ..core import (exceptions, memory_interface)
from ..core.target import Target
from ..probe.debug_probe import DebugProbe
from ..probe.swj import SWJSequenceSender
from .ap import APSEL_APBANKSEL
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
DPADDR_DPBANKSEL_MASK = 0xf0
DPADDR_DPBANKSEL_SHIFT = 4

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

# DP SELECT register fields.
SELECT_DPBANKSEL_MASK = 0x0000000f
SELECT_APADDR_MASK = 0xfffffff0

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
        
        # Make sure we have a session, since we get the session from the probe and probes have their session set
        # after creation.
        assert self._session is not None, "DPConnector requires the probe to have a session"
    
    @property
    def idr(self):
        """! @brief DPIDR instance containing values read from the DP IDR register."""
        return self._idr
    
    def _get_protocol(self, protocol):
        # Convert protocol from setting if not passed as parameter.
        if protocol is None:
            protocol_name = self._session.options.get('dap_protocol').strip().lower()
            protocol = DebugProbe.PROTOCOL_NAME_MAP[protocol_name]
            if protocol not in self._probe.supported_wire_protocols:
                raise exceptions.DebugError("requested wire protocol %s not supported by the debug probe" % protocol.name)
        return protocol
    
    def connect(self, protocol=None):
        """! @brief Establish a connection to the DP.
        
        This method causes the debug probe to connect using the wire protocol.
        
        @param self
        @param protocol One of the @ref pyocd.probe.debug_probe.DebugProbe.Protocol
            "DebugProbe.Protocol" enums. If not provided, will default to the `dap_protocol` setting.
        
        @exception DebugError
        @exception TransferError
        """
        try:
            self._probe.lock()

            # Determine the requested wire protocol.
            protocol = self._get_protocol(protocol)

            # If this is not None then the probe is already connected.
            current_wire_protocol = self._probe.wire_protocol
            already_connected = current_wire_protocol is not None
        
            if already_connected:
                self._check_protocol(current_wire_protocol, protocol)
            else:
                self._connect_probe(protocol)

            protocol = self._probe.wire_protocol
            self._connect_dp(protocol)
        finally:
            self._probe.unlock()
    
    def _check_protocol(self, current_wire_protocol, protocol):
        # Warn about mismatched current and requested wire protocols.
        if (protocol is not current_wire_protocol) and (protocol is not DebugProbe.Protocol.DEFAULT):
            LOG.warning("Cannot use %s; already connected with %s", protocol.name, current_wire_protocol.name)
        else:
            LOG.debug("Already connected with %s", current_wire_protocol.name)

    def _connect_probe(self, protocol):
        # Debug log with the selected protocol.
        if protocol is not DebugProbe.Protocol.DEFAULT:
            LOG.debug("Using %s wire protocol", protocol.name)
        
        # Connect using the selected protocol.
        self._probe.connect(protocol)

        # Log the actual protocol if selected was default.
        if protocol is DebugProbe.Protocol.DEFAULT:
            protocol = self._probe.wire_protocol
            LOG.debug("Default wire protocol selected; using %s", protocol.name)
        
    def _connect_dp(self, protocol):
        # Get SWJ settings.
        use_dormant = self._session.options.get('dap_swj_use_dormant')
        send_swj = self._session.options.get('dap_swj_enable') \
                and (DebugProbe.Capability.SWJ_SEQUENCE in self._probe.capabilities)

        # Create object to send SWJ sequences.
        swj = SWJSequenceSender(self._probe, use_dormant)
        
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
                # try enabling use of dormant state if it wasn't already enabled.
                LOG.debug("DP IDCODE read failed; resending SWJ sequence (use dormant=%s)", use_dormant)
                
                if attempt == 1:
                    # If already using dormant mode, just raise, we don't need to retry the same mode.
                    if use_dormant:
                        raise
                    
                    # After the second attempt, switch to enabling dormant mode.
                    swj.use_dormant = True
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
        """! @brief Constructor.
        @param self The DebugPort object.
        @param probe The @ref pyocd.probe.debug_probe.DebugProbe "DebugProbe" object. The probe is assumed to not
            have been opened yet.
        @param target An instance of @ref pyocd.core.soc_target.SoCTarget "SoCTarget". Assumed to not have been
            fully initialized.
        """
        self._probe = probe
        self.target = target
        self._session = target.session
        self.valid_aps = None
        self.dpidr = None
        self.aps = {}
        self._access_number = 0
        self._cached_dp_select = None
        self._protocol = None
        self._probe_managed_ap_select = False
        self._probe_managed_dpbanksel = False
        self._probe_supports_dpbanksel = False
        self._probe_supports_apv2_addresses = False
        self._have_probe_capabilities = False
        self._did_check_version = False
        
        # DPv3 attributes
        self._is_dpv3 = False
        self._addr_size = None
        self._addr_mask = None
        self._errmode = None
        self._base_addr = None
        self._apacc_mem_interface = None
        
        # Subscribe to reset events.
        self._session.subscribe(self._reset_did_occur, (Target.Event.PRE_RESET, Target.Event.POST_RESET))

    @property
    def probe(self):
        return self._probe
    
    @property
    def session(self):
        return self._session
    
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
    
    def lock(self):
        """! @brief Lock the DP from access by other threads."""
        self.probe.lock()
    
    def unlock(self):
        """! @brief Unlock the DP."""
        self.probe.unlock()

    def connect(self, protocol=None):
        """! @brief Connect to the target.
        
        This method causes the debug probe to connect using the selected wire protocol. The probe
        must have already been opened prior to this call.
        
        Unlike create_connect_sequence(), this method is intended to be used when manually constructing a
        DebugPort instance. It simply calls create_connect_sequence() and invokes the returned call sequence.
        
        @param self
        @param protocol One of the @ref pyocd.probe.debug_probe.DebugProbe.Protocol
            "DebugProbe.Protocol" enums. If not provided, will default to the `protocol` setting.
        """
        self._protocol = protocol
        self.create_connect_sequence().invoke()

    def create_connect_sequence(self):
        """! @brief Returns call sequence to connect to the target.
        
        Returns a @ref pyocd.utility.sequence.CallSequence CallSequence that will connect to the
        DP, power up debug and the system, check the DP version to identify whether the target uses
        ADI v5 or v6, then clears sticky errors.
        
        The probe must have already been opened prior to this method being called.
        
        @param self
        @return @ref pyocd.utility.sequence.CallSequence CallSequence
        """
        seq = [
            ('lock_probe',          self.probe.lock),
            ]
        if not self._have_probe_capabilities:
            seq += [
                ('get_probe_capabilities', self._get_probe_capabilities),
                ]
        seq += [
            ('connect',             self._connect),
            ('clear_sticky_err',    self.clear_sticky_err),
            ('power_up_debug',      self.power_up_debug),
            ]
        if not self._did_check_version:
            seq += [
                ('check_version',       self._check_version),
                ]
        seq += [
            ('unlock_probe',        self.probe.unlock),
            ]
        return CallSequence(*seq)

    def _get_probe_capabilities(self):
        """! @brief Examine the probe's capabilities."""
        caps = self._probe.capabilities
        self._probe_managed_ap_select = (DebugProbe.Capability.MANAGED_AP_SELECTION in caps)
        self._probe_managed_dpbanksel = (DebugProbe.Capability.MANAGED_DPBANKSEL in caps)
        self._probe_supports_dpbanksel = (DebugProbe.Capability.BANKED_DP_REGISTERS in caps)
        self._probe_supports_apv2_addresses = (DebugProbe.Capability.APv2_ADDRESSES in caps)
        self._have_probe_capabilities = True

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
            # Check that the probe will be able to access ADIv6 APs.
            if self._probe_managed_ap_select and not self._probe_supports_apv2_addresses:
                raise exceptions.ProbeError("connected to ADIv6 target with probe that does not support APv2 addresses")
            
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

        self._did_check_version = True

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

    def _invalidate_cache(self):
        """! @brief Invalidate cached DP registers."""
        self._cached_dp_select = None
    
    def _reset_did_occur(self, notification):
        """! @brief Handles reset notifications to invalidate register cache.
        
        The cache is cleared on all resets just to be safe. On most devices, warm resets do not reset
        debug logic, but it does happen on some devices.
        """
        self._invalidate_cache()
    
    def reset(self):
        """! @brief Hardware reset.
        
        Pre- and post-reset notifications are sent.
        
        This method can be called before the DebugPort is connected.
        """
        self.session.notify(Target.Event.PRE_RESET, self)
        self.probe.reset()
        self.session.notify(Target.Event.POST_RESET, self)

    def assert_reset(self, asserted):
        """! @brief Assert or deassert the hardware reset signal.
        
        A pre-reset notification is sent before asserting reset, whereas a post-reset notification is sent
        after deasserting reset.
        
        This method can be called before the DebugPort is connected.
        
        @param self This object.
        @param asserted True if nRESET is to be driven low; False will drive nRESET high.
        """
        is_asserted = self.is_reset_asserted()
        if asserted and not is_asserted:
            self.session.notify(Target.Event.PRE_RESET, self)

        self.probe.assert_reset(asserted)

        if not asserted and is_asserted:
            self.session.notify(Target.Event.POST_RESET, self)

    def is_reset_asserted(self):
        """! @brief Returns the current state of the nRESET signal.
        
        This method can be called before the DebugPort is initalized.

        @retval True Reset is asserted; nRESET is low.
        @retval False Reset is not asserted; nRESET is high.
        """
        return self.probe.is_reset_asserted()

    def set_clock(self, frequency):
        """! @brief Change the wire protocol's clock frequency.
        @param self This object.
        @param frequency New wire protocol frequency in Hertz.
        """
        self.probe.set_clock(frequency)

    def _write_dp_select(self, mask, value):
        """! @brief Modify part of the DP SELECT register and write if cache is stale.
        
        The DP lock must already be acquired before calling this method.
        """
        # Compute the new SELECT value and see if we need to write it.
        if self._cached_dp_select is None:
            select = value
        else:
            select = (self._cached_dp_select & ~mask) | value
            if select == self._cached_dp_select:
                return
        
        # Update the SELECT register and cache.
        self.write_dp(DP_SELECT, select)
        self._cached_dp_select = select
    
    def _set_dpbanksel(self, addr, is_write):
        """! @brief Updates the DPBANKSEL field of the SELECT register as required.
        
        Several DP registers (most, actually) ignore DPBANKSEL. If one of those is being
        accessed, any value of DPBANKSEL can be used. Otherwise SELECT is updated if necessary
        and a lock acquired so another thread doesn't change DPBANKSEL until thsi transaction is
        complete.
        
        This method also handles the case where the debug probe manages DPBANKSEL on its own,
        such as with STLink.
        
        @return Whether the access needs a lock on DP SELECT.
        @exception exceptions.ProbeError Raised when a banked register is being accessed but the
            probe doesn't support DPBANKSEL.
        """
        # For DPv1-2, only address 0x4 (CTRL/STAT) honours DPBANKSEL.
        # For DPv3, SELECT and RDBUFF ignore DPBANKSEL for both reads and writes, while
        # ABORT ignores it only for writes (address 0 for reads is IDR).
        if self._is_dpv3 and not is_write:
            registers_ignoring_dpbanksel = (DP_SELECT, DP_RDBUFF)
        else:
            registers_ignoring_dpbanksel = (DP_ABORT, DP_SELECT, DP_RDBUFF)
        
        if (addr & DPADDR_MASK) not in registers_ignoring_dpbanksel:
            # Get the DP bank.
            dpbanksel = (addr & DPADDR_DPBANKSEL_MASK) >> DPADDR_DPBANKSEL_SHIFT
            
            # Check if the probe handles this for us.
            if self._probe_managed_dpbanksel:
                # If there is a nonzero DPBANKSEL and the probe doesn't support this,
                # then report an error.
                if dpbanksel and not self._probe_supports_dpbanksel:
                    raise exceptions.ProbeError("probe does not support banked DP registers")
                else:
                    return False
            
            # Update the selected DP bank.
            self.lock()
            self._write_dp_select(SELECT_DPBANKSEL_MASK, dpbanksel)
            return True
        else:
            return False

    def read_dp(self, addr, now=True):
        if (addr & DPADDR_MASK) % 4 != 0:
            raise ValueError("DP address must be word aligned")
        num = self.next_access_number
        
        # Update DPBANKSEL if required.
        did_lock = self._set_dpbanksel(addr, False)

        try:
            result_cb = self.probe.read_dp(addr & DPADDR_MASK, now=False)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            if did_lock:
                self.unlock()
            raise
        except Exception:
            if did_lock:
                self.unlock()
            raise

        # Read callback returned for async reads.
        def read_dp_cb():
            try:
                result = result_cb()
                TRACE.debug("read_dp:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.TargetError as error:
                TRACE.debug("read_dp:%06d %s(addr=0x%08x) -> error (%s)", num, "" if now else "...", addr, error)
                self._handle_error(error, num)
                raise
            finally:
                if did_lock:
                    self.unlock()

        if now:
            return read_dp_cb()
        else:
            TRACE.debug("read_dp:%06d (addr=0x%08x) -> ...", num, addr)
            return read_dp_cb

    def write_dp(self, addr, data):
        if (addr & DPADDR_MASK) % 4 != 0:
            raise ValueError("DP address must be word aligned")
        num = self.next_access_number
        
        # Update DPBANKSEL if required.
        did_lock = self._set_dpbanksel(addr, True)

        # Write the DP register.
        try:
            TRACE.debug("write_dp:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.probe.write_dp(addr & DPADDR_MASK, data)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise
        finally:
            if did_lock:
                self.unlock()

        return True
    
    def _select_ap(self, addr):
        """! @brief Write DP_SELECT to choose the given AP.
        
        Handles the case where the debug probe manages selecting an AP itself, in which case we
        never write SELECT directly.

        @return Whether the access needs a lock on DP SELECT.
        """
        # If the probe handles selecting the AP for us, there's nothing to do here.
        if self._probe_managed_ap_select:
            return False
        
        # Write DP SELECT to select the probe.
        self.lock()
        if self.adi_version == ADIVersion.ADIv5:
            self._write_dp_select(APSEL_APBANKSEL, addr & APSEL_APBANKSEL)
        elif self.adi_version == ADIVersion.ADIv6:
            self._write_dp_select(SELECT_APADDR_MASK, addr & SELECT_APADDR_MASK)
        else:
            self.unlock()
            assert False, "invalid ADI version"
        return True

    def write_ap(self, addr, data):
        assert isinstance(addr, int)
        num = self.next_access_number
        did_lock = False

        try:
            did_lock = self._select_ap(addr)
            TRACE.debug("write_ap:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.probe.write_ap(addr, data)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise
        finally:
            if did_lock:
                self.unlock()

        return True

    def read_ap(self, addr, now=True):
        assert isinstance(addr, int)
        num = self.next_access_number
        did_lock = False

        try:
            did_lock = self._select_ap(addr)
            result_cb = self.probe.read_ap(addr, now=False)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            if did_lock:
                self.unlock()
            raise
        except Exception:
            if did_lock:
                self.unlock()
            raise

        # Read callback returned for async reads.
        def read_ap_cb():
            try:
                result = result_cb()
                TRACE.debug("read_ap:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.TargetError as error:
                TRACE.debug("read_ap:%06d %s(addr=0x%08x) -> error (%s)", num, "" if now else "...", addr, error)
                self._handle_error(error, num)
                raise
            finally:
                if did_lock:
                    self.unlock()

        if now:
            return read_ap_cb()
        else:
            TRACE.debug("read_ap:%06d (addr=0x%08x) -> ...", num, addr)
            return read_ap_cb

    def write_ap_multiple(self, addr, values):
        assert isinstance(addr, int)
        num = self.next_access_number
        did_lock = False

        try:
            did_lock = self._select_ap(addr)
            TRACE.debug("write_ap_multiple:%06d (addr=0x%08x) = (%i values)", num, addr, len(values))
            return self.probe.write_ap_multiple(addr, values)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise
        finally:
            if did_lock:
                self.unlock()

    def read_ap_multiple(self, addr, count=1, now=True):
        assert isinstance(addr, int)
        num = self.next_access_number
        did_lock = False
        
        try:
            did_lock = self._select_ap(addr)
            TRACE.debug("read_ap_multiple:%06d (addr=0x%08x, count=%i)", num, addr, count)
            result_cb = self.probe.read_ap_multiple(addr, count, now=False)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            raise
        except Exception:
            if did_lock:
                self.unlock()
            raise

        # Need to wrap the deferred callback to convert exceptions.
        def read_ap_multiple_cb():
            try:
                return result_cb()
            except exceptions.TargetError as error:
                TRACE.debug("read_ap_multiple:%06d %s(addr=0x%08x) -> error (%s)", num, "" if now else "...", addr, error)
                self._handle_error(error, num)
                raise
            finally:
                if did_lock:
                    self.unlock()

        if now:
            return read_ap_multiple_cb()
        else:
            return read_ap_multiple_cb

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
        self._invalidate_cache()
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

