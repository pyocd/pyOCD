# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
# Copyright (c) 2022 Clay McClure
# Copyright (c) 2022 Toshiba Electronic Devices & Storage Corporation
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

import logging
from enum import Enum
from typing import (cast, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple, TYPE_CHECKING, Union, overload)
from typing_extensions import Literal

from ..core import (exceptions, memory_interface)
from ..core.target import Target
from ..core.target_delegate import DelegateHavingMixIn
from ..probe.debug_probe import DebugProbe
from ..probe.swj import SWJSequenceSender
from .ap import APSEL_APBANKSEL
from ..utility.sequencer import CallSequence
from ..utility.timeout import Timeout

if TYPE_CHECKING:
    from .ap import (APAddressBase, AccessPort)
    from ..core.session import Session
    from ..utility.notification import Notification

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
class DPIDR(NamedTuple):
    idr: int
    partno: int
    version: int
    revision: int
    mindp: int

class ADIVersion(Enum):
    """@brief Supported versions of the Arm Debug Interface."""
    ADIv5 = 5
    ADIv6 = 6

class ProbeConnector:
    """@brief Configures the debug probe for a given wire protocol.

    This class will ask the probe to connect using a given wire protocol, unless the probe is already
    connected.
    """

    def __init__(self, probe: DebugProbe) -> None:
        """@brief Constructor.
        @param self
        @param probe The DebugProbe instance to connect.
        """
        self._probe = probe

        # Make sure we have a session, since we get the session from the probe and probes have their session set
        # after creation.
        assert probe.session is not None, "ProbeConnector requires the probe to have a session"
        self._session = probe.session

    def _get_protocol(self, protocol: Optional[DebugProbe.Protocol]) -> DebugProbe.Protocol:
        # Convert protocol from setting if not passed as parameter.
        if protocol is None:
            protocol_name = self._session.options.get('dap_protocol').strip().lower()
            protocol = DebugProbe.PROTOCOL_NAME_MAP[protocol_name]
            if protocol not in self._probe.supported_wire_protocols:
                raise exceptions.DebugError("requested wire protocol %s not supported by the debug probe" % protocol.name)
        return protocol

    def connect(self, protocol: Optional[DebugProbe.Protocol] = None) -> None:
        """@brief Cause the debug probe to connect using the wire protocol.

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
        finally:
            self._probe.unlock()

    def _check_protocol(self, current_wire_protocol: DebugProbe.Protocol, protocol: DebugProbe.Protocol) -> None:
        # Warn about mismatched current and requested wire protocols.
        if (protocol is not current_wire_protocol) and (protocol is not DebugProbe.Protocol.DEFAULT):
            LOG.warning("Cannot use %s; already connected with %s", protocol.name, current_wire_protocol.name)
        else:
            LOG.debug("Already connected with %s", current_wire_protocol.name)

    def _connect_probe(self, protocol: DebugProbe.Protocol) -> None:
        # Debug log with the selected protocol.
        if protocol is not DebugProbe.Protocol.DEFAULT:
            LOG.debug("Using %s wire protocol", protocol.name)

        # Connect using the selected protocol.
        self._probe.connect(protocol)

        # Log the actual protocol if selected was default.
        if protocol is DebugProbe.Protocol.DEFAULT:
            actual_protocol = self._probe.wire_protocol
            assert actual_protocol
            LOG.debug("Default wire protocol selected; using %s", actual_protocol.name)

class DPConnector:
    """@brief Establishes a connection to the DP for a given wire protocol.

    This class will make multiple attempts at sending the SWJ sequence to select the wire protocol and read the
    DP IDR register. The probe must be already connected for the desired wire protocol.
    """

    def __init__(self, probe: DebugProbe) -> None:
        self._probe = probe
        self._idr = DPIDR(0, 0, 0, 0, 0)

        # Make sure we have a session, since we get the session from the probe and probes have their session set
        # after creation.
        assert probe.session is not None, "DPConnector requires the probe to have a session"
        self._session = probe.session

    @property
    def idr(self) -> DPIDR:
        """@brief DPIDR instance containing values read from the DP IDR register."""
        return self._idr

    def connect(self) -> None:
        """@brief Establish a connection to the DP."""
        try:
            self._probe.lock()

            protocol = self._probe.wire_protocol
            assert protocol is not None, "the probe must already be connected"

            # Get SWJ settings.
            use_dormant = self._session.options.get('dap_swj_use_dormant')
            send_swj = self._session.options.get('dap_swj_enable') \
                    and (DebugProbe.Capability.SWJ_SEQUENCE in self._probe.capabilities)

            # Create object to send SWJ sequences.
            swj = SWJSequenceSender(self._probe, use_dormant)

            def jtag_enter_run_test_idle():
                self._probe.jtag_sequence(6, 1, False, 0x3f)
                self._probe.jtag_sequence(1, 0, False, 0x1)

            if protocol == DebugProbe.Protocol.JTAG \
               and DebugProbe.Capability.JTAG_SEQUENCE in self._probe.capabilities:
                use_jtag_enter_run_test_idle = True
            else:
                use_jtag_enter_run_test_idle = False

            # Multiple attempts to select protocol and read DP IDR.
            for attempt in range(4):
                try:
                    if send_swj:
                        swj.select_protocol(protocol)

                    if use_jtag_enter_run_test_idle:
                        jtag_enter_run_test_idle()

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
        finally:
            self._probe.unlock()

    def read_idr(self) -> DPIDR:
        """@brief Read IDR register and get DP version"""
        dpidr = self._probe.read_dp(DP_IDR, now=True)
        TRACE.debug("DPConnector read DP_IDR = 0x%08x", dpidr)
        dp_partno = (dpidr & DPIDR_PARTNO_MASK) >> DPIDR_PARTNO_SHIFT
        dp_version = (dpidr & DPIDR_VERSION_MASK) >> DPIDR_VERSION_SHIFT
        dp_revision = (dpidr & DPIDR_REVISION_MASK) >> DPIDR_REVISION_SHIFT
        is_mindp = (dpidr & DPIDR_MIN_MASK) != 0
        return DPIDR(dpidr, dp_partno, dp_version, dp_revision, is_mindp)

class DebugPort(DelegateHavingMixIn):
    """@brief Represents the Arm Debug Interface (ADI) Debug Port (DP)."""

    ## Sleep for 50 ms between connection tests and reconnect attempts after a reset.
    _RESET_RECOVERY_SLEEP_INTERVAL = 0.05

    ## Number of times to try to read DP registers after hw reset before attempting reconnect.
    _RESET_RECOVERY_ATTEMPTS_BEFORE_RECONNECT = 1

    def __init__(self, probe: DebugProbe, target: Target) -> None:
        """@brief Constructor.
        @param self The DebugPort object.
        @param probe The @ref pyocd.probe.debug_probe.DebugProbe "DebugProbe" object. The probe is assumed to not
            have been opened yet.
        @param target An instance of @ref pyocd.core.soc_target.SoCTarget "SoCTarget". Assumed to not have been
            fully initialized.
        """
        self._probe = probe
        self.target = target
        assert target.session
        self._session = target.session
        self.valid_aps: Optional[List[APAddressBase]] = None
        self.dpidr = DPIDR(0, 0, 0, 0, 0)
        self.aps: Dict[APAddressBase, AccessPort] = {}
        self._access_number: int = 0
        self._cached_dp_select: Optional[int] = None
        self._protocol: Optional[DebugProbe.Protocol] = None
        self._probe_managed_ap_select: bool = False
        self._probe_managed_dpbanksel: bool = False
        self._probe_supports_dpbanksel: bool = False
        self._probe_supports_apv2_addresses: bool = False
        self._have_probe_capabilities: bool = False
        self._did_check_version: bool = False
        self._log_dp_info: bool = True

        # DPv3 attributes
        self._is_dpv3: bool = False
        self._addr_size: int = -1
        self._addr_mask: int = -1
        self._errmode: int = -1
        self._base_addr: int = -1
        self._apacc_mem_interface: Optional[APAccessMemoryInterface] = None

        # Subscribe to reset events.
        self._session.subscribe(self._reset_did_occur, (Target.Event.PRE_RESET, Target.Event.POST_RESET))

    @property
    def probe(self) -> DebugProbe:
        return self._probe

    @property
    def session(self) -> Session:
        return self._session

    @property
    def adi_version(self) -> ADIVersion:
        return ADIVersion.ADIv6 if self._is_dpv3 else ADIVersion.ADIv5

    @property
    def base_address(self) -> int:
        """@brief Base address of the first component for an ADIv6 system."""
        return self._base_addr

    @property
    def apacc_memory_interface(self) -> APAccessMemoryInterface:
        """@brief Memory interface for performing APACC transactions."""
        if self._apacc_mem_interface is None:
            self._apacc_mem_interface = APAccessMemoryInterface(self)
        return self._apacc_mem_interface

    @property
    def next_access_number(self) -> int:
        self._access_number += 1
        return self._access_number

    def lock(self) -> None:
        """@brief Lock the DP from access by other threads."""
        self.probe.lock()

    def unlock(self) -> None:
        """@brief Unlock the DP."""
        self.probe.unlock()

    def connect(self, protocol: Optional[DebugProbe.Protocol] = None) -> None:
        """@brief Connect to the target.

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

    def disconnect(self) -> None:
        """@brief Disconnect from target.

        DP debug is powered down. See power_down_debug().
        """
        self.power_down_debug()

    def create_connect_sequence(self) -> CallSequence:
        """@brief Returns call sequence to connect to the target.

        Returns a @ref pyocd.utility.sequence.CallSequence CallSequence that will connect to the
        DP, power up debug and the system, check the DP version to identify whether the target uses
        ADI v5 or v6, then clears sticky errors.

        The probe must have already been opened prior to this method being called.

        @param self
        @return @ref pyocd.utility.sequence.CallSequence CallSequence
        """
        seq: List[Tuple[str, Callable]] = [
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

    def _get_probe_capabilities(self) -> None:
        """@brief Examine the probe's capabilities."""
        caps = self._probe.capabilities
        self._probe_managed_ap_select = (DebugProbe.Capability.MANAGED_AP_SELECTION in caps)
        self._probe_managed_dpbanksel = (DebugProbe.Capability.MANAGED_DPBANKSEL in caps)
        self._probe_supports_dpbanksel = (DebugProbe.Capability.BANKED_DP_REGISTERS in caps)
        self._probe_supports_apv2_addresses = (DebugProbe.Capability.APv2_ADDRESSES in caps)
        self._have_probe_capabilities = True

    # Usually when we call a debug sequence, we first check if the sequence exists. For the below
    # methods, we rely on .call_pre_discovery_debug_sequence() to do this for us.
    def connect_debug_port_hook(self) -> Optional[bool]:
        from .coresight_target import CoreSightTarget
        cst = cast(CoreSightTarget, self.session.target)
        return cst.call_pre_discovery_debug_sequence('DebugPortSetup')

    def enable_debug_port_hook(self) -> Optional[bool]:
        from .coresight_target import CoreSightTarget
        cst = cast(CoreSightTarget, self.session.target)
        return cst.call_pre_discovery_debug_sequence('DebugPortStart')

    def disable_debug_port_hook(self) -> Optional[bool]:
        from .coresight_target import CoreSightTarget
        cst = cast(CoreSightTarget, self.session.target)
        return cst.call_pre_discovery_debug_sequence('DebugPortStop')

    def _connect(self) -> None:
        # Connect the probe.
        probe_conn = ProbeConnector(self.probe)
        probe_conn.connect(self._protocol)

        # Attempt to connect DP.
        connector = DPConnector(self.probe)
        if not self.connect_debug_port_hook():
            connector.connect()
            self.dpidr = connector.idr
        else:
            # We still need to read the IDR for our own use.
            self.dpidr = connector.read_idr()
        assert self.dpidr

        # Report on DP version.
        LOG.log(logging.INFO if self._log_dp_info else logging.DEBUG,
            "DP IDR = 0x%08x (v%d%s rev%d)", self.dpidr.idr, self.dpidr.version,
            " MINDP" if self.dpidr.mindp else "", self.dpidr.revision)

    def _check_version(self) -> None:
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

    @overload
    def read_reg(self, addr: int) -> int:
        ...

    @overload
    def read_reg(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read_reg(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read_reg(self, addr: int, now: bool) -> Union[int, Callable[[], int]]:
        ...

    def read_reg(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        return self.read_dp(addr, now)

    def write_reg(self, addr: int, data: int) -> None:
        self.write_dp(addr, data)

    def power_up_debug(self) -> bool:
        """@brief Assert DP power requests.

        Request both debug and system power be enabled, and wait until the request is acked.
        There is a timeout for the request.

        @return Boolean indicating whether the power up request succeeded.
        """
        if self.enable_debug_port_hook():
            return True

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

    def power_down_debug(self) -> bool:
        """@brief Deassert DP power requests.

        ADIv6 says that we must not clear CSYSPWRUPREQ and CDBGPWRUPREQ at the same time.
        ADIv5 says CSYSPWRUPREQ must not be set to 1 while CDBGPWRUPREQ is set to 0. So we
        start with deasserting system power, then debug power. Each deassertion has its own
        timeout.

        @return Boolean indicating whether the power down request succeeded.
        """
        if self.disable_debug_port_hook():
            return True

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

    def _invalidate_cache(self) -> None:
        """@brief Invalidate cached DP registers."""
        self._cached_dp_select = None

    def _reset_did_occur(self, notification: Notification) -> None:
        """@brief Handles reset notifications to invalidate register cache.

        The cache is cleared on all resets just to be safe. On most devices, warm resets do not reset
        debug logic, but it does happen on some devices.
        """
        self._invalidate_cache()

    def post_reset_recovery(self) -> None:
        """@brief Wait for the target to recover from reset, with auto-reconnect if needed."""
        # Check if we can access DP registers. If this times out, then reconnect the DP and retry.
        with Timeout(self.session.options.get('reset.dap_recover.timeout'),
                self._RESET_RECOVERY_SLEEP_INTERVAL) as time_out:
            attempt = 0
            while time_out.check():
                try:
                    # Try to read CTRL/STAT. If the power-up bits request are reset, then the DP
                    # connection was not lost and we can just return.
                    value = self.read_reg(DP_CTRL_STAT)
                    if (value & (CSYSPWRUPREQ | CDBGPWRUPREQ)) == (CSYSPWRUPREQ | CDBGPWRUPREQ):
                        return
                except exceptions.TransferError:
                    # Ignore errors caused by flushing.
                    try:
                        self.flush()
                    except exceptions.TransferError:
                        pass

                if attempt == self._RESET_RECOVERY_ATTEMPTS_BEFORE_RECONNECT:
                    LOG.info("DAP is not accessible after reset; attempting reconnect")
                elif attempt > self._RESET_RECOVERY_ATTEMPTS_BEFORE_RECONNECT:
                    # Try reconnect.
                    try:
                        self._log_dp_info = False
                        self.connect()
                    finally:
                        self._log_dp_info = True

                attempt += 1
            else:
                LOG.error("DAP is not accessible after reset followed by attempted reconnect")

    def reset(self, *, send_notifications: bool = True) -> None:
        """@brief Hardware reset.

        Pre- and post-reset notifications are sent.

        This method can be called before the DebugPort is connected.

        @param self This object.
        @param send_notifications Optional keyword-only parameter used by higher-level reset methods so they can
            manage the sending of reset notifications themselves, in order to provide more context in the notification.

        @todo Should automatic recovery from a disconnected DAP be provided for these low-level hardware resets
            like is done for CortexM.reset()?
        """
        if send_notifications:
            self.session.notify(Target.Event.PRE_RESET, self)

        self.probe.reset()
        self.post_reset_recovery()

        if send_notifications:
            self.session.notify(Target.Event.POST_RESET, self)

    def assert_reset(self, asserted: bool, *, send_notifications: bool = True) -> None:
        """@brief Assert or deassert the hardware reset signal.

        A pre-reset notification is sent before asserting reset, whereas a post-reset notification is sent
        after deasserting reset.

        This method can be called before the DebugPort is connected.

        @param self This object.
        @param asserted True if nRESET is to be driven low; False will drive nRESET high.
        @param send_notifications Optional keyword-only parameter used by higher-level reset methods so they can
            manage the sending of reset notifications themselves, in order to provide more context in the notification.
        """
        is_asserted = False
        if send_notifications:
            is_asserted = self.is_reset_asserted()
            if asserted and not is_asserted:
                self.session.notify(Target.Event.PRE_RESET, self)

        self.probe.assert_reset(asserted)

        if send_notifications and not asserted and is_asserted:
            self.session.notify(Target.Event.POST_RESET, self)

    def is_reset_asserted(self) -> bool:
        """@brief Returns the current state of the nRESET signal.

        This method can be called before the DebugPort is initalized.

        @retval True Reset is asserted; nRESET is low.
        @retval False Reset is not asserted; nRESET is high.
        """
        return self.probe.is_reset_asserted()

    def set_clock(self, frequency: float) -> None:
        """@brief Change the wire protocol's clock frequency.
        @param self This object.
        @param frequency New wire protocol frequency in Hertz.
        """
        self.probe.set_clock(frequency)

    def _write_dp_select(self, mask: int, value: int) -> None:
        """@brief Modify part of the DP SELECT register and write if cache is stale.

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

    def _set_dpbanksel(self, addr: int, is_write: bool) -> bool:
        """@brief Updates the DPBANKSEL field of the SELECT register as required.

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

    @overload
    def read_dp(self, addr: int) -> int:
        ...

    @overload
    def read_dp(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read_dp(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read_dp(self, addr: int, now: bool) -> Union[int, Callable[[], int]]:
        ...

    def read_dp(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
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
        def read_dp_cb() -> int:
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

    def write_dp(self, addr: int, data: int) -> None:
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

    def _select_ap(self, addr: int) -> bool:
        """@brief Write DP_SELECT to choose the given AP.

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

    def write_ap(self, addr: int, data: int) -> None:
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

    @overload
    def read_ap(self, addr: int) -> int:
        ...

    @overload
    def read_ap(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read_ap(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read_ap(self, addr: int, now: bool) -> Union[int, Callable[[], int]]:
        ...

    def read_ap(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
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
        def read_ap_cb() -> int:
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

    def write_ap_multiple(self, addr: int, values: Sequence[int]) -> None:
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

    @overload
    def read_ap_multiple(self, addr: int, count: int = 1) -> Sequence[int]:
        ...

    @overload
    def read_ap_multiple(self, addr: int, count: int, now: Literal[True] = True) -> Sequence[int]:
        ...

    @overload
    def read_ap_multiple(self, addr: int, count: int, now: Literal[False]) -> Callable[[], Sequence[int]]:
        ...

    @overload
    def read_ap_multiple(self, addr: int, count: int, now: bool) -> Union[Sequence[int], Callable[[], Sequence[int]]]:
        ...

    def read_ap_multiple(self, addr: int, count: int = 1, now: bool = True) \
             -> Union[Sequence[int], Callable[[], Sequence[int]]]:
        assert isinstance(addr, int)
        num = self.next_access_number
        did_lock = False

        try:
            did_lock = self._select_ap(addr)
            TRACE.debug("read_ap_multiple:%06d (addr=0x%08x, count=%i)", num, addr, count)
            result_cb = self.probe.read_ap_multiple(addr, count, now=False)
        except exceptions.TargetError as error:
            self._handle_error(error, num)
            if did_lock:
                self.unlock()
            raise
        except Exception:
            if did_lock:
                self.unlock()
            raise

        # Need to wrap the deferred callback to convert exceptions.
        def read_ap_multiple_cb() -> Sequence[int]:
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

    def _handle_error(self, error: Exception, num: int) -> None:
        TRACE.debug("error:%06d %s", num, error)
        # Clear sticky error for fault errors.
        if isinstance(error, exceptions.TransferFaultError):
            self.clear_sticky_err()
        # For timeouts caused by WAIT responses, set DAPABORT to abort the transfer.
        elif isinstance(error, exceptions.TransferTimeoutError):
            # This may put the AP that was aborted into an unpredictable state. Should consider
            # attempting to reset debug logic.
            self.write_reg(DP_ABORT, ABORT_DAPABORT)

    def clear_sticky_err(self) -> None:
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
    """@brief Memory interface for performing simple APACC transactions.

    This class allows the caller to generate Debug APB transactions from a DPv3. It simply
    adapts the MemoryInterface to APACC transactions.

    By default, it passes memory transaction addresses unmodified to the DP. But an instance can be
    constructed by passing an APAddress object to the constructor that offsets transaction addresses
    so they are relative to the APAddress base.

    Only 32-bit transfers are supported.
    """

    def __init__(self, dp: DebugPort, ap_address: Optional[APAddressBase] = None) -> None:
        """@brief Constructor.

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
    def dp(self) -> DebugPort:
        return self._dp

    @property
    def short_description(self) -> str:
        if self._ap_address is None:
            return "Root Component"
        else:
            return "Root Component ({})".format(self._ap_address)

    def write_memory(self, addr: int, data: int, transfer_size: int = 32) -> None:
        """@brief Write a single memory location.

        By default the transfer size is a word."""
        if transfer_size != 32:
            raise exceptions.DebugError("unsupported transfer size")

        return self._dp.write_ap(self._offset + addr, data)

    @overload
    def read_memory(self, addr: int, transfer_size: int) -> int:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: bool) -> Union[int, Callable[[], int]]:
        ...

    def read_memory(self, addr: int, transfer_size: int = 32, now: bool = True) -> Union[int, Callable[[], int]]:
        """@brief Read a memory location.

        By default, a word will be read."""
        if transfer_size != 32:
            raise exceptions.DebugError("unsupported transfer size")

        return self._dp.read_ap(self._offset + addr, now)

    def write_memory_block32(self, addr: int, data: Sequence[int]) -> None:
        """@brief Write an aligned block of 32-bit words."""
        addr += self._offset
        for word in data:
            self._dp.write_ap(addr, word)
            addr += 4

    def read_memory_block32(self, addr: int, size: int) -> Sequence[int]:
        """@brief Read an aligned block of 32-bit words."""
        addr += self._offset
        result_cbs = [self._dp.read_ap(addr + i * 4, now=False) for i in range(size)]
        result = [cb() for cb in result_cbs]
        return result

