# pyOCD debugger
# Copyright (c) 2021-2022 Chris Reed
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
from time import sleep
from typing import (cast, Dict, TYPE_CHECKING)

from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.ap import (APAddressBase, APv1Address, AccessPort, MEM_AP)
from ...probe.debug_probe import DebugProbe
from .delegates import DebugSequenceFunctionsDelegate
from .sequences import DebugSequenceRuntimeError

if TYPE_CHECKING:
    from ...coresight.dap import DebugPort

LOG = logging.getLogger(__name__)

# Disable warnings for the non-standard methods names we use to match the sequences function
# names, since introspection is used to look up functions.
# pylint: disable=invalid_name

class DebugSequenceCommonFunctions(DebugSequenceFunctionsDelegate):
    """@brief Implements functions provided by the debug sequence environment."""

    APSEL_SHIFT = 24

    DP_ABORT = 0x00

    def __init__(self) -> None:
        self._ap_cache: Dict[APAddressBase, MEM_AP] = {}

    @property
    def target(self) -> CoreSightTarget:
        return cast(CoreSightTarget, self.context.session.target)

    def _get_ap_addr(self) -> APAddressBase:
        """@brief Return the AP address selected by __ap or __apid variables.

        If the DFP uses apids then the `__apid` variable takes precedence. Otherwise the `__ap` variable
        is used.
        """
        pack_device = self.context.delegate.cmsis_pack_device

        if pack_device.uses_apid:
            apid = self.context.get_variable('__apid')
            try:
                ap_addr = pack_device.apid_map[apid]
            except KeyError:
                raise DebugSequenceRuntimeError(f"__apid has invalid value ({apid})")
        else:
            # The __ap variable is only used to reference v1 APs.
            # TODO handle __dp being non-zero, when we support multiple DPs.
            ap_addr = APv1Address(self.context.get_variable('__ap'))

            dp_num = self.context.get_variable('__dp')
            if dp_num != 0:
                raise DebugSequenceRuntimeError(f"currently only __dp==0 is supported ({dp_num} specified)")

        return ap_addr

    def _get_mem_ap(self) -> MEM_AP:
        """@brief Return the current MEM_AP object.

        Normally, the AP object created during discovery is returned from the target's dict of APs. However,
        sequences can be run prior to discovery, and are allowed to perform memory acceses. Therefore we must
        handle the case of there not being a readily available AP object by creating a temporary one here.

        A cache dict is used to prevent repeatedly recreating the same AP when multiple memory transfers
        appear in a sequence. The cache is _only_ used for temporary AP objects; the target's AP dict always
        takes priority and is checked first.
        """
        ap_addr = self._get_ap_addr()

        # Try to get an existing AP from the target.
        try:
            ap = self.target.aps[ap_addr]
            if not isinstance(ap, MEM_AP):
                raise DebugSequenceRuntimeError(f"AP at address {ap_addr} is not a MEM-AP")
            return ap
        except KeyError:
            pass

        # The AP doesn't exist or we haven't performed discovery yet, but we still need to support memory
        # transfers for debug sequences. So attempt to create a temporary one.
        # TODO can this only be done prior to discovery?

        # Check if we have already created and cached this AP.
        try:
            return self._ap_cache[ap_addr]
        except KeyError:
            pass

        # Haven't encountered this AP yet. Create and cache it.
        # This call will raise exceptions.TargetError if there is no AP with the requested address.
        ap = AccessPort.create(self.target.dp, ap_addr)

        # Make sure this is a MEM-AP.
        if not isinstance(ap, MEM_AP):
            raise DebugSequenceRuntimeError(f"AP at address {ap_addr} is not a MEM-AP")

        # Save in the cache.
        self._ap_cache[ap_addr] = ap

        return ap

    def _get_dp(self, ignore_apid: bool = False) -> DebugPort:
        """@brief Get the DebugPort object specified by the __dp or __apid variable."""
        pack_device = self.context.delegate.cmsis_pack_device
        if not pack_device.uses_apid or ignore_apid:
            dp_num = self.context.get_variable('__dp')
        else:
            apid = self.context.get_variable('__apid')
            try:
                ap_addr = pack_device.apid_map[apid]
            except KeyError:
                raise DebugSequenceRuntimeError(f"__apid has invalid value ({apid})")
            else:
                dp_num = ap_addr.dp_index

        if dp_num != 0:
            raise DebugSequenceRuntimeError(f"currently only __dp==0 is supported ({dp_num} specified)")

        # In any case, for now we always return the only DebugPort object we have.
        return self.target.dp

    def _get_ignore_errors(self) -> bool:
        """@brief Whether the debug sequence has set __errorcontrol to ignore faults."""
        errcontrol = self.context.get_variable('__errorcontrol')
        return (errcontrol & 1) == 1

    def sequence(self, name: str) -> None:
        # This call will raise if the named sequence is invalid. However, we should have already
        # verified the sequence name is valid during semantic checking.
        #
        # The pname from the current context is passed in order to match a pname-specific
        # sequence; a matching sequence with no pname will also be found.
        seq = self.context.delegate.get_sequence_with_name(name, pname=self.context.pname)

        if self.context.pname:
            LOG.debug("Running debug sub-sequence '%s' (%s)", name, self.context.pname)
        else:
            LOG.debug("Running debug sub-sequence '%s'", name)

        # Run the sequence.
        subsequence_scope = seq.execute(self.context)

        # Copy the result to parent sequence.
        if subsequence_scope is not None:
            result_value = subsequence_scope.get('__Result')
            LOG.debug("Sub-sequence '%s' result = %d", name, result_value)
            self.context.current_scope.set('__Result', result_value)

    def read8(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read8(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read8(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def read16(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read16(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read16(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def read32(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read32(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read32(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def read64(self, addr: int) -> int:
        try:
            return self._get_mem_ap().read64(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Read64(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def readap(self, addr: int) -> int:
        try:
            ap_addr = self._get_ap_addr()
            reg_addr = ap_addr.address | addr
            return self._get_dp().read_ap(reg_addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("ReadAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def readaccessap(self, addr: int) -> int:
        try:
            dp = self._get_dp(True)
            apacc = dp.apacc_memory_interface
            return apacc.read32(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("ReadAccessAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def readdp(self, addr: int) -> int:
        try:
            return self._get_dp(True).read_dp(addr)
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("ReadDP(%#010x) ignored %r because __errorcontrol is set", addr, err)
                return 0
            else:
                raise

    def write8(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write8(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write8(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def write16(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write16(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write16(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def write32(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write32(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write32(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def write64(self, addr: int, val: int) -> None:
        try:
            self._get_mem_ap().write64(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("Write64(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def writeap(self, addr: int, val: int) -> None:
        try:
            ap_addr = self._get_ap_addr()
            reg_addr = ap_addr.address | addr
            self._get_dp().write_ap(reg_addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("WriteAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def writeaccessap(self, addr: int, val: int) -> None:
        try:
            dp = self._get_dp(True)
            apacc = dp.apacc_memory_interface
            apacc.write32(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("WriteAccessAP(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def writedp(self, addr: int, val: int) -> None:
        try:
            self._get_dp(True).write_dp(addr, val)
            self.target.flush()
        except exceptions.TransferError as err:
            if self._get_ignore_errors():
                LOG.debug("WriteDP(%#010x) ignored %r because __errorcontrol is set", addr, err)
            else:
                raise

    def flashbufferwrite(self, addr: int, offset: int, length: int, mode: int) -> None:
        raise NotImplementedError()

    def dap_delay(self, delay: int) -> None:
        # Flush before sleeping, in case there are any outstanding transactions.
        self.target.flush()

        # TODO This is really expected to be sent to the target via the CMSIS-DAP command, but for most
        # cases this will work fine. However, it would fail for atomic sequences.
        sleep(delay / 1e6)

    def dap_writeabort(self, value: int) -> None:
        assert self.context.session.probe
        mode = self.context.session.probe.wire_protocol
        if mode == DebugProbe.Protocol.SWD:
            self._get_dp().write_reg(self.DP_ABORT, value)
        elif mode == DebugProbe.Protocol.JTAG:
            # TODO support jtag abort
            self._get_dp().write_reg(self.DP_ABORT, value)
        self.target.flush()

    def dap_swj_pins(self, pinout: int, pinselect: int, pinwait: int) -> int:
        """
        Pin bits:
        - Bit 0: SWCLK/TCK
        - Bit 1: SWDIO/TMS
        - Bit 2: TDI
        - Bit 3: TDO
        - Bit 5: nTRST
        - Bit 7: nRESET

        Must return 0xFFFFFFFF if the pins cannot be read.
        """
        from ...probe.cmsis_dap_probe import CMSISDAPProbe

        probe = self.context.session.probe
        assert probe
        if DebugProbe.Capability.PIN_ACCESS not in probe.capabilities:
            return 0xFFFFFFFF

        # Write pins if any were selected to be modified, wait if needed, then read
        # all available pins.
        if pinselect != 0:
            probe.write_pins(DebugProbe.PinGroup.PROTOCOL_PINS,
                    CMSISDAPProbe.from_cmsis_dap_pins(pinselect),
                    CMSISDAPProbe.from_cmsis_dap_pins(pinout))
        if pinwait > 0:
            sleep(pinwait / 1e9)
        result = CMSISDAPProbe.to_cmsis_dap_pins(
                probe.read_pins(DebugProbe.PinGroup.PROTOCOL_PINS,
                                DebugProbe.ProtocolPin.ALL_PINS))

        return result

    def dap_swj_clock(self, val: int) -> None:
        assert self.context.session.probe
        self.context.session.probe.set_clock(val)

    def dap_swj_sequence(self, cnt: int, val: int) -> None:
        probe = self.context.session.probe
        assert probe
        if DebugProbe.Capability.SWJ_SEQUENCE not in probe.capabilities:
            raise DebugSequenceRuntimeError(
                    "debug sequence called DAP_SWJ_Sequence, but debug probe does not support this operation")
        probe.swj_sequence(cnt, val)

    def dap_jtag_sequence(self, cnt: int, tms: int, tdi: int) -> int:
        probe = self.context.session.probe
        assert probe
        if DebugProbe.Capability.JTAG_SEQUENCE not in probe.capabilities:
            raise DebugSequenceRuntimeError(
                "debug sequence called DAP_JTAG_Sequence, but debug probe does not support this operation")
        tdo = probe.jtag_sequence(cnt, tms, True, tdi)
        return tdo or 0

    def query(self, type: int, message: str, default: int) -> int:
        LOG.info(f"Query({type}): {message} [{default}]")
        # Just return the default value since we're running in "batch" mode.
        return default

    def queryvalue(self, message: str, default: int) -> int:
        LOG.info(f"QueryValue: {message} [{default}]")
        # Just return the default value since we're running in "batch" mode.
        return default

    _MESSAGE_LEVEL_MAP = {
        0: logging.INFO,
        1: logging.WARNING,
        2: logging.ERROR,
    }
    def message(self, type: int, format: str, *args: int) -> None:
        level = self._MESSAGE_LEVEL_MAP.get(type, 2) # default to error for invalid type
        LOG.log(level, format % args)

    def loaddebuginfo(self, file: str) -> int:
        # Return 1 to indicate failure.
        return 1

# pylint: enable=invalid_name
