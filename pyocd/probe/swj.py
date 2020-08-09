# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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

from ..probe.debug_probe import DebugProbe

LOG = logging.getLogger(__name__)

class SWJSequenceSender(object):
    """! @brief Class to send canned SWJ sequences."""

    def __init__(self, probe, use_dormant):
        self._probe = probe
        self._use_dormant = use_dormant
    
    @property
    def use_dormant(self):
        return self._use_dormant
    
    @use_dormant.setter
    def use_dormant(self, flag):
        self._use_dormant = flag

    def select_protocol(self, protocol):
        """! @brief Send SWJ sequence to select chosen wire protocol."""
        # Not all probes support sending SWJ sequences.
        assert isinstance(protocol, DebugProbe.Protocol)
        if protocol == DebugProbe.Protocol.SWD:
            self._switch_to_swd()
        elif protocol == DebugProbe.Protocol.JTAG:
            self._switch_to_jtag()

    def _switch_to_swd(self):
        """! @brief Send SWJ sequence to select SWD."""
        if self._use_dormant:
            LOG.debug("Sending SWJ sequence to select SWD; using dormant state")
            
            # Ensure current debug interface is in reset state
            self._probe.swj_sequence(51, 0xffffffffffffff)
            
            # Send all this in one transfer:
            # Select Dormant State (from JTAG), 0xb3bbbbbaff
            # 8 cycles SWDIO/TMS HIGH, 0xff
            # Alert Sequence, 0x19bc0ea2e3ddafe986852d956209f392
            # 4 cycles SWDIO/TMS LOW + 8-Bit SWD Activation Code (0x1A), 0x01a0
            self._probe.swj_sequence(188, 0x01a019bc0ea2e3ddafe986852d956209f392ffb3bbbbbaff)
           
            # Enter SWD Line Reset State
            self._probe.swj_sequence(51, 0xffffffffffffff)  # > 50 cycles SWDIO/TMS High
            self._probe.swj_sequence(8,  0x00)                # At least 2 idle cycles (SWDIO/TMS Low)
        else:
            LOG.debug("Sending deprecated SWJ sequence to select SWD")
            
            # Ensure current debug interface is in reset state
            self._probe.swj_sequence(51, 0xffffffffffffff)
            
            # Execute SWJ-DP Switch Sequence JTAG to SWD (0xE79E)
            # Change if SWJ-DP uses deprecated switch code (0xEDB6)
            self._probe.swj_sequence(16, 0xe79e)
            
            # Enter SWD Line Reset State
            self._probe.swj_sequence(51, 0xffffffffffffff)  # > 50 cycles SWDIO/TMS High
            self._probe.swj_sequence(8,  0x00)                # At least 2 idle cycles (SWDIO/TMS Low)
    
    def _switch_to_jtag(self):
        """! @brief Send SWJ sequence to select JTAG."""
        if self._use_dormant:
            LOG.debug("Sending SWJ sequence to select JTAG ; using dormant state")
            
            # Ensure current debug interface is in reset state
            self._probe.swj_sequence(51, 0xffffffffffffff)
            
            # Select Dormant State (from SWD)
            # At least 8 cycles SWDIO/TMS HIGH, 0xE3BC
            # Alert Sequence, 0x19bc0ea2e3ddafe986852d956209f392
            # 4 cycles SWDIO/TMS LOW + 8-Bit JTAG Activation Code (0x0A), 0x00a0
            self._probe.swj_sequence(188, 0x00a019bc0ea2e3ddafe986852d956209f392ffe3bc)
           
            # Ensure JTAG interface is reset
            self._probe.swj_sequence(6, 0x3f)
        else:
            LOG.debug("Sending deprecated SWJ sequence to select JTAG")
            
            # Ensure current debug interface is in reset state
            self._probe.swj_sequence(51, 0xffffffffffffff)
            
            # Execute SWJ-DP Switch Sequence SWD to JTAG (0xE73C)
            # Change if SWJ-DP uses deprecated switch code (0xAEAE)
            self._probe.swj_sequence(16, 0xe73c)
            
            # Ensure JTAG interface is reset
            self._probe.swj_sequence(6, 0x3f)
    
