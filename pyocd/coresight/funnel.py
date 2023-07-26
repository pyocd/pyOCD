# pyOCD debugger
# Copyright (c) 2023 Protech Engineering
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

from .component import CoreSightComponent

LOG = logging.getLogger(__name__)

class TraceFunnel(CoreSightComponent):
    """@brief CoreSight Trace Funnel"""

    # Register definitions.
    #
    # The addresses are offsets from the base address.
    CSTF = 0x00000000
    CSTF_ENSX_MASK = 0xFF

    DEVID = 0x00000FC8
    DEVID_PORTCOUNT_MASK = 0xF

    def __init__(self, ap, cmpid=None, addr=None):
        """@brief Standard CoreSight component constructor."""
        super().__init__(ap, cmpid, addr)
        self._available_channels = 2

    @property
    def available_channels(self) -> int:
        """@brief Number of input ports connected to the funnel"""
        return self._available_channels

    def init(self) -> None:
        """@brief Reads Funnel connected channels and enables them all by default."""
        devid = self.ap.read32(self.address + TraceFunnel.DEVID)
        self._available_channels = devid & TraceFunnel.DEVID_PORTCOUNT_MASK
        self.enable()

    def set_enabled_channels(self, channels: int) -> bool:
        """@brief Sets the enabled Trace Funnel channels.

        @param channels Word describing the desired state for the funnel channels.
            Setting the n-th bit of this word high enables the corresponding n-th channel, setting it low disables it.
        """
        valid_channels_mask = 2**self.available_channels-1
        if channels & ~valid_channels_mask:
            LOG.warning(f"Trace Funnel: Trying to enable too many channels. Only {self.available_channels} channels are present")
            return False

        cstf = self.ap.read32(self.address + TraceFunnel.CSTF)
        cstf = cstf & ~TraceFunnel.CSTF_ENSX_MASK
        cstf = cstf | channels
        self.ap.write32(self.address + TraceFunnel.CSTF, cstf)

        return True

    def enable(self) -> None:
        """@brief Enables all channels"""
        self.set_enabled_channels(2**self.available_channels-1)

    def disable(self) -> None:
        """@brief Disables all channels"""
        self.set_enabled_channels(0x00)
