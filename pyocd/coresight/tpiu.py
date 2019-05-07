# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

from .component import CoreSightComponent

class TPIU(CoreSightComponent):
    """! @brief Trace Port Interface Unit"""

    # Register definitions.
    #
    # The addresses are offsets from the base address.
    ACPR = 0x00000010
    ACPR_PRESCALER_MASK = 0x0000ffff

    SPPR = 0x000000f0
    SPPR_TXMODE_MASK = 0x00000003
    SPPR_TXMODE_NRZ = 0x00000002

    FFCR = 0x00000304
    FFCR_ENFCONT_MASK = (1 << 1)

    DEVID = 0x00000fc8
    DEVID_NRZ_MASK = (1 << 11)

    def __init__(self, ap, cmpid=None, addr=None):
        """! @brief Standard CoreSight component constructor."""
        super(TPIU, self).__init__(ap, cmpid, addr)
        self._has_swo_uart = False
    
    @property
    def has_swo_uart(self):
        """! @brief Whether SWO UART mode is supported by the TPIU."""
        return self._has_swo_uart

    def init(self):
        """! @brief Reads TPIU capabilities.
        
        Currently this method simply checks whether the TPIU supports SWO in asynchronous
        UART mode. The result of this check is available via the has_swo_uart property.
        """
        devid = self.ap.read32(self.address + TPIU.DEVID)
        self._has_swo_uart = (devid & TPIU.DEVID_NRZ_MASK) != 0
        
    def set_swo_clock(self, swo_clock, system_clock):
        """! @brief Prepare TPIU for transmitting SWO at a given baud rate.
        
        Configures the TPIU for SWO UART mode, then sets the SWO clock frequency based on
        the provided system clock.
        
        @param self
        @param swo_clock Desired SWO baud rate in Hertz.
        @param system_clock The frequency of the SWO clock source in Hertz. This is almost always
            the system clock, also called the HCLK or fast clock.
        @return Boolean indicating if SWO UART mode could be configured with the requested
            baud rate set within 3%.
        """
        # First check whether SWO UART is supported.
        if not self.has_swo_uart:
            return False
            
        # Go ahead and configure for SWO.
        self.ap.write32(self.address + TPIU.SPPR, TPIU.SPPR_TXMODE_NRZ) # Select SWO UART mode.
        self.ap.write32(self.address + TPIU.FFCR, 0) # Disable formatter.
    
        # Compute the divider.
        div = (system_clock // swo_clock) - 1
        actual = system_clock // (div + 1)
        deltaPercent = abs(swo_clock - actual) / swo_clock
        # Make sure the target baud rate was met with 3%.
        if deltaPercent > 0.03:
            return False
        self.ap.write32(self.address + TPIU.ACPR, div & TPIU.ACPR_PRESCALER_MASK)
        return True


