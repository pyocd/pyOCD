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

from .component import CoreSightComponent
from ..utility.timeout import Timeout

ACK_TIMEOUT = 5.0

## @brief Granular Power Requestor.
#
# Currently only supports enabling power domains.
class GPR(CoreSightComponent):
    CPWRUPREQ = 0x0
    CPWRUPACK = 0x0
    
    CPWRUPM_COUNT_MASK = 0x3f
    
    @classmethod
    def factory(cls, ap, cmpid, address):
        # Attempt to return the same instance that was created during ROM table scanning.
        rom_gpr = cmpid.parent_rom_table.gpr
        if rom_gpr is not None and rom_gpr.address == address:
            return rom_gpr
        
        # No luck, create a new instance.
        gpr = cls(ap, cmpid, address)
        return gpr

    def __init__(self, ap, cmpid=None, addr=None):
        super(GPR, self).__init__(ap, cmpid, addr)

    ## @brief Inits the GPR.
    def init(self):
        self.domain_count = self.cmpid.devid[2] & self.CPWRUPM_COUNT_MASK
    
    ## @brief Enable power to a power domaind by mask.
    # @param self
    # @param mask Bitmask of the domains to power up.
    # @retval True Requested domains were successfully powered on.
    # @return False Timeout waiting for power ack bit(s) to set.
    def _power_up(self, mask):
        # Enable power up request bits.
        self.ap.write32(self.address + self.CPWRUPREQ, mask)
        
        # Wait for ack bits to set.
        with Timeout(ACK_TIMEOUT) as t_o:
            while t_o.check():
                value = self.ap.read32(self.address + self.CPWRUPACK)
                if (value & mask) == mask:
                    return True
            else:
                return False
    
    ## @brief Enable power to all available power domains.
    # @param self
    # @retval True All domains were successfully powered on.
    # @return False Timeout waiting for power ack bit(s) to set.
    def power_up_all(self):
        mask = (1 << self.domain_count) - 1
        return self._power_up(mask)
    
    ## @brief Power up a single power domain by domain ID.
    # @param self
    # @param domain_id Integer power domain ID.
    # @retval True Requested domain was powered on successfully.
    # @return False Timeout waiting for power ack bit to set.
    def power_up_one(self, domain_id):
        mask = 1 << domain_id
        return self._power_up(mask)
    
    def __repr__(self):
        return "<GPR @ %x: count=%d>" % (id(self), self.domain_count)
        


