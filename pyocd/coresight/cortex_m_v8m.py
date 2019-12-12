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

from .cortex_m import CortexM
from .core_ids import CORE_TYPE_NAME
from ..core import exceptions
from ..core.target import Target

LOG = logging.getLogger(__name__)

class CortexM_v8M(CortexM):
    """! @brief Component class for a v8-M architecture Cortex-M core."""

    ARMv8M_BASE = 0xC
    ARMv8M_MAIN = 0xF
    
    DSCSR = 0xE000EE08
    DSCSR_CDSKEY = 0x00020000
    DSCSR_CDS = 0x00010000
    DSCSR_SBRSEL = 0x00000002
    DSCSR_SBRSELEN = 0x00000001
    
    # Processor Feature Register 1
    PFR1 = 0xE000ED44
    PFR1_SECURITY_MASK = 0x000000f0
    PFR1_SECURITY_SHIFT = 4

    def __init__(self, rootTarget, ap, memoryMap=None, core_num=0, cmpid=None, address=None):
        super(CortexM_v8M, self).__init__(rootTarget, ap, memoryMap, core_num, cmpid, address)

        # Only v7-M supports VECTRESET.
        self._supports_vectreset = False
    
    @property
    def supported_security_states(self):
        """! @brief Tuple of security states supported by the processor.
        
        @return Tuple of @ref pyocd.core.target.Target.SecurityState "Target.SecurityState". The
            result depends on whether the Security extension is enabled.
        """
        if self.has_security_extension:
            return (Target.SecurityState.NONSECURE, Target.SecurityState.SECURE)
        else:
            return (Target.SecurityState.NONSECURE)

    def _read_core_type(self):
        """! @brief Read the CPUID register and determine core type and architecture."""
        # Read CPUID register
        cpuid = self.read32(CortexM.CPUID)

        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        if implementer != CortexM.CPUID_IMPLEMENTER_ARM:
            LOG.warning("CPU implementer is not ARM!")

        self.arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        
        self.cpu_revision = (cpuid & CortexM.CPUID_VARIANT_MASK) >> CortexM.CPUID_VARIANT_POS
        self.cpu_patch = (cpuid & CortexM.CPUID_REVISION_MASK) >> CortexM.CPUID_REVISION_POS
        
        pfr1 = self.read32(self.PFR1)
        self.has_security_extension = ((pfr1 & self.PFR1_SECURITY_MASK) >> self.PFR1_SECURITY_SHIFT) == 1
        
        if self.core_type in CORE_TYPE_NAME:
            if self.has_security_extension:
                LOG.info("CPU core #%d is %s r%dp%d (security ext present)", self.core_number, CORE_TYPE_NAME[self.core_type], self.cpu_revision, self.cpu_patch)
            else:
                LOG.info("CPU core #%d is %s r%dp%d", self.core_number, CORE_TYPE_NAME[self.core_type], self.cpu_revision, self.cpu_patch)
        else:
            LOG.warning("CPU core #%d type is unrecognized", self.core_number)
    
    def get_security_state(self):
        """! @brief Returns the current security state of the processor.
        
        @return @ref pyocd.core.target.Target.SecurityState "Target.SecurityState" enumerator.
        """
        dscsr = self.read32(self.DSCSR)
        if (dscsr & self.DSCSR_CDS) != 0:
            return Target.SecurityState.SECURE
        else:
            return Target.SecurityState.NONSECURE
        
