# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

from .cortex_m import CortexM
from .core_ids import (CORE_TYPE_NAME, CoreArchitecture, CortexMExtension)
from ..core.target import Target
from .cortex_m_core_registers import CoreRegisterGroups

LOG = logging.getLogger(__name__)

class CortexM_v8M(CortexM):
    """! @brief Component class for a v8.x-M architecture Cortex-M core."""

    ARMv8M_BASE = 0xC
    ARMv8M_MAIN = 0xF

    ## DFSR.PMU added in v8.1-M.
    DFSR_PMU = (1 << 5)
    
    DSCSR = 0xE000EE08
    DSCSR_CDSKEY = 0x00020000
    DSCSR_CDS = 0x00010000
    DSCSR_SBRSEL = 0x00000002
    DSCSR_SBRSELEN = 0x00000001
    
    # Processor Feature Register 1
    PFR1 = 0xE000ED44
    PFR1_SECURITY_MASK = 0x000000f0
    PFR1_SECURITY_SHIFT = 4
    
    PFR1_SECURITY_EXT_V8_0 = 0x1 # Base security extension.
    PFR1_SECURITY_EXT_V8_1 = 0x3 # v8.1-M adds several instructions.

    # Media and FP Feature Register 1
    MVFR1 = 0xE000EF44
    MVFR1_MVE_MASK = 0x00000f00
    MVFR1_MVE_SHIFT = 8
    MVFR1_MVE__INTEGER = 0x1
    MVFR1_MVE__FLOAT = 0x2

    def __init__(self, rootTarget, ap, memory_map=None, core_num=0, cmpid=None, address=None):
        super(CortexM_v8M, self).__init__(rootTarget, ap, memory_map, core_num, cmpid, address)

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
            return (Target.SecurityState.NONSECURE,)

    def _read_core_type(self):
        """! @brief Read the CPUID register and determine core type and architecture."""
        # Read CPUID register
        cpuid = self.read32(CortexM.CPUID)

        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        if implementer != CortexM.CPUID_IMPLEMENTER_ARM:
            LOG.warning("CPU implementer is not ARM!")

        arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        
        self.cpu_revision = (cpuid & CortexM.CPUID_VARIANT_MASK) >> CortexM.CPUID_VARIANT_POS
        self.cpu_patch = (cpuid & CortexM.CPUID_REVISION_MASK) >> CortexM.CPUID_REVISION_POS
        
        pfr1 = self.read32(self.PFR1)
        pfr1_sec = ((pfr1 & self.PFR1_SECURITY_MASK) >> self.PFR1_SECURITY_SHIFT)
        self.has_security_extension = pfr1_sec in (self.PFR1_SECURITY_EXT_V8_0, self.PFR1_SECURITY_EXT_V8_1)
        if self.has_security_extension:
            self._extensions.append(CortexMExtension.SEC)
        if pfr1_sec == self.PFR1_SECURITY_EXT_V8_1:
            self._extensions.append(CortexMExtension.SEC_V81)
        
        if arch == self.ARMv8M_BASE:
            self._architecture = CoreArchitecture.ARMv8M_BASE
        else:
            self._architecture = CoreArchitecture.ARMv8M_MAIN
        
        if self.core_type in CORE_TYPE_NAME:
            if self.has_security_extension:
                LOG.info("CPU core #%d is %s r%dp%d (security ext present)", self.core_number, CORE_TYPE_NAME[self.core_type], self.cpu_revision, self.cpu_patch)
            else:
                LOG.info("CPU core #%d is %s r%dp%d", self.core_number, CORE_TYPE_NAME[self.core_type], self.cpu_revision, self.cpu_patch)
        else:
            LOG.warning("CPU core #%d type is unrecognized", self.core_number)

    def _check_for_fpu(self):
        """! @brief Determine if a core has an FPU.
        
        In addition to the tests performed by CortexM, this method tests for the MVE extension.
        """
        super(CortexM_v8M, self)._check_for_fpu()
        
        # Check for MVE.
        mvfr1 = self.read32(self.MVFR1)
        mve = (mvfr1 & self.MVFR1_MVE_MASK) >> self.MVFR1_MVE_SHIFT
        if mve == self.MVFR1_MVE__INTEGER:
            self._extensions.append(CortexMExtension.MVE)
        elif mve == self.MVFR1_MVE__FLOAT:
            self._extensions += [CortexMExtension.MVE, CortexMExtension.MVE_FP]

    def _build_registers(self):
        super(CortexM_v8M, self)._build_registers()
        
        # Registers available with Security extension, either Baseline or Mainline.
        if self.has_security_extension:
            self._core_registers.add_group(CoreRegisterGroups.V8M_SEC_ONLY)

        # Mainline-only registers.
        if self.architecture == CoreArchitecture.ARMv8M_MAIN:
            self._core_registers.add_group(CoreRegisterGroups.V7M_v8M_ML_ONLY)
        
            # Registers available when both Mainline and Security extensions are implemented.
            if self.has_security_extension:
                self._core_registers.add_group(CoreRegisterGroups.V8M_ML_SEC_ONLY)
        
        # MVE registers.
        if CortexMExtension.MVE in self.extensions:
            self._core_registers.add_group(CoreRegisterGroups.V81M_MVE_ONLY)
        
    def get_security_state(self):
        """! @brief Returns the current security state of the processor.
        
        @return @ref pyocd.core.target.Target.SecurityState "Target.SecurityState" enumerator.
        """
        dscsr = self.read32(self.DSCSR)
        if (dscsr & self.DSCSR_CDS) != 0:
            return Target.SecurityState.SECURE
        else:
            return Target.SecurityState.NONSECURE

    def clear_debug_cause_bits(self):
        self.write32(CortexM.DFSR,
                self.DFSR_PMU
                | CortexM.DFSR_EXTERNAL
                | CortexM.DFSR_VCATCH
                | CortexM.DFSR_DWTTRAP
                | CortexM.DFSR_BKPT
                | CortexM.DFSR_HALTED)
    
    def get_halt_reason(self):
        """! @brief Returns the reason the core has halted.
        
        This overridden version of this method adds support for v8.x-M halt reasons.
        
        @return @ref pyocd.core.target.Target.HaltReason "Target.HaltReason" enumerator or None.
        """
        dfsr = self.read32(self.DFSR)
        if dfsr & self.DFSR_HALTED:
            reason = Target.HaltReason.DEBUG
        elif dfsr & self.DFSR_BKPT:
            reason = Target.HaltReason.BREAKPOINT
        elif dfsr & self.DFSR_DWTTRAP:
            reason = Target.HaltReason.WATCHPOINT
        elif dfsr & self.DFSR_VCATCH:
            reason = Target.HaltReason.VECTOR_CATCH
        elif dfsr & self.DFSR_EXTERNAL:
            reason = Target.HaltReason.EXTERNAL
        elif dfsr & self.DFSR_PMU:
            reason = Target.HaltReason.PMU
        else:
            reason = None
        return reason

