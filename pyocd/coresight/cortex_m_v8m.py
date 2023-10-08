# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

import logging

from .cortex_m import CortexM
from .core_ids import (CORE_TYPE_NAME, CoreArchitecture, CortexMExtension)
from ..core.target import Target
from .cortex_m_core_registers import CoreRegisterGroups

LOG = logging.getLogger(__name__)

class CortexM_v8M(CortexM):
    """@brief Component class for a v8.x-M architecture Cortex-M core."""

    ARMv8M_BASE = 0xC
    ARMv8M_MAIN = 0xF

    ## DFSR.PMU added in v8.1-M.
    DFSR_PMU = (1 << 5)

    DSCSR = 0xE000EE08
    DSCSR_CDSKEY = 0x00020000
    DSCSR_CDS = 0x00010000
    DSCSR_SBRSEL = 0x00000002
    DSCSR_SBRSELEN = 0x00000001

    # Processor Feature Register 0
    PFR0 = 0xE000ED40
    PFR0_RAS_MASK = 0xf0000000
    PFR0_RAS_SHIFT = 28
    PFR0_RAS_VERSION_1 = 2

    # Processor Feature Register 1
    PFR1 = 0xE000ED44
    PFR1_SECURITY_MASK = 0x000000f0
    PFR1_SECURITY_SHIFT = 4

    PFR1_SECURITY_EXT_V8_0 = 0x1 # Base security extension.
    PFR1_SECURITY_EXT_V8_1 = 0x3 # v8.1-M adds several instructions.

    # Debug Feature Register 0
    DFR0 = 0xE000ED48
    DFR0_UDE_MASK = 0xf0000000
    DFR0_UDE_SHIFT = 28
    DFR0_UDE_SUPPORTED = 1

    # Media and FP Feature Register 1
    MVFR1 = 0xE000EF44
    MVFR1_MVE_MASK = 0x00000f00
    MVFR1_MVE_SHIFT = 8
    MVFR1_MVE__INTEGER = 0x1
    MVFR1_MVE__FLOAT = 0x2
    MVFR1_FP16_MASK = 0x00f00000
    MVFR1_FP16_SHIFT = 20
    MVFR1_FP16__SUPPORTED = 0x1 # FP16 format support is present.

    # Instruction Set Attribute Register 0
    ISAR0 = 0xE000ED60
    ISAR0_CMPBRANCH_MASK = 0x0000f000
    ISAR0_CMPBRANCH_SHIFT = 12
    ISAR0_CMPBRANCH__LOB = 0x3 # LOB instructions from v8.1-M are present.

    # Instruction Set Attribute Register 5
    ISAR5 = 0xE000ED74
    ISAR5_PACBTI_MASK = 0x00f00000
    ISAR5_PACBTI_SHIFT = 20
    ISAR5_PACBTI__NONE = 0x0 # PACBTI is not present.

    # PMU Type register
    PMU_TYPE = 0xE0003E00
    PMU_TYPE_N_MASK  = 0x0000000f

    def __init__(self, rootTarget, ap, memory_map=None, core_num=0, cmpid=None, address=None):
        super().__init__(rootTarget, ap, memory_map, core_num, cmpid, address)

    @property
    def supported_security_states(self):
        """@brief Tuple of security states supported by the processor.

        @return Tuple of @ref pyocd.core.target.Target.SecurityState "Target.SecurityState". The
            result depends on whether the Security extension is enabled.
        """
        if self.has_security_extension:
            return (Target.SecurityState.NONSECURE, Target.SecurityState.SECURE)
        else:
            return (Target.SecurityState.NONSECURE,)

    def _read_core_type(self):
        """@brief Read the CPUID register and determine core type and architecture."""
        # Schedule deferred reads.
        cpuid_cb = self.read32(self.CPUID, now=False)
        pfr0_cb = self.read32(self.PFR0, now=False)
        pfr1_cb = self.read32(self.PFR1, now=False)
        dfr0_cb = self.read32(self.DFR0, now=False)
        isar0_cb = self.read32(self.ISAR0, now=False)
        isar3_cb = self.read32(self.ISAR3, now=False)
        isar5_cb = self.read32(self.ISAR5, now=False)
        pmu_type_cb = self.read32(self.PMU_TYPE, now=False)
        mpu_type_cb = self.read32(self.MPU_TYPE, now=False)

        # Read CPUID register
        cpuid = cpuid_cb()
        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        self.cpu_revision = (cpuid & CortexM.CPUID_VARIANT_MASK) >> CortexM.CPUID_VARIANT_POS
        self.cpu_patch = (cpuid & CortexM.CPUID_REVISION_MASK) >> CortexM.CPUID_REVISION_POS

        # Check for DSP extension
        isar3 = isar3_cb()
        isar3_simd = (isar3 & self.ISAR3_SIMD_MASK) >> self.ISAR3_SIMD_SHIFT
        if isar3_simd == self.ISAR3_SIMD__DSP:
            self._extensions.append(CortexMExtension.DSP)

        # Check for RAS extension.
        pfr0 = pfr0_cb()
        pfr0_ras = (pfr0 & self.PFR0_RAS_MASK) >> self.PFR0_RAS_SHIFT
        if pfr0_ras == self.PFR0_RAS_VERSION_1:
            self._extensions.append(CortexMExtension.RAS)

        # Check for the security extension.
        pfr1 = pfr1_cb()
        pfr1_sec = (pfr1 & self.PFR1_SECURITY_MASK) >> self.PFR1_SECURITY_SHIFT
        self.has_security_extension = pfr1_sec in (self.PFR1_SECURITY_EXT_V8_0, self.PFR1_SECURITY_EXT_V8_1)
        if self.has_security_extension:
            self._extensions.append(CortexMExtension.SEC)
        if pfr1_sec == self.PFR1_SECURITY_EXT_V8_1:
            self._extensions.append(CortexMExtension.SEC_V81)

        # Check for UDE extension.
        dfr0 = dfr0_cb()
        dfr0_ude = (dfr0 & self.DFR0_UDE_MASK) >> self.DFR0_UDE_SHIFT
        if dfr0_ude == self.DFR0_UDE_SUPPORTED:
            self._extensions.append(CortexMExtension.UDE)

        # Check for PACBTI extension.
        isar5 = isar5_cb()
        isar5_pacbti = (isar5 & self.ISAR5_PACBTI_MASK) >> self.ISAR5_PACBTI_SHIFT
        if isar5_pacbti != self.ISAR5_PACBTI__NONE:
            self._extensions.append(CortexMExtension.PACBTI)

        # Check for PMU extension.
        pmu_type = pmu_type_cb()
        pmu_type_n = pmu_type & self.PMU_TYPE_N_MASK
        if pmu_type_n > 0:
            self._extensions.append(CortexMExtension.PMU)

        # Check for MPU extension
        mpu_type = mpu_type_cb()
        mpu_type_dregions = (mpu_type & self.MPU_TYPE_DREGIONS_MASK) >> self.MPU_TYPE_DREGIONS_SHIFT
        if mpu_type_dregions > 0:
            self._extensions.append(CortexMExtension.MPU)

        # Determine the base/main variant.
        if arch == self.ARMv8M_BASE:
            self._architecture = CoreArchitecture.ARMv8M_BASE
        else:
            self._architecture = CoreArchitecture.ARMv8M_MAIN

        # Determine the architecture major/minor version.
        # The presence of low-overhead loop and branch instructions is used to distinguish v8.1-M from v8.0-M.
        isar0 = isar0_cb()
        isar0_cmpbranch = (isar0 & self.ISAR0_CMPBRANCH_MASK) >> self.ISAR0_CMPBRANCH_SHIFT
        if isar0_cmpbranch == self.ISAR0_CMPBRANCH__LOB:
            self._arch_version = (8, 1)
        else:
            self._arch_version = (8, 0)

        self._core_name = CORE_TYPE_NAME.get((implementer, self.core_type), f"Unknown (CPUID={cpuid:#010x})")

    def _check_for_fpu(self):
        """@brief Determine if a core has an FPU.

        In addition to the tests performed by CortexM, this method tests for the MVE extension.
        """
        # Schedule this deferred read before calling the super implementation.
        mvfr1_cb = self.read32(self.MVFR1, now=False)

        super()._check_for_fpu()

        # Check for MVE.
        mvfr1 = mvfr1_cb()
        mve = (mvfr1 & self.MVFR1_MVE_MASK) >> self.MVFR1_MVE_SHIFT
        if mve == self.MVFR1_MVE__INTEGER:
            self._extensions.append(CortexMExtension.MVE)
        elif mve == self.MVFR1_MVE__FLOAT:
            self._extensions += [CortexMExtension.MVE, CortexMExtension.MVE_FP]

        # Check for half-precision FP.
        fp16 = (mvfr1 & self.MVFR1_FP16_MASK) >> self.MVFR1_FP16_SHIFT
        if fp16 == self.MVFR1_FP16__SUPPORTED:
            self._extensions.append(CortexMExtension.FPU_HP)

    def _build_registers(self):
        super()._build_registers()

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
        """@brief Returns the current security state of the processor.

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
        """@brief Returns the reason the core has halted.

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

