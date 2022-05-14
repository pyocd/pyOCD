# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
# Copyright (c) 2022 Chris Reed
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

from enum import Enum
from typing import (Dict, Tuple)

# pylint: disable=invalid_name

# CPUID IMPLEMENTER values
CPUID_ARM = 0x41
CPUID_ARM_CHINA = 0x63

# CPUID PARTNO values
ARM_SC000 = 0xC30
ARM_SC300 = 0xC33
ARM_CortexM0 = 0xC20
ARM_CortexM1 = 0xC21
ARM_CortexM3 = 0xC23
ARM_CortexM4 = 0xC24
ARM_CortexM7 = 0xC27
ARM_CortexM0p = 0xC60
ARM_CortexM23 = 0xD20
ARM_CortexM33 = 0xD21
ARM_CortexM35P = 0xD31
ARM_CortexM55 = 0xD22
ARM_CortexM85 = 0xD23
ARM_China_StarMC1 = 0x132

# pylint: enable=invalid_name

## @brief User-friendly names for core types.
CORE_TYPE_NAME: Dict[Tuple[int, int], str] = {
        (CPUID_ARM,        ARM_SC000):         "SecurCore SC000",
        (CPUID_ARM,        ARM_SC300):         "SecurCore SC300",
        (CPUID_ARM,        ARM_CortexM0):      "Cortex-M0",
        (CPUID_ARM,        ARM_CortexM1):      "Cortex-M1",
        (CPUID_ARM,        ARM_CortexM3):      "Cortex-M3",
        (CPUID_ARM,        ARM_CortexM4):      "Cortex-M4",
        (CPUID_ARM,        ARM_CortexM7):      "Cortex-M7",
        (CPUID_ARM,        ARM_CortexM0p):     "Cortex-M0+",
        (CPUID_ARM,        ARM_CortexM23):     "Cortex-M23",
        (CPUID_ARM,        ARM_CortexM33):     "Cortex-M33",
        (CPUID_ARM,        ARM_CortexM35P):    "Cortex-M35P",
        (CPUID_ARM,        ARM_CortexM55):     "Cortex-M55",
        (CPUID_ARM,        ARM_CortexM85):     "Cortex-M85",
        (CPUID_ARM_CHINA,  ARM_China_StarMC1): "Star-MC1",
    }

class CoreArchitecture(Enum):
    """@brief CPU architectures."""
    ARMv6M = 1
    ARMv7M = 2
    ARMv8M_BASE = 3
    ARMv8M_MAIN = 4

class CortexMExtension(Enum):
    """@brief Extensions for the Cortex-M architecture."""
    FPU = "FPU" # Single-Precision floating point
    DSP = "DSP" # Digital Signal Processing instructions
    FPU_DP = "FPU_DP" # Double-Precision floating point
    FPU_HP = "FPU_HP" # Half-Precision floating point
    FPU_V4 = "FPUv4" # FPv4, only present in Cortex-M4F
    FPU_V5 = "FPUv5" # FPv5 single or double precision
    SEC = "SEC" # Security Extension
    SEC_V81 = "SEC_V81" # v8.1-M additions to the Security Extension
    MVE = "MVE" # M-profile Vector Extension, with integer support
    MVE_FP = "MVE_FP" # M-profile Vector Extension single- and half-precision floating-point
    UDE = "UDE" # Unprivileged Debug Extension
    RAS = "RAS" # Reliability, Serviceability, and Availability
    PMU = "PMU" # Performance Monitoring Unit
    MPU = "MPU" # Memory Protection Unit
    PACBTI = "PACBTI" # Pointer Authentication and Branch Target Identification
