# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

# pylint: disable=invalid_name

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

# pylint: enable=invalid_name

## @brief User-friendly names for core types.
CORE_TYPE_NAME = {
                 ARM_SC000 : "SecurCore SC000",
                 ARM_SC300 : "SecurCore SC300",
                 ARM_CortexM0 : "Cortex-M0",
                 ARM_CortexM1 : "Cortex-M1",
                 ARM_CortexM3 : "Cortex-M3",
                 ARM_CortexM4 : "Cortex-M4",
                 ARM_CortexM7 : "Cortex-M7",
                 ARM_CortexM0p : "Cortex-M0+",
                 ARM_CortexM23 : "Cortex-M23",
                 ARM_CortexM33 : "Cortex-M33",
                 ARM_CortexM35P : "Cortex-M35P",
                 ARM_CortexM55 : "Cortex-M55",
               }

class CoreArchitecture(Enum):
    """! @brief CPU architectures."""
    ARMv6M = 1
    ARMv7M = 2
    ARMv8M_BASE = 3
    ARMv8M_MAIN = 4
    
class CortexMExtension(Enum):
    """! @brief Extensions for the Cortex-M architecture."""
    FPU = "FPU" # Single-Precision floating point
    DSP = "DSP" # Digital Signal Processing instructions
    FPU_DP = "FPU_DP" # Double-Precision floating point
    FPU_HP = "FPU_HP" # Half-Precision floating point
    SEC = "SEC" # Security Extension
    SEC_V81 = "SEC_V81" # v8.1-M additions to the Security Extension
    MVE = "MVE" # M-profile Vector Extension, with integer support
    MVE_FP = "MVE_FP" # M-profile Vector Extension single- and half-precision floating-point
    UDE = "UDE" # Unprivileged Debug Extension
    RAS = "RAS" # Reliability, Serviceability, and Availability
    PMU = "PMU" # Performance Monitoring Unit
    LOB = "LOB" # Low-Overhead loops and Branch Future
    PXN = "PXN" # Privileged eXecute-Never
    MAIN = "MAIN" # Main Extension
    MPU = "MPU" # Memory Protection Unit
    DIT = "DIT" # Data-Independent Timing
    FPCXT = "FPCXT" # Floating Point Context
