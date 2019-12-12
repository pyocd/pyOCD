# pyOCD debugger
# Copyright (c) 019 Arm Limited
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

# pylint: disable=invalid_name

# CPUID PARTNO values
ARM_CortexM0 = 0xC20
ARM_CortexM1 = 0xC21
ARM_CortexM3 = 0xC23
ARM_CortexM4 = 0xC24
ARM_CortexM7 = 0xC27
ARM_CortexM0p = 0xC60
ARM_CortexM23 = 0xD20
ARM_CortexM33 = 0xD21
ARM_CortexM35P = 0xD22

# pylint: enable=invalid_name

## @brief User-friendly names for core types.
CORE_TYPE_NAME = {
                 ARM_CortexM0 : "Cortex-M0",
                 ARM_CortexM1 : "Cortex-M1",
                 ARM_CortexM3 : "Cortex-M3",
                 ARM_CortexM4 : "Cortex-M4",
                 ARM_CortexM7 : "Cortex-M7",
                 ARM_CortexM0p : "Cortex-M0+",
                 ARM_CortexM23 : "Cortex-M23",
                 ARM_CortexM33 : "Cortex-M33",
                 ARM_CortexM35P : "Cortex-M35P",
               }
