# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
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

"""HPM6750EVK2 board definition.

HPM6750EVK2 board with 32MB XPI0 NOR flash.
Dual-core HPM6750 (Y=0 part, no internal flash).
"""

from .target_hpm67x0 import HPM67x0


class HPM6750EVK2(HPM67x0):
    """HPM6750EVK2 board with 32MB XPI0 NOR flash."""

    def __init__(self, session):
        super().__init__(session)
        self.add_xpi_flash(
            flash_size=0x2000000,
            nor_config_header=0xFCF90002,
            nor_config_opt0=0x5,  # freq_opt=5 (100MHz): flash-boot mode stable.
                                 # opt0=0x7 (133MHz) causes program timeout (result
                                 # 0x3) in flash-boot mode (cross-verified against
                                 # hpm_flashloader and hpm_sdk).
            nor_config_opt1=0xE,
            is_boot_memory=True,
        )
