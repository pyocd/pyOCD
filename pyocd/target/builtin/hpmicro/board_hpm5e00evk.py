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

"""HPM5E00EVK board definition.

HPM5E00EVK board with 16MB XPI0 NOR flash and hybrid XPI region.
"""

from .target_hpm5ex1 import HPM5Ex1


class HPM5E00EVK(HPM5Ex1):
    """HPM5E00EVK board with 16MB XPI0 NOR flash."""

    def __init__(self, session):
        super().__init__(session)
        self.add_xpi_flash(
            algo_type='flm',
            flash_size=0x1000000,
            is_boot_memory=True,
            nor_config_header=0xFCF90002,
            nor_config_opt0=0x6,
            nor_config_opt1=0x1000,
        )
        self.add_xpi_flash(
            algo_type='flm',
            flash_size=0x1000000,
            nor_config_header=0xFCF90002,
            nor_config_opt0=0x6,
            nor_config_opt1=0x1000,
            flash_base=0xB0000000,
            is_boot_memory=False,
        )
