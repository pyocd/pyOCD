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

"""HPM5300EVK board definition.

HPM5300EVK board with 1MB XPI0 NOR flash.
"""

from .target_hpm53x1 import HPM53x1


class HPM5300EVK(HPM53x1):
    """HPM5300EVK board with 1MB XPI0 NOR flash."""

    def __init__(self, session):
        super().__init__(session)
        self.add_xpi_flash(
            flash_size=0x100000,
            nor_config_header=0xFCF90002,
            nor_config_opt0=0x5,
            nor_config_opt1=0x1000,
            is_boot_memory=True,
        )
