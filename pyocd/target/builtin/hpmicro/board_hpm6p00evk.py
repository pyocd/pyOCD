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

"""HPM6P00EVK board definition.

HPM6P00EVK board (revA, HPM6P80 die) with 16 MB XPI0 NOR flash.
The revA board mounts HPM6P80 (not HPM6P84 that the SDK hpm6p00evk
defaults target), so the flash pin-group select (opt1) is group 0,
not the SDK default 0x1000 (group 1). Flash size is the SFDP-reported
16 MB, not the SDK placeholder 1 MB.
"""

from .target_hpm6px1 import HPM6Px1


class HPM6P00EVK(HPM6Px1):
    """HPM6P00EVK board (revA, HPM6P80 die) with 16 MB XPI0 NOR flash."""

    def __init__(self, session):
        super().__init__(session)
        self.add_xpi_flash(
            flash_size=0x1000000,
            nor_config_header=0xFCF90002,
            nor_config_opt0=0x5,
            nor_config_opt1=0x0,
            is_boot_memory=True,
        )

