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

"""HPM67x4 (Y=4) part target definition for pyOCD.

HPM6700 family Y=4 variant. 4MB internal flash at XPI0 (0x80000000).
Dual-core RISC-V MCU with core-local ILM addressing.
Covers HPM6454, HPM6754.
"""

from .target_hpm67x0 import HPM67x0


class HPM67x4(HPM67x0):
    """HPM67x4 (Y=4) RISC-V dual-core MCU. 4MB internal flash at XPI0.

    Extends HPM67x0 (Y=0 base) with 4MB internal flash at 0x80000000.
    Board subclasses call add_xpi_flash() for external flash params.
    """

    PART_NUMBER = "HPM67x4"
    INTERNAL_FLASH_SIZE = 0x400000  # 4MB

    def __init__(self, session):
        super().__init__(session)
