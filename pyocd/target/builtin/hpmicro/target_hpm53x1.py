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

"""HPM53x1 (Y=1) part target definition for pyOCD.

HPM5300 family Y=1 variant. 1MB internal flash at XPI0 (0x80000000).
Covers HPM5301, HPM5321, HPM5331, HPM5361, HPM53M1.
"""

from .target_hpm53x0 import HPM53x0


class HPM53x1(HPM53x0):
    """HPM53x1 (Y=1) RISC-V MCU. 1MB internal flash at XPI0.

    Extends HPM53x0 (Y=0 base) with 1MB internal flash at 0x80000000.
    Board subclasses call add_xpi_flash() for external flash params.
    """

    PART_NUMBER = "HPM53x1"
    INTERNAL_FLASH_SIZE = 0x100000  # 1MB

    def __init__(self, session):
        super().__init__(session)
