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

"""HPM63x4 (Y=4) part target definition for pyOCD.

HPM6300 family Y=4 variant. 4MB internal flash at XPI0 (0x80000000).
Single-core RISC-V MCU. Covers HPM6364.
"""

from .target_hpm63x0 import HPM63x0


class HPM63x4(HPM63x0):
    """HPM63x4 (Y=4) RISC-V single-core MCU. 4MB internal flash at XPI0.

    Extends HPM63x0 (Y=0 base) with 4MB internal flash at 0x80000000.
    Board subclasses call add_xpi_flash() for external flash params.
    """

    PART_NUMBER = "HPM63x4"
    INTERNAL_FLASH_SIZE = 0x400000  # 4MB

    def __init__(self, session):
        super().__init__(session)
