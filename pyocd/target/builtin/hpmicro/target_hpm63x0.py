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

"""HPM63x0 (Y=0 base) part target definition for pyOCD.

HPM6300 family Y=0 base target (HPM6320/6330/6340/6350/6360).
Single-core RISC-V MCU. No internal flash.

Memory map (no flash):
    ILM:         0x00000000, 128KB (rwx)
    DLM:         0x00080000, 128KB (rw)
    AXI_SRAM:    0x01080000, 512KB (rwx)
    AHB_SRAM:    0xF0300000, 32KB  (rw)
"""

from ....core.memory_map import MemoryMap, RamRegion
from .base import HPMicroTarget

# -- Memory layout --
_ILM_BASE = 0x00000000       # Instruction Local Memory
_ILM_SIZE = 0x20000          # 128 KB
_DLM_BASE = 0x00080000       # Data Local Memory
_DLM_SIZE = 0x20000          # 128 KB

# -- System SRAM --
_AXI_SRAM_BASE = 0x01080000
_AXI_SRAM_SIZE = 0x80000      # 512 KB
_AHB_SRAM_BASE = 0xF0300000
_AHB_SRAM_SIZE = 0x8000       # 32 KB

# -- XPI controller --
# XPI1 base: 0xF3040000 (defined in class XPI_MAP)


class HPM63x0(HPMicroTarget):
    """HPM63x0 (Y=0 base) RISC-V MCU.

    Family base target with RAM only. No flash region defined.
    HPM63x4 (Y=4) variant extends this with 4MB internal flash.
    Board subclasses call add_xpi_flash() with board-specific flash params.
    """

    CSR_CONFIGS = ["hpmicro/hpm_d45_csr.yaml"]

    PART_NUMBER = "HPM63x0"
    PART_FAMILIES = ["HPM6300"]

    XPI_MAP = {
        0x80000000: 0xF3040000,
    }
    _FLASH_RAM_START = _ILM_BASE
    _FLASH_RAM_SIZE = _ILM_SIZE

    MEMORY_MAP = MemoryMap(
        RamRegion(name="ILM", start=_ILM_BASE, length=_ILM_SIZE,
                  access='rwx', is_boot_memory=True),
        RamRegion(name="DLM", start=_DLM_BASE, length=_DLM_SIZE,
                  access='rw'),
        RamRegion(name="AXI_SRAM", start=_AXI_SRAM_BASE, length=_AXI_SRAM_SIZE,
                  access='rwx'),
        RamRegion(name="AHB_SRAM", start=_AHB_SRAM_BASE, length=_AHB_SRAM_SIZE,
                  access='rw'),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
