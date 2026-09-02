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

"""HPM5Ex0 (Y=0 base) part target definition for pyOCD.

HPM5E00 family Y=0 base target. No internal flash.
All parts in this family are Y=1, so this base serves as
the common memory map for the HPM5Ex1 variant.

Memory map (no flash):
    ILM:   0x00000000, 256KB (rwx)
    DLM:   0x00200000, 256KB (rw)
    AXI_SRAM: 0x01200000, 256KB (rwx)
    AHB_SRAM: 0xF0200000, 32KB (rw)
"""

import logging

from ....core.memory_map import MemoryMap, RamRegion
from .base import HPMicroTarget

LOG = logging.getLogger(__name__)

# -- Memory layout --
_ILM_BASE = 0x00000000       # Instruction Local Memory
_ILM_SIZE = 0x40000          # 256 KB
_DLM_BASE = 0x00200000       # Data Local Memory
_DLM_SIZE = 0x40000          # 256 KB

# -- System SRAM --
_AXI_SRAM_BASE = 0x01200000
_AXI_SRAM_SIZE = 0x40000      # 256 KB
_AHB_SRAM_BASE = 0xF0200000
_AHB_SRAM_SIZE = 0x8000       # 32 KB

# -- XPI controller --
# XPI0 base: 0xF3000000 (defined in class XPI_MAP)


class HPM5Ex0(HPMicroTarget):
    """HPM5Ex0 (Y=0 base) RISC-V MCU.

    Family base target with RAM only. No flash region defined.
    HPM5Ex1 (Y=1) variant extends this with 1MB internal flash.
    Board subclasses call add_xpi_flash() with board-specific flash params.
    """

    CSR_CONFIGS = ["hpmicro/hpm_d45_csr.yaml"]

    PART_NUMBER = "HPM5Ex0"
    PART_FAMILIES = ["HPM5E00"]

    XPI_MAP = {
        0x80000000: 0xF3000000,
        0xB0000000: 0xF3000000,
    }
    _FLASH_RAM_START = _ILM_BASE
    _FLASH_RAM_SIZE = _ILM_SIZE

    # HPM5E00EVK boot ROM halts before c_startup vector copy executes, so ILM 0x0
    # is not overwritten during `mon reset halt`. No shift needed here — keep at 0.
    # Verified: offset=0x1000 also safe after formula fix in base.py, but unnecessary.

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
        # HPM5E00EVK uses FT2232H adapter with nTRST on GPIO pin 9.
        # Added as lowest-priority layer so CLI -O and config files can override.
        # These defaults are only effective when an FTDI debug probe is selected.
        session.options.add_back({'ftdi.pin.ntrst': 9})

    # ISP detection, _pre_flash_init, and _register_reset_hooks are inherited
    # from HPMicroTarget base. HPM5Ex0 uses the standard PC-based ISP
    # detection without modification.
