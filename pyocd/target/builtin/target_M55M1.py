# pyOCD debugger
# Copyright (c) 2024 Nuvoton
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap, MemoryType)
from ...debug.svd.loader import SVDFile

SCS_DHCSR        = 0xE000EDF0
SCS_DHCSR_S_SDE  = 0x00100000
SCU_SRAM0MPCLUT0 = 0x40402410
SCU_SRAM1MPCLUT0 = 0x40402414
SCU_SRAM2MPCLUT0 = 0x40402418

def flash_algo(load_address):
    return {
        'load_address' : load_address,

        # Flash algorithm as a hex string
        'instructions': [
        0xE00ABE00, 
        0x9004b086, 0x92029103, 0x90014678, 0x90009801, 0x0003f89d, 0x280006c0, 0xe7ffd528, 0x40a0f04f,
        0xb9186800, 0x2001e7ff, 0xe08d9005, 0x1000f240, 0x0000f2c5, 0x60012159, 0x60012116, 0x60012188,
        0x28016800, 0xe7ffd003, 0x90052001, 0xf244e07c, 0xf2c50000, 0x21490004, 0x68006001, 0xe7ffb918,
        0x90052001, 0x2000e070, 0xe06d9005, 0x1000f240, 0x0000f2c4, 0x60012159, 0x60012116, 0x60012188,
        0x28016800, 0xe7ffd003, 0x90052001, 0xf241e05c, 0xf2c40100, 0x68080100, 0x0028f040, 0xf2416008,
        0xf2c4213c, 0xf04f0100, 0x60081001, 0x0000f244, 0x0004f2c4, 0x60012169, 0xf0006800, 0x28290029,
        0xe7ffd003, 0x90052001, 0xe7ffe03e, 0x0004f241, 0x0000f2c4, 0xf0006800, 0x28280028, 0xe7ffd001,
        0xf242e7f4, 0xf2c40014, 0x68000000, 0xd11b2803, 0xe7ffe7ff, 0x0010f242, 0x0000f2c4, 0x0fc06800,
        0xe7ffb108, 0xf242e7f6, 0xf2c40110, 0x20020100, 0xe7ff6008, 0x0014f242, 0x0000f2c4, 0x0fc06800,
        0xe7ffb108, 0xe7ffe7f6, 0x4100f241, 0x0100f2c4, 0x60082002, 0x5100f241, 0x0100f2c4, 0x60082000,
        0x2000e7ff, 0xe7ff9005, 0xb0069805, 0xbf004770, 0x9003b084, 0x90014678, 0x90009801, 0x00c19800,
        0x0000f244, 0x0004f2c4, 0xbf442900, 0x0000f244, 0x0004f2c5, 0xe7ff9002, 0x6c009802, 0xb10807c0,
        0xe7f9e7ff, 0x20009902, 0xb0046008, 0xbf004770, 0x9003b085, 0x92019102, 0x9803e7ff, 0x07c06c00,
        0xe7ffb108, 0x9903e7f9, 0xf0406808, 0x60080040, 0x20229903, 0x980260c8, 0x60489903, 0x99039801,
        0x99036088, 0x61082001, 0x8f6ff3bf, 0x9803e7ff, 0x07c06c00, 0xe7ffb108, 0x9803e7f9, 0x90006800,
        0x0000f89d, 0x28000640, 0xe7ffd506, 0x99039800, 0x20016008, 0xe0029004, 0x90042000, 0x9804e7ff,
        0x4770b005, 0xb084b580, 0x46789003, 0x98019001, 0x98009000, 0xf24400c1, 0xf2c40000, 0x29000004,
        0xf244bf44, 0xf2c50000, 0x90020004, 0xf0209803, 0x90035080, 0xf6419803, 0xea2071ff, 0x90030001,
        0x99039802, 0x0200f04f, 0xffa2f7ff, 0xbd80b004, 0x9006b088, 0x92049105, 0x0018f89d, 0xb1180780,
        0x2001e7ff, 0xe05c9007, 0x90014678, 0x90009801, 0x00c19800, 0x0000f244, 0x0004f2c4, 0xbf442900,
        0x0000f244, 0x0004f2c5, 0x98059003, 0x0003f100, 0x0003f020, 0x98069005, 0x5080f020, 0xe7ff9006,
        0x6c009803, 0xb10807c0, 0xe7f9e7ff, 0x68089903, 0x0040f040, 0x99036008, 0x60c82021, 0x9805e7ff,
        0xe7ffb360, 0x99039806, 0x98046048, 0x99036800, 0x99036088, 0x61082001, 0x8f6ff3bf, 0x9803e7ff,
        0x07c06c00, 0xe7ffb108, 0x9803e7f9, 0x90026800, 0x0008f89d, 0x28000640, 0xe7ffd506, 0x99039802,
        0x20016008, 0xe00c9007, 0x30049806, 0x98049006, 0x90043004, 0x38049805, 0xe7d09005, 0x90072000,
        0x9807e7ff, 0x4770b008, 0x9007b089, 0x92059106, 0x001cf89d, 0xb1180780, 0x9807e7ff, 0xe0669008,
        0x90014678, 0x90009801, 0x00c19800, 0x0000f244, 0x0004f2c4, 0xbf442900, 0x0000f244, 0x0004f2c5,
        0x98069004, 0x0003f100, 0x0003f020, 0x98079006, 0x5080f000, 0x98079002, 0x5080f020, 0xe7ff9007,
        0x6c009804, 0xb10807c0, 0xe7f9e7ff, 0x68089904, 0x0040f040, 0x99046008, 0x60c82000, 0x9806e7ff,
        0xe7ffb390, 0x99049807, 0x99046048, 0x61082001, 0x8f6ff3bf, 0x9804e7ff, 0x07c06c00, 0xe7ffb108,
        0x9804e7f9, 0x90036800, 0x000cf89d, 0x28000640, 0xe7ffd506, 0x99049803, 0x20016008, 0xe0169008,
        0x68809804, 0x68099905, 0xd0034288, 0x2001e7ff, 0xe00c9008, 0x30049807, 0x98059007, 0x90053004,
        0x38049806, 0xe7ca9006, 0x90082000, 0x9808e7ff, 0x4770b009, 0x00000000
        ],

        # Relative function addresses
        'pc_init': load_address + 0x00000005,
        'pc_unInit': load_address + 0x00000155,
        'pc_program_page': load_address + 0x00000255,
        'pc_erase_sector': load_address + 0x00000209,
        'pc_eraseAll': 0x0,

        'static_base' : load_address + 0x0000004 + 0x00000414,
        'begin_stack' : load_address + 0x00000700,
        'begin_data' : load_address + 0x1000,
        'page_size' : 0x2000,
        'analyzer_supported' : False,
        'analyzer_address' : 0x00000000,
        'page_buffers' : [load_address + 0x00001000, load_address + 0x00003000],   # Enable double buffering
        'min_program_length' : 0x2000,
    }

class M55M1H2LJAE(CoreSightTarget):
    VENDOR = "Nuvoton"

    MEMORY_MAP = MemoryMap(
        FlashRegion(name='aprom',      start=0x00100000, length=0x200000, sector_size=0x2000,
                                                                          page_size=0x2000,
                                                                          is_boot_memory=True,
                                                                          algo=flash_algo(0x20000000)),
        FlashRegion(name='aprom_ns',   start=0x10100000, length=0x200000, sector_size=0x2000,
                                                                          page_size=0x2000,
                                                                          is_boot_memory=True,
                                                                          algo=flash_algo(0x20000000)),
        FlashRegion(name='ldrom',      start=0x0F100000, length=0x2000,   sector_size=0x2000,
                                                                          page_size=0x2000,
                                                                          algo=flash_algo(0x20000000)),
        RamRegion(  name='itcm',       start=0x00000000, length=0x10000),
        RamRegion(  name='dtcm',       start=0x20000000, length=0x20000),
        RamRegion(  name='sram',       start=0x20100000, length=0x150000),
        RamRegion(  name='sram_ns',    start=0x30100000, length=0x150000)
        )

    def __init__(self, link):
        super(M55M1H2LJAE, self).__init__(link, self.MEMORY_MAP)

    def post_connect_hook(self):
        dhcsr = self.read32(SCS_DHCSR)

        if (dhcsr & SCS_DHCSR_S_SDE) == 0:
            sram0mpclut0 = self.read32(0x10000000 + SCU_SRAM0MPCLUT0)
            sram1mpclut0 = self.read32(0x10000000 + SCU_SRAM1MPCLUT0)
            sram2mpclut0 = self.read32(0x10000000 + SCU_SRAM2MPCLUT0)
            srammpcluts  = [sram0mpclut0, sram1mpclut0, sram2mpclut0]
            snsaddr      = 0x20250000

            for i in range(len(srammpcluts)):
                for j in range(16):
                    if srammpcluts[i] & (1 << j):
                        snsaddr = 0x20100000 + (0x8000 * (i * 16 + j))
                        break

            for region in self.memory_map.clone():
                if (region.start & 0x10000000) > 0:
                    if region.type == MemoryType.FLASH:
                        self.memory_map[region.name].algo = flash_algo(0x10000000 + snsaddr)
                else:
                    self.memory_map.remove_region(self.memory_map[region.name])
