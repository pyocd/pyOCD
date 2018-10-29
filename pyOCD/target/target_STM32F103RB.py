"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2018 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from ..flash.flash import Flash
from ..core.coresight_target import (SVDFile, CoreSightTarget)
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)
import logging

DBGMCU_CR = 0xE0042004
#0111 1110 0011 1111 1111 1111 0000 0000
DBGMCU_VAL = 0x7E3FFF00

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4603b510, 0x4c442000, 0x48446020, 0x48446060, 0x46206060, 0xf01069c0, 0xd1080f04, 0x5055f245,
    0x60204c40, 0x60602006, 0x70fff640, 0x200060a0, 0x4601bd10, 0x69004838, 0x0080f040, 0x61104a36,
    0x47702000, 0x69004834, 0x0004f040, 0x61084932, 0x69004608, 0x0040f040, 0xe0036108, 0x20aaf64a,
    0x60084930, 0x68c0482c, 0x0f01f010, 0x482ad1f6, 0xf0206900, 0x49280004, 0x20006108, 0x46014770,
    0x69004825, 0x0002f040, 0x61104a23, 0x61414610, 0xf0406900, 0x61100040, 0xf64ae003, 0x4a2120aa,
    0x481d6010, 0xf01068c0, 0xd1f60f01, 0x6900481a, 0x0002f020, 0x61104a18, 0x47702000, 0x4603b510,
    0xf0201c48, 0xe0220101, 0x69004813, 0x0001f040, 0x61204c11, 0x80188810, 0x480fbf00, 0xf01068c0,
    0xd1fa0f01, 0x6900480c, 0x0001f020, 0x61204c0a, 0x68c04620, 0x0f14f010, 0x4620d006, 0xf04068c0,
    0x60e00014, 0xbd102001, 0x1c921c9b, 0x29001e89, 0x2000d1da, 0x0000e7f7, 0x40022000, 0x45670123,
    0xcdef89ab, 0x40003000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000021,
    'pc_unInit': 0x20000053,
    'pc_program_page': 0x200000dd,
    'pc_erase_sector': 0x2000009f,
    'pc_eraseAll': 0x20000065,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000128,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001400],   # Enable double buffering
    'min_program_length' : 0x400,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}


class Flash_stm32f103rb(Flash):

    def __init__(self, target):
        super(Flash_stm32f103rb, self).__init__(target, FLASH_ALGO)

class STM32F103RB(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x08000000,  length=0x20000,      blocksize=0x400, is_boot_memory=True),
        RamRegion(      start=0x20000000,  length=0x5000)
        )

    def __init__(self, link):
        super(STM32F103RB, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile(vendor="STMicro", filename="STM32F103xx.svd", is_local=False)

    def create_init_sequence(self):
        seq = super(STM32F103RB, self).create_init_sequence()

        seq.insert_after('create_cores',
            ('setup_dbgmcu', self.setup_dbgmcu)
            )

        return seq

    def setup_dbgmcu(self):
        self.writeMemory(DBGMCU_CR, DBGMCU_VAL)
