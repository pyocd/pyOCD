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
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 
    0x9002b084, 0x92009101, 0x21594830, 0x21166001, 0x21886001, 0x68006001, 0xd0032801, 0x2001e7ff,
    0xe0509003, 0x6808492a, 0x43104a2a, 0x492a6008, 0x22046808, 0x60084310, 0x4828e7ff, 0x21506800,
    0x28504008, 0xe7ffd001, 0x4825e7f7, 0x60012169, 0x21296800, 0x28294008, 0xe7ffd003, 0x90032001,
    0x4820e031, 0xf2406800, 0x40087100, 0x1100f240, 0xd0164288, 0xe7ffe7ff, 0x6800481a, 0xb10807c0,
    0xe7f9e7ff, 0x68084918, 0x43102201, 0x43902206, 0xe7ff6008, 0x68004813, 0xb10807c0, 0xe7f9e7ff,
    0x4912e7ff, 0x22066808, 0x22014310, 0x60084390, 0x6808490f, 0x4390220f, 0x490e6008, 0x60082003,
    0x90032000, 0x9803e7ff, 0x4770b004, 0x40000100, 0x40000200, 0x00040004, 0x40000204, 0x40000250,
    0x4000c000, 0x400001fc, 0x400001f8, 0x40000210, 0x40000220, 0x4000c04c, 0x9000b081, 0x4807e7ff,
    0x07c06800, 0xe7ffb108, 0x4905e7f9, 0x22016808, 0x60084390, 0xb0012000, 0x46c04770, 0x4000c040,
    0x4000c000, 0x9000b081, 0xb0012000, 0x46c04770, 0x9003b085, 0x92019102, 0x7800a803, 0xb1180780,
    0x2001e7ff, 0xe0899004, 0x1cc09802, 0x43882103, 0xe7ff9002, 0x68004843, 0xb10807c0, 0xe7f9e7ff,
    0x68084941, 0x43102240, 0xe7ff6008, 0x28009802, 0xe7ffd071, 0x2000493d, 0x493d6008, 0x6008202f,
    0x2001493c, 0xf3bf6008, 0xe7ff8f6f, 0x68004835, 0xb10807c0, 0xe7f9e7ff, 0x68004833, 0x46689000,
    0x06407800, 0xd5062800, 0x9800e7ff, 0x6008492e, 0x90042001, 0x9803e052, 0x6008492c, 0x68009801,
    0x6008492d, 0x2027492a, 0x492a6008, 0x60082001, 0x8f6ff3bf, 0x4823e7ff, 0x07c06800, 0xe7ffb108,
    0x4821e7f9, 0x90006800, 0x78004668, 0x28000640, 0xe7ffd506, 0x491c9800, 0x20016008, 0xe02d9004,
    0x491a9803, 0x491a6008, 0x60082021, 0x20014919, 0xf3bf6008, 0xe7ff8f6f, 0x68004812, 0xb10807c0,
    0xe7f9e7ff, 0x68004810, 0x46689000, 0x06407800, 0xd5062800, 0x9800e7ff, 0x6008490b, 0x90042001,
    0x9803e00c, 0x90031d00, 0x1d009801, 0x98029001, 0x90021f00, 0x2000e78a, 0xe7ff9004, 0xb0059804,
    0x46c04770, 0x4000c040, 0x4000c000, 0x4000c004, 0x4000c00c, 0x4000c010, 0x4000c008, 0x9003b085,
    0x92019102, 0x7800a803, 0xb1180780, 0x9803e7ff, 0xe04c9004, 0x1cc09802, 0x43882103, 0xe7ff9002,
    0x68004824, 0xb10807c0, 0xe7f9e7ff, 0x68084922, 0x43102240, 0x49216008, 0x60082000, 0x9802e7ff,
    0xe7ffb390, 0x491e9803, 0x491e6008, 0x60082001, 0x8f6ff3bf, 0x4817e7ff, 0x07c06800, 0xe7ffb108,
    0x4815e7f9, 0x90006800, 0x78004668, 0x28000640, 0xe7ffd506, 0x49109800, 0x20016008, 0xe0169004,
    0x68004811, 0x68099901, 0xd0034288, 0x2001e7ff, 0xe00c9004, 0x1d009803, 0x98019003, 0x90011d00,
    0x1f009802, 0xe7ca9002, 0x90042000, 0x9804e7ff, 0x4770b005, 0x4000c040, 0x4000c000, 0x4000c00c,
    0x4000c004, 0x4000c010, 0x4000c008, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x200000fd,
    'pc_program_page': 0x20000135,
    'pc_erase_sector': 0x20000129,
    'pc_eraseAll': 0x0,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000034c,
    'begin_stack' : 0x20000600,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x1000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20002000],   # Enable double buffering
    'min_program_length' : 0x1000,
}

class M2L31KIDAE(CoreSightTarget):
    VENDOR = "Nuvoton"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x80000,  sector_size=0x1000,
                                                        page_size=0x1000,
                                                        is_boot_memory=True,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x0F100000, length=0x2000,   sector_size=0x1000,
                                                        page_size=0x1000,
                                                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x2A000)
        )

    def __init__(self, session):
        super(M2L31KIDAE, self).__init__(session, self.MEMORY_MAP)
