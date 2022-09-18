# pyOCD debugger
# Copyright (c) 2022 Yuntu Microelectronics
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

MAIN_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x48414601, 0x4a406840, 0x29006050, 0x483fd005, 0x60104a3f, 0x4a3cb2c8, 0xbf006090, 0x6840483a,
    0x40102280, 0xd0f92800, 0x68404837, 0x4010220e, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x69004833, 0x43082101, 0x61084931, 0x49324831, 0x48326008, 0x46086008, 0x08406840,
    0x60480040, 0x492b2001, 0xbf006048, 0x68c04829, 0xd1fb2801, 0x49272000, 0xf7ff6008, 0xbd70ffc1,
    0x20004601, 0xb5104770, 0x48264604, 0x20106020, 0xffb6f7ff, 0xb510bd10, 0x20012400, 0xf7ff0700,
    0x4604fff2, 0xf7ff4820, 0x1904ffee, 0xf7ff481f, 0x1904ffea, 0xf7ff481e, 0x1904ffe6, 0x2100481d,
    0x20126008, 0xff9cf7ff, 0xbd101900, 0xb082b5f7, 0x460d4604, 0x46279e04, 0x90012004, 0xbf009500,
    0xc701ce01, 0xf7ff2002, 0x2800ff8b, 0x2001d002, 0xbdf0b005, 0x98009901, 0x90001a40, 0x28009800,
    0xbf00d1ee, 0x0000e7f4, 0x40020000, 0xfd9573f5, 0x40020200, 0x40064000, 0x0000b631, 0x40052000,
    0x0000c278, 0x12345678, 0x10000200, 0x10000400, 0x10000600, 0x00001234, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x20000085,
    'pc_program_page': 0x200000d1,
    'pc_erase_sector': 0x2000008b,
    'pc_eraseAll': 0x2000009b,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000138,
    'begin_stack' : 0x20002150,
    'end_stack' : 0x20001150,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x8,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000140,
        0x20000148
    ],
    'min_program_length' : 0x8,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x138,
    'rw_start': 0x13c,
    'rw_size': 0x4,
    'zi_start': 0x140,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}
DATA_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x48414601, 0x4a406840, 0x29006050, 0x483fd005, 0x60104a3f, 0x4a3cb2c8, 0xbf006090, 0x6840483a,
    0x40102280, 0xd0f92800, 0x68404837, 0x4010220e, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x69004833, 0x43082101, 0x61084931, 0x49324831, 0x48326008, 0x46086008, 0x08406840,
    0x60480040, 0x492b2001, 0xbf006048, 0x68c04829, 0xd1fb2801, 0x49272000, 0xf7ff6008, 0xbd70ffc1,
    0x20004601, 0xb5104770, 0x21004826, 0x20126008, 0xffb6f7ff, 0xb570bd10, 0x24004605, 0x07002001,
    0xfff9f7ff, 0x48204604, 0xfff5f7ff, 0x481f1904, 0xfff1f7ff, 0x481e1904, 0xffedf7ff, 0x48191904,
    0x60082100, 0xf7ff2012, 0x1900ff9b, 0xb5f7bd70, 0x4604b082, 0x9e04460d, 0x20044627, 0x95009001,
    0xce01bf00, 0x2002c701, 0xff8af7ff, 0xd0022800, 0xb0052001, 0x9901bdf0, 0x1a409800, 0x98009000,
    0xdcee2800, 0xe7f42000, 0x40020000, 0xfd9573f5, 0x40020200, 0x40064000, 0x0000b631, 0x40052000,
    0x0000c278, 0x00001234, 0x10000200, 0x10000400, 0x10000600, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x20000085,
    'pc_program_page': 0x200000d3,
    'pc_erase_sector': 0x2000009b,
    'pc_eraseAll': 0x2000008b,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000134,
    'begin_stack' : 0x20002150,
    'end_stack' : 0x20001150,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x8,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000140,
        0x20000148
    ],
    'min_program_length' : 0x8,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x134,
    'rw_start': 0x138,
    'rw_size': 0x4,
    'zi_start': 0x13c,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x10000000,
    'flash_size': 0x800,
    'sector_sizes': (
        (0x10000000, 0x200),
    )
}

class YTM32B1LE0(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x0000,      length=0x10000,      blocksize=0x200, is_boot_memory=True, algo=MAIN_FLASH_ALGO),
        FlashRegion(    start=0x10000000,  length=0x800,        blocksize=0x200, is_boot_memory=False, algo=DATA_FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
