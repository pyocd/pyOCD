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
    0x48494601, 0x4a487e40, 0x29007650, 0x4847d002, 0x76d16390, 0x4844bf00, 0x22207e40, 0x28004010,
    0x2000d0f9, 0x63904a40, 0x7e404610, 0x40102216, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x493b483a, 0x483b6008, 0x46086008, 0x08406840, 0x60480040, 0x49394838, 0x48396088,
    0x48396088, 0x48396088, 0x60886088, 0x60884833, 0x60084837, 0x60084837, 0x60084837, 0x60084837,
    0x48336008, 0x48286008, 0x21016800, 0x43880589, 0x60084925, 0x61084832, 0x61484832, 0xf7ff2000,
    0xbd70ffaf, 0x20004601, 0xb5104770, 0x482e4604, 0x20406020, 0xffa4f7ff, 0xb510bd10, 0x482b2400,
    0xfff3f7ff, 0x482a1904, 0xffeff7ff, 0x48291904, 0xffebf7ff, 0x48281904, 0xffe7f7ff, 0x48271904,
    0x60082100, 0xf7ff2041, 0x1900ff8b, 0xb5f7bd10, 0x4604b082, 0x9e04460d, 0x20044627, 0x95009001,
    0xce01bf00, 0x2020c701, 0xff7af7ff, 0xd0022800, 0xb0052001, 0x9901bdf0, 0x1a409800, 0x98009000,
    0xdcee2800, 0xe7f42000, 0x40020000, 0x0065fe9a, 0x0000b631, 0x40052000, 0x0000c278, 0x0001001e,
    0x40064000, 0x4001001e, 0x8001001e, 0xc001001e, 0x0001220c, 0x4001220c, 0x8001220c, 0xc001220c,
    0x009c1388, 0x00b49c40, 0x12345678, 0x00400200, 0x00400400, 0x00400600, 0x00400800, 0x00001234,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x200000a9,
    'pc_program_page': 0x200000f3,
    'pc_erase_sector': 0x200000af,
    'pc_eraseAll': 0x200000bf,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000180,
    'begin_stack' : 0x20001390 + 0x2000,
    'end_stack' : 0x20000390 + 0x2000,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000190,
        0x20000290
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x180,
    'rw_start': 0x184,
    'rw_size': 0x4,
    'zi_start': 0x188,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

DATA_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x48484601, 0x4a477e40, 0x29007650, 0x76d1d000, 0x4844bf00, 0x22207e40, 0x28004010, 0x4841d0f9,
    0x22167e40, 0x28004010, 0x2001d001, 0x20004770, 0xb570e7fc, 0x460d4604, 0x483b4616, 0x6008493b,
    0x6008483b, 0x68404608, 0x00400840, 0x48396048, 0x60884939, 0x60884839, 0x60884839, 0x60884839,
    0x48346088, 0x48386088, 0x48386008, 0x48386008, 0x48386008, 0x60086008, 0x60084833, 0x68004829,
    0x05892101, 0x49274388, 0x48336008, 0x48336108, 0x48336148, 0x20006388, 0xffb2f7ff, 0x4601bd70,
    0x47702000, 0x4604b510, 0x6020482e, 0xf7ff2040, 0xbd10ffa7, 0x2400b510, 0xf7ff482b, 0x1904fff3,
    0xf7ff482a, 0x1904ffef, 0xf7ff4829, 0x1904ffeb, 0xf7ff4828, 0x1904ffe7, 0x21004827, 0x20416008,
    0xff8ef7ff, 0xbd101900, 0xb082b5f7, 0x460d4604, 0x46279e04, 0x90012004, 0xbf009500, 0xc701ce01,
    0xf7ff2020, 0x2800ff7d, 0x2001d002, 0xbdf0b005, 0x98009901, 0x90001a40, 0x28009800, 0x2000dcee,
    0x0000e7f4, 0x40020000, 0x0000b631, 0x40052000, 0x0000c278, 0x0001001e, 0x40064000, 0x4001001e,
    0x8001001e, 0xc001001e, 0x0001220c, 0x4001220c, 0x8001220c, 0xc001220c, 0x009c1388, 0x00b49c40,
    0x0065fe9a, 0x12345678, 0x00400200, 0x00400400, 0x00400600, 0x00400800, 0x00001234, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000037,
    'pc_unInit': 0x200000a3,
    'pc_program_page': 0x200000ed,
    'pc_erase_sector': 0x200000a9,
    'pc_eraseAll': 0x200000b9,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000017c,
    'begin_stack' : 0x20001390 + 0x2000,
    'end_stack' : 0x20000390 + 0x2000,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000190,
        0x20000290
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x17c,
    'rw_start': 0x180,
    'rw_size': 0x4,
    'zi_start': 0x184,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x400200,
    'flash_size': 0x800,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

class YTM32B1LD0(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x00000000,  length=0x10000,    blocksize=0x200, is_boot_memory=True, algo=MAIN_FLASH_ALGO),
        FlashRegion(start=0x00400200,  length=0x800,      blocksize=0x200, is_boot_memory=False, algo=DATA_FLASH_ALGO),
        RamRegion(  start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
