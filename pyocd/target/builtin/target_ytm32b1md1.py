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

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x48414601, 0x4a406840, 0x29006050, 0x483fd005, 0x60104a3f, 0x4a3cb2c8, 0xbf006090, 0x6840483a,
    0x40102280, 0xd0f92800, 0x68404837, 0x4010220c, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x69004833, 0x43082101, 0x61084931, 0x49324831, 0x48326008, 0x46086008, 0x08406840,
    0x60480040, 0x492b2003, 0xbf006008, 0x68804829, 0x0f800780, 0xd1f92803, 0x49262001, 0xbf006048,
    0x68c04824, 0xd1fb2801, 0x4822bf00, 0x21046880, 0x28044008, 0x2000d1f9, 0x6008491e, 0x491a4821,
    0x20006008, 0xffacf7ff, 0x4601bd70, 0x47702000, 0x201eb510, 0xffa4f7ff, 0xb510bd10, 0x481a4604,
    0x20106020, 0xff9cf7ff, 0xb5f7bd10, 0x4606b082, 0x9c04460f, 0x20084635, 0x97009001, 0xcc01bf00,
    0xcc01c501, 0x2002c501, 0xff8af7ff, 0xd0022800, 0xb0052001, 0x9901bdf0, 0x1a409800, 0x98009000,
    0xdcec2800, 0xe7f42000, 0x40010000, 0xfd9573f5, 0x40010200, 0x4007c000, 0x0000b631, 0x4006a000,
    0x0000c278, 0x00308300, 0x12345678, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x200000af,
    'pc_program_page': 0x200000cf,
    'pc_erase_sector': 0x200000bf,
    'pc_eraseAll': 0x200000b5,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000012c,
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
    'ro_size': 0x12c,
    'rw_start': 0x130,
    'rw_size': 0x4,
    'zi_start': 0x134,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x80000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}
class YTM32B1MD1(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x80000,      blocksize=0x400, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
