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
    0x483c4601, 0x4a3b7e40, 0x29007650, 0x76d1d000, 0x4838bf00, 0x22207e40, 0x28004010, 0x4835d0f9,
    0x22167e40, 0x28004010, 0x2001d001, 0x20004770, 0xb570e7fc, 0x460d4604, 0x482f4616, 0x6008492f,
    0x6008482f, 0x68404608, 0x00400840, 0x482d6048, 0x6088492d, 0x6088482d, 0x6088482d, 0x6088482d,
    0x48286088, 0x482c6088, 0x482c6008, 0x482c6008, 0x482c6008, 0x60086008, 0x60084827, 0x6800481d,
    0x05892101, 0x491b4388, 0x20006008, 0xffb8f7ff, 0x4601bd70, 0x47702000, 0x4823b510, 0x60082100,
    0xf7ff2041, 0xbd10ffad, 0x4604b510, 0x6020481f, 0xf7ff2040, 0xbd10ffa5, 0xb082b5f7, 0x460d4604,
    0x46279e04, 0x90012004, 0xbf009500, 0xc701ce01, 0xf7ff2020, 0x2800ff95, 0x2001d002, 0xbdf0b005,
    0x98009901, 0x90001a40, 0x28009800, 0x2000dcee, 0x0000e7f4, 0x40020000, 0x0000b631, 0x40052000,
    0x0000c278, 0x0001001e, 0x40064000, 0x4001001e, 0x8001001e, 0xc001001e, 0x0001220c, 0x4001220c,
    0x8001220c, 0xc001220c, 0x00001234, 0x12345678, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000037,
    'pc_unInit': 0x20000097,
    'pc_program_page': 0x200000bd,
    'pc_erase_sector': 0x200000ad,
    'pc_eraseAll': 0x2000009d,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000130,
    'begin_stack' : 0x20001340,
    'end_stack' : 0x20000340,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000140,
        0x20000240
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x130,
    'rw_start': 0x134,
    'rw_size': 0x4,
    'zi_start': 0x138,
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
    0x483e4601, 0x4a3d7e40, 0x29007650, 0x76d1d000, 0x483abf00, 0x22207e40, 0x28004010, 0x4837d0f9,
    0x22167e40, 0x28004010, 0x2001d001, 0x20004770, 0xb570e7fc, 0x460d4604, 0x48314616, 0x60084931,
    0x60084831, 0x68404608, 0x00400840, 0x482f6048, 0x6088492f, 0x6088482f, 0x6088482f, 0x6088482f,
    0x482a6088, 0x482e6088, 0x482e6008, 0x482e6008, 0x482e6008, 0x60086008, 0x60084829, 0x6800481f,
    0x05892101, 0x491d4388, 0x48296008, 0x20006388, 0xffb6f7ff, 0x4601bd70, 0x4a182000, 0x47706390,
    0x4824b510, 0x60082100, 0xf7ff2041, 0xbd10ffa9, 0x4604b510, 0x60204820, 0xf7ff2040, 0xbd10ffa1,
    0xb082b5f7, 0x460d4604, 0x46279e04, 0x90012004, 0xbf009500, 0xc701ce01, 0xf7ff2020, 0x2800ff91,
    0x2001d002, 0xbdf0b005, 0x98009901, 0x90001a40, 0x28009800, 0x2000dcee, 0x0000e7f4, 0x40020000,
    0x0000b631, 0x40052000, 0x0000c278, 0x0001001e, 0x40064000, 0x4001001e, 0x8001001e, 0xc001001e,
    0x0001220c, 0x4001220c, 0x8001220c, 0xc001220c, 0x0065fe9a, 0x00001234, 0x12345678, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000037,
    'pc_unInit': 0x2000009b,
    'pc_program_page': 0x200000c5,
    'pc_erase_sector': 0x200000b5,
    'pc_eraseAll': 0x200000a5,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000013c,
    'begin_stack' : 0x20001350,
    'end_stack' : 0x20000350,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000150,
        0x20000250
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x13c,
    'rw_start': 0x140,
    'rw_size': 0x4,
    'zi_start': 0x144,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x400200,
    'flash_size': 0x800,
    'sector_sizes': (
        (0x400200, 0x200),
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
