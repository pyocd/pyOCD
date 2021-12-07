# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2021 Major Lin
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
    0xe00abe00,
    0xb5704770, 0x460d4604, 0x48454616, 0x49447e40, 0x48447648, 0x60084944, 0x60084844, 0x68404608,
    0x00400840, 0xf0006048, 0xf000f851, 0xbd70f843, 0x20004601, 0xb5104770, 0x493920ff, 0x483c7648,
    0x60082100, 0x49362041, 0xf00076c8, 0xbd10f833, 0x4604b510, 0xffd4f7ff, 0x493120ff, 0x48357648,
    0x20406020, 0xf00076c8, 0xbd10f825, 0x4605b5fe, 0x4616460c, 0x95014637, 0x90002004, 0x20ffbf00,
    0x76484927, 0x98016839, 0x20206001, 0x76c84924, 0xf810f000, 0xd0012800, 0xbdfe2001, 0x98011d3f,
    0x90011d00, 0x1a249800, 0xffaaf7ff, 0xd1e62c00, 0xe7f22000, 0x481abf00, 0x21207e40, 0x28004008,
    0x4817d0f9, 0x21167e40, 0x47704008, 0x491b481a, 0x481b6248, 0x481b6248, 0x481b6248, 0x62486248,
    0x62484815, 0x60884819, 0x60884819, 0x60884819, 0x60884819, 0x48156088, 0x48186088, 0x48186008,
    0x48186008, 0x48186008, 0x60086008, 0x60084813, 0x68004803, 0x05892101, 0x49014388, 0x47706008,
    0x40020000, 0x0000b631, 0x40052000, 0x0000c278, 0x00001234, 0x12345678, 0x009f1b10, 0x40064000,
    0x409f1b10, 0x809f1b10, 0xc09f1b10, 0x0001001e, 0x4001001e, 0x8001001e, 0xc001001e, 0x0001220c,
    0x4001220c, 0x8001220c, 0xc001220c, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000007,
    'pc_unInit': 0x20000035,
    'pc_program_page': 0x20000071,
    'pc_erase_sector': 0x20000055,
    'pc_eraseAll': 0x2000003b,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000016c,
    'begin_stack' : 0x20000378,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x80,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001080],   # Enable double buffering
    'min_program_length' : 0x80,

    # Relative region addresses and sizes
    'ro_start': 0x0,
    'ro_size': 0x16c,
    'rw_start': 0x16c,
    'rw_size': 0x4,
    'zi_start': 0x170,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

class YTM32B1LD0(CoreSightTarget):

    VENDOR = "YTMicro"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x0000,           length=0x10000,      blocksize=0x200, is_boot_memory=True,
            algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
