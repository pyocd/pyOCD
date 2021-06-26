# pyOCD debugger
# Copyright (c) 2021 Huada Semiconductor Corporation
# Copyright (c) 2021 Chris Reed
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


#DEBUG_ACTIVE
DEBUG_ACTIVE = 0x40002038
DEBUG_ACTIVE_VAL = 0x00000FFF

FLASH_ALGO = { 
    'load_address' : 0x20000000,
    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4770ba40, 0x4770bac0, 0x4c5fb570, 0x06806820, 0xd0210f85, 0xf8b2f000, 0x21016820, 0x60204308,
    0x050068e0, 0xf000d5fc, 0x6820f8a9, 0x43882130, 0xf0006020, 0x2d01f8a3, 0x2d02d004, 0x2d03d005,
    0xe005d10a, 0x21026820, 0x6820e004, 0xe0012104, 0x21086820, 0x60204388, 0xf890f000, 0x21ff6820,
    0x438831c1, 0xf0006020, 0x6820f889, 0x026d2503, 0x602043a8, 0xf882f000, 0x43a868e0, 0xf00060e0,
    0x4c42f877, 0x60202020, 0xf872f000, 0x60602017, 0xf86ef000, 0x60a0201b, 0xf86af000, 0x60e0483c,
    0xf866f000, 0x6120483b, 0xf862f000, 0x61602018, 0xf85ef000, 0x61a020f0, 0xf85af000, 0x00c0207d,
    0x200061e0, 0x2000bd70, 0xb5704770, 0x6a204c2f, 0xd4fc06c0, 0xf84cf000, 0x6320482f, 0xf848f000,
    0x21036a20, 0x62204308, 0x602d2500, 0x06c06a20, 0xf000d4fc, 0x6325f83d, 0xbd702000, 0x4c23b570,
    0x6a214605, 0xd4fc06c8, 0xf832f000, 0x63204822, 0xf82ef000, 0x08806a20, 0x1c800080, 0x26006220,
    0x6a20602e, 0xd4fc06c0, 0xf822f000, 0x20006326, 0xb5f7bd70, 0x460f4616, 0xf0002400, 0x4d13f819,
    0x63284815, 0xf814f000, 0x08806a28, 0x1c400080, 0xe0066228, 0x5d319800, 0x6a285501, 0xd4fc06c0,
    0x42bc1c64, 0xf000d3f6, 0x2000f803, 0xbdfe6328, 0x490a4806, 0x490a62c1, 0x477062c1, 0x49074802,
    0x49076081, 0x47706081, 0x40002000, 0x40020000, 0x00004650, 0x000222e0, 0x0000ffff, 0x00005a5a,
    0x0000a5a5, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000029,
    'pc_unInit': 0x200000e7,
    'pc_program_page': 0x20000153,
    'pc_erase_sector': 0x2000011d,
    'pc_eraseAll': 0x200000eb,

    'static_base' : 0x20000000 + 0x00000020 + 0x000001a4,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0x600,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20000600],   
    'min_program_length' : 0x200,
  }


class HC32L110(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32L110, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32L110.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)


class HC32F003(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x4000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x800)
        )

    def __init__(self, session):
        super(HC32F003, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32F003.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)


class HC32F005(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32F005, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32F005.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)
