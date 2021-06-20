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
    0x4770ba40, 0x4770bac0, 0x4d6db570, 0x06006828, 0x486c0f44, 0x68e98900, 0x0d400540, 0x02c90ac9,
    0x60e94301, 0xd0262c00, 0xf8bcf000, 0x21016828, 0x60284308, 0x050068e8, 0xf000d5fc, 0x6828f8b3,
    0x438821e0, 0xf0006028, 0x2c01f8ad, 0x2c02d006, 0x2c03d007, 0x2c04d008, 0xe008d10d, 0x21026828,
    0x6828e007, 0xe0042104, 0x21086828, 0x6828e001, 0x43882110, 0xf0006028, 0x6828f895, 0x02092107,
    0x60284388, 0xf88ef000, 0x21036828, 0x438802c9, 0xf0006028, 0x4c4cf879, 0x60202020, 0xf874f000,
    0x60602017, 0xf870f000, 0x60a0201b, 0xf86cf000, 0x60e04846, 0xf868f000, 0x61204845, 0xf864f000,
    0x61602018, 0xf860f000, 0x61a020f0, 0xf85cf000, 0x00c0207d, 0x200061e0, 0x2000bd70, 0xb5704770,
    0x6a204c39, 0xd4fc06c0, 0xf84ef000, 0x43c02000, 0xf0006320, 0x6a20f849, 0x43082103, 0x25006220,
    0x6a20602d, 0xd4fc06c0, 0xf83ef000, 0x20006325, 0xb570bd70, 0x46054c2c, 0x06c86a21, 0xf000d4fc,
    0x2000f833, 0x632043c0, 0xf82ef000, 0x08806a20, 0x1c800080, 0x26006220, 0x6a20602e, 0xd4fc06c0,
    0xf822f000, 0x20006326, 0xb5f7bd70, 0x460f4616, 0xf0002400, 0x4d1cf819, 0x63281e60, 0xf814f000,
    0x08806a28, 0x1c400080, 0xe0066228, 0x5d319800, 0x6a285501, 0xd4fc06c0, 0x42bc1c64, 0xf000d3f6,
    0x2000f803, 0xbdfe6328, 0x6ac1480f, 0x0c094a11, 0x18890409, 0x6ac162c1, 0x0c094a0f, 0x18890409,
    0x477062c1, 0x68814806, 0x0c094a0a, 0x18890409, 0x68816081, 0x0c094a08, 0x18890409, 0x47706081,
    0x40002000, 0x00100c00, 0x40020000, 0x00004650, 0x000222e0, 0x00005a5a, 0x0000a5a5, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000029,
    'pc_unInit': 0x200000fb,
    'pc_program_page': 0x2000016b,
    'pc_erase_sector': 0x20000133,
    'pc_eraseAll': 0x200000ff,

    'static_base' : 0x20000000 + 0x00000020 + 0x000001dc,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0x800,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20000800],   # Enable double buffering
    'min_program_length' : 0x200,
  }


class HC32L136(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x10000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x2000)
        )

    def __init__(self, session):
        super(HC32L136, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32L136.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)


class HC32L130(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32L130, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32L130.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)


class HC32F030(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32F030, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32F030.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)
