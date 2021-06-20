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
    0x4770ba40, 0x4770bac0, 0x6a014809, 0xd4fc06c9, 0x62c14908, 0x62c14908, 0x22036a01, 0x62014311,
    0x60092100, 0x06c96a01, 0x2000d4fc, 0x00004770, 0x40020000, 0x00005a5a, 0x0000a5a5, 0x6a0a4909,
    0xd4fc06d2, 0x62ca4a08, 0x62ca4a08, 0x08926a0a, 0x1c920092, 0x2200620a, 0x6a086002, 0xd4fc06c0,
    0x47702000, 0x40020000, 0x00005a5a, 0x0000a5a5, 0x2000b438, 0x70084669, 0x68014846, 0x0f4a0609,
    0x700a4669, 0x89094944, 0x054968c2, 0x0ad20d49, 0x430a02d2, 0x4a4160c2, 0x49416082, 0x68036081,
    0x022d2507, 0x600343ab, 0x60816082, 0x24016803, 0x60034323, 0x051b68c3, 0x466bd5fc, 0x2b00781b,
    0x6082d025, 0x68036081, 0x43a324e0, 0x60826003, 0x466b6081, 0x2b01781b, 0x2b02d006, 0x2b03d009,
    0x2b04d00c, 0xe00ed113, 0x24026803, 0x600343a3, 0x6803e00d, 0x43a32404, 0xe0086003, 0x24086803,
    0x600343a3, 0x6803e003, 0x43a32410, 0x60826003, 0x68036081, 0x600343ab, 0x60816082, 0x24036803,
    0x43a302e4, 0x6a036003, 0x43230524, 0x481d6203, 0x62c162c2, 0x240c6a03, 0x620343a3, 0x62c162c2,
    0x60032320, 0x62c162c2, 0x60432317, 0x62c162c2, 0x6083231b, 0x62c162c2, 0x60c34b13, 0x62c162c2,
    0x61034b12, 0x62c162c2, 0x61432318, 0x62c162c2, 0x618323f0, 0x62c162c2, 0x00db237d, 0x62c261c3,
    0x230062c1, 0x630343db, 0x62c162c2, 0xbc386343, 0x47702000, 0x40002000, 0x00100c00, 0x00005a5a,
    0x0000a5a5, 0x40020000, 0x00004650, 0x000222e0, 0x4b0db430, 0x25004c0b, 0x4c0c62dc, 0x6a1c62dc,
    0x00a408a4, 0x621c1c64, 0xd9072900, 0x55445d54, 0x06e46a1c, 0x1c6dd4fc, 0xd3f7428d, 0x2000bc30,
    0x00004770, 0x00005a5a, 0x40020000, 0x0000a5a5, 0x49054806, 0x4a0662c1, 0x230062c2, 0x62c16303,
    0x634362c2, 0x47704618, 0x00005a5a, 0x40020000, 0x0000a5a5, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000091,
    'pc_unInit': 0x20000211,
    'pc_program_page': 0x200001d1,
    'pc_erase_sector': 0x2000005d,
    'pc_eraseAll': 0x20000029,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000214,
    'begin_stack' : 0x20000500,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001200],   # Enable double buffering
    'min_program_length' : 0x200,
  }


class HC32L072(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x20000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x4000)
        )

    def __init__(self, session):
        super(HC32L072, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32L07x.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)


class HC32L073(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x20000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x4000)
        )

    def __init__(self, session):
        super(HC32L073, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32L07x.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)


class HC32F072(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x20000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x4000)
        )

    def __init__(self, session):
        super(HC32F072, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32L07x.svd")

    def post_connect_hook(self):
        self.write32(DEBUG_ACTIVE, DEBUG_ACTIVE_VAL)
