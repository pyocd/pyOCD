# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
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

DBGMCU_CR = 0xE0042004
#0111 1110 0011 1111 1111 1111 0000 0000
DBGMCU_VAL = 0x7E3FFF00

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe00abe00,
    0x4603b510, 0x6900482d, 0x00800880, 0x4c2b1cc0, 0x20006120, 0x4601bd10, 0x47702000, 0x4a272000,
    0x48276290, 0x48276290, 0x21006290, 0x0248e006, 0x60504a22, 0x601020f1, 0xb2811c48, 0xddf629ff,
    0x4a1e2000, 0x47706290, 0x20004601, 0x62904a1b, 0x6290481b, 0x6290481b, 0x60414610, 0x601020f1,
    0x62902000, 0xb5304770, 0x46144603, 0x4d132000, 0x481362a8, 0x481362a8, 0x1cc862a8, 0xe0070881,
    0x6043480e, 0x4d0dcc01, 0x20f060a8, 0x1d1b6028, 0x1e494608, 0xd1f32800, 0x62a84d08, 0xb530bd30,
    0x06e42401, 0xe0041903, 0x7014781c, 0x1c521c5b, 0x460c1c40, 0x2c001e49, 0xbd30d1f6, 0x40022000,
    0x00112233, 0x55667788, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x2000001b,
    'pc_program_page': 0x2000006b,
    'pc_erase_sector': 0x2000004d,
    'pc_eraseAll': 0x20000021,

    'static_base' : 0x20000000 + 0x00000004 + 0x000000c8,
    'begin_stack' : 0x200002d0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000],
    'min_program_length' : 0x200,

    # Relative region addresses and sizes
    'ro_start': 0x0,
    'ro_size': 0xc8,
    'rw_start': 0xc8,
    'rw_size': 0x4,
    'zi_start': 0xcc,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

class VT32F0283LT(CoreSightTarget):

    VENDOR = "Vega"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x00010000,      blocksize=0x200, is_boot_memory=True,
            algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x00002000)
        )

    def __init__(self, session):
        super(VT32F0283LT, self).__init__(session, self.MEMORY_MAP)
        #self._svd_location = SVDFile.from_builtin("STM32F103xx.svd")

    # def post_connect_hook(self):
    #     self.write_memory(DBGMCU_CR, DBGMCU_VAL)



