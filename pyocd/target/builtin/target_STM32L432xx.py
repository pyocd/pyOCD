# pyOCD debugger
# Copyright (c) 2020 Wagner Sartori Junior
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

class DBGMCU:
    CR = 0xE0042004
    CR_VALUE = 0x7 # DBG_STANDBY | DBG_STOP | DBG_SLEEP

    APB1FZR1 = 0xE0042008
    APB1FZR1_VALUE = 0b10000010111000000001110000110001

    APB1FZR2 = 0xE004200C
    APB1FZR2_VALUE = 0b00000000000000000000000000100000

    APB2FZR = 0xE0042010
    APB2FZR_VALUE = 0b00000000000000110000100000000000

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x8f4ff3bf, 0x48584770, 0x49586800, 0x0d000500, 0xd0001840, 0x47702001, 0x6a004855, 0x0fc00280,
    0xb5004770, 0xf7ff4602, 0x2801ffee, 0xf7ffd108, 0x2801fff3, 0x484fd104, 0xd3014282, 0xbd002001,
    0xbd002000, 0x4602b500, 0xffddf7ff, 0xd0022801, 0x0d8002d0, 0x4948bd00, 0x40080ad0, 0xd5f90391,
    0x300130ff, 0x4842bd00, 0x60814944, 0x60814944, 0x60012100, 0x61014943, 0x03c06a00, 0x4843d406,
    0x60014941, 0x60412106, 0x60814941, 0x47702000, 0x49372001, 0x614807c0, 0x47702000, 0x47702001,
    0x49384833, 0x13c16101, 0x69416141, 0x04122201, 0x61414311, 0x4a354937, 0x6011e000, 0x03db6903,
    0x2100d4fb, 0x46086141, 0xb5104770, 0xf7ff4604, 0x4603ffa8, 0xf7ff4620, 0x4925ffb5, 0x610c4c29,
    0x02d800c2, 0x43021c92, 0x6948614a, 0x04122201, 0x61484310, 0x8f4ff3bf, 0x4a244826, 0x6010e000,
    0x03db690b, 0x2000d4fb, 0x69086148, 0xd0014020, 0x2001610c, 0xb5f0bd10, 0x4d151dc9, 0x4f1908c9,
    0x612f00c9, 0x616b2300, 0xe0184c1a, 0x616b2301, 0x60036813, 0x60436853, 0x8f4ff3bf, 0xe0004b13,
    0x692e601c, 0xd4fb03f6, 0x616b2300, 0x423b692b, 0x612fd002, 0xbdf02001, 0x39083008, 0x29003208,
    0x2000d1e4, 0x0000bdf0, 0xe0042000, 0xfffffbcb, 0x40022000, 0x08020000, 0x000003bf, 0x45670123,
    0xcdef89ab, 0x0000c3fa, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000087,
    'pc_unInit': 0x200000b1,
    'pc_program_page': 0x20000137,
    'pc_erase_sector': 0x200000eb,
    'pc_eraseAll': 0x200000c1,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000198,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001400],   # Enable double buffering
    'min_program_length' : 0x400,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}

class STM32L432xC(CoreSightTarget):
        
    VENDOR = "STMicroelectronics"

    MEMORY_MAP = MemoryMap(
        FlashRegion(name='flash', start=0x08000000, length=0x40000,
                        sector_size=0x800,
                        page_size=0x400,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(name='sram1',   start=0x20000000, length=0xC000),
        RamRegion(name='sram2',   start=0x10000000, length=0x4000)
        )

    def __init__(self, session):
        super(STM32L432xC, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32L4x2.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1FZR1, DBGMCU.APB1FZR1_VALUE)
        self.write32(DBGMCU.APB1FZR2, DBGMCU.APB1FZR2_VALUE)
        self.write32(DBGMCU.APB2FZR, DBGMCU.APB2FZR_VALUE)

