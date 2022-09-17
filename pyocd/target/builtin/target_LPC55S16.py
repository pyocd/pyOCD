# pyOCD debugger
# Copyright (c) 2022 PyOCD Authors
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

from ..family.target_lpc5500 import LPC5500Family
from ...core.memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xf240b580, 0xf2c00004, 0xf6420000, 0xf84961e0, 0xf2401000, 0xf2c52000, 0x21000000, 0x1080f8c0,
    0x1084f8c0, 0x1180f8c0, 0x71fbf647, 0xf6406001, 0x21ff6004, 0x0000f2c5, 0x01def2cc, 0xf04f6001,
    0x210240a0, 0xf2407001, 0xf2c00008, 0x44480000, 0xf860f000, 0xbf182800, 0xbd802001, 0x47702000,
    0xf240b580, 0xf2c00008, 0xf2460000, 0x4448636c, 0xf6c62100, 0xf44f3365, 0xf0003276, 0x2800f851,
    0x2001bf18, 0xbf00bd80, 0xf020b580, 0xf2404170, 0xf2c00008, 0xf2460000, 0x4448636c, 0x3365f6c6,
    0x7200f44f, 0xf83cf000, 0xbf182800, 0xbd802001, 0x460bb580, 0x4170f020, 0x0008f240, 0x0000f2c0,
    0xf5b34448, 0xbf987f00, 0x7300f44f, 0xf82ef000, 0xbf182800, 0xbd802001, 0x460cb5b0, 0xf0204605,
    0x46114070, 0xf0004622, 0x2800f872, 0x4425bf08, 0xbdb04628, 0x460ab580, 0x4170f020, 0x0008f240,
    0x0000f2c0, 0xf0004448, 0x2800f817, 0x2001bf18, 0x0000bd80, 0x018cf245, 0x3100f2c1, 0x47086809,
    0x3c4ff64a, 0x3c00f2c1, 0xbf004760, 0x3cb5f64a, 0x3c00f2c1, 0xbf004760, 0x3381f64a, 0x3300f2c1,
    0xbf004718, 0x4ca5f64a, 0x3c00f2c1, 0xbf004760, 0x03a0f245, 0x3300f2c1, 0x4718681b, 0x01a4f245,
    0x3100f2c1, 0x47086809, 0x01a8f245, 0x3100f2c1, 0x47086809, 0x03acf245, 0x3300f2c1, 0x4718681b,
    0x0cb4f245, 0x3c00f2c1, 0xc000f8dc, 0xbf004760, 0x02b8f245, 0x3200f2c1, 0x47106812, 0x02bcf245,
    0x3200f2c1, 0x47106812, 0x03c0f245, 0x3300f2c1, 0x4718681b, 0x02b0f245, 0x3200f2c1, 0x47106812,
    0x0cc8f245, 0x3c00f2c1, 0xc000f8dc, 0xea404760, 0xb5100301, 0xd10f079b, 0xd30d2a04, 0xc908c810,
    0x429c1f12, 0xba20d0f8, 0x4288ba19, 0x2001d901, 0xf04fbd10, 0xbd1030ff, 0x07d3b11a, 0x1c52d003,
    0x2000e007, 0xf810bd10, 0xf8113b01, 0x1b1b4b01, 0xf810d107, 0xf8113b01, 0x1b1b4b01, 0x1e92d101,
    0x4618d1f1, 0x0000bd10, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000061,
    'pc_program_page': 0x200000b5,
    'pc_erase_sector': 0x2000008d,
    'pc_eraseAll': 0x20000065,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000228,
    'begin_stack' : 0x20001670,
    'end_stack' : 0x20000670,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000270,
        0x20000470
    ],
    'min_program_length' : 0x200,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x228,
    'rw_start': 0x22c,
    'rw_size': 0x4,
    'zi_start': 0x230,
    'zi_size': 0x40,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x3d800,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

S_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xf240b580, 0xf2c00004, 0xf6420000, 0xf84961e0, 0xf2401000, 0xf2c52000, 0x21000000, 0x1080f8c0,
    0x1084f8c0, 0x1180f8c0, 0x71fbf647, 0xf6406001, 0x21ff6004, 0x0000f2c5, 0x01def2cc, 0xf04f6001,
    0x210240a0, 0xf2407001, 0xf2c00008, 0x44480000, 0xf860f000, 0xbf182800, 0xbd802001, 0x47702000,
    0xf240b580, 0xf2c00008, 0xf2460000, 0x4448636c, 0xf6c62100, 0xf44f3365, 0xf0003276, 0x2800f851,
    0x2001bf18, 0xbf00bd80, 0xf020b580, 0xf2404170, 0xf2c00008, 0xf2460000, 0x4448636c, 0x3365f6c6,
    0x7200f44f, 0xf83cf000, 0xbf182800, 0xbd802001, 0x460bb580, 0x4170f020, 0x0008f240, 0x0000f2c0,
    0xf5b34448, 0xbf987f00, 0x7300f44f, 0xf82ef000, 0xbf182800, 0xbd802001, 0x460cb5b0, 0xf0204605,
    0x46114070, 0xf0004622, 0x2800f872, 0x4425bf08, 0xbdb04628, 0x460ab580, 0x4170f020, 0x0008f240,
    0x0000f2c0, 0xf0004448, 0x2800f817, 0x2001bf18, 0x0000bd80, 0x018cf245, 0x3100f2c1, 0x47086809,
    0x3c4ff64a, 0x3c00f2c1, 0xbf004760, 0x3cb5f64a, 0x3c00f2c1, 0xbf004760, 0x3381f64a, 0x3300f2c1,
    0xbf004718, 0x4ca5f64a, 0x3c00f2c1, 0xbf004760, 0x03a0f245, 0x3300f2c1, 0x4718681b, 0x01a4f245,
    0x3100f2c1, 0x47086809, 0x01a8f245, 0x3100f2c1, 0x47086809, 0x03acf245, 0x3300f2c1, 0x4718681b,
    0x0cb4f245, 0x3c00f2c1, 0xc000f8dc, 0xbf004760, 0x02b8f245, 0x3200f2c1, 0x47106812, 0x02bcf245,
    0x3200f2c1, 0x47106812, 0x03c0f245, 0x3300f2c1, 0x4718681b, 0x02b0f245, 0x3200f2c1, 0x47106812,
    0x0cc8f245, 0x3c00f2c1, 0xc000f8dc, 0xea404760, 0xb5100301, 0xd10f079b, 0xd30d2a04, 0xc908c810,
    0x429c1f12, 0xba20d0f8, 0x4288ba19, 0x2001d901, 0xf04fbd10, 0xbd1030ff, 0x07d3b11a, 0x1c52d003,
    0x2000e007, 0xf810bd10, 0xf8113b01, 0x1b1b4b01, 0xf810d107, 0xf8113b01, 0x1b1b4b01, 0x1e92d101,
    0x4618d1f1, 0x0000bd10, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000061,
    'pc_program_page': 0x200000b5,
    'pc_erase_sector': 0x2000008d,
    'pc_eraseAll': 0x20000065,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000228,
    'begin_stack' : 0x20001670,
    'end_stack' : 0x20000670,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000270,
        0x20000470
    ],
    'min_program_length' : 0x200,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x228,
    'rw_start': 0x22c,
    'rw_size': 0x4,
    'zi_start': 0x230,
    'zi_size': 0x40,

    # Flash information
    'flash_start': 0x10000000,
    'flash_size': 0x3d800,
    'sector_sizes': (
        (0x0, 0x200),
    )
}


class LPC55S16(LPC5500Family):

    MEMORY_MAP = MemoryMap(
        FlashRegion(name='nsflash',     start=0x00000000, length=0x0003d800, access='rx',
            page_size=0x200,
            sector_size=0x200,
            is_boot_memory=True,
            are_erased_sectors_readable=False,
            algo=FLASH_ALGO),
        RomRegion(  name='nsrom',       start=0x03000000, length=0x00020000, access='rx'),
        RamRegion(  name='nscoderam',   start=0x04000000, length=0x00004000, access='rwx',
            default=False),
        FlashRegion(name='sflash',      start=0x10000000, length=0x0003d800, access='rx',
            page_size=0x200,
            sector_size=0x200,
            is_boot_memory=True,
            are_erased_sectors_readable=False,
            algo=S_FLASH_ALGO,
            alias='nsflash'),
        RomRegion(  name='srom',        start=0x13000000, length=0x00020000, access='srx',
            alias='nsrom'),
        RamRegion(  name='scoderam',    start=0x14000000, length=0x00004000, access='srwx',
            alias='nscoderam',
            default=False),
        RamRegion(  name='nsram',       start=0x20000000, length=0x00010000, access='rwx'),
        RamRegion(  name='sram',        start=0x30000000, length=0x00010000, access='srwx',
            alias='nsram'),
        )

    def __init__(self, session):
        super(LPC55S16, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("LPC55S16.xml")
