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
    0x4919b5b0, 0x4a196808, 0x5098464b, 0x68024818, 0x511a4c18, 0x4c186902, 0x6942511a, 0x511a4c17,
    0x68544a17, 0x515c4d17, 0x079b6893, 0x4b18d408, 0x4b186013, 0x68536013, 0x43a32401, 0xe0036053,
    0x60134b11, 0x60134b11, 0x600a2200, 0x0792688a, 0x4911d1fc, 0x21036001, 0x49106101, 0xf0006141,
    0x2000f81f, 0x46c0bdb0, 0x40064000, 0x00000010, 0x40020000, 0x00000004, 0x00000008, 0x0000000c,
    0x40052000, 0x00000014, 0x0000a518, 0x0000d826, 0x0000b631, 0x0000c278, 0x00010100, 0x00030003,
    0x68014803, 0x68016001, 0xd5fc0609, 0x46c04770, 0x40020004, 0x464a4911, 0x48115853, 0x58516003,
    0x23036882, 0x42994013, 0x480ed1fa, 0x58084649, 0x60104a0d, 0x5808480d, 0x480d6110, 0x61505808,
    0x6881480c, 0xd4070789, 0x6001490b, 0x6001490b, 0x464a490b, 0x60415851, 0x47702000, 0x00000010,
    0x40064000, 0x00000004, 0x40020000, 0x00000008, 0x0000000c, 0x40052000, 0x0000b631, 0x0000c278,
    0x00000014, 0x2400b510, 0xf0004620, 0x2800f80d, 0x2001d108, 0x18200240, 0x29760a61, 0xd9f34604,
    0xbd102000, 0xbd102001, 0x490fb580, 0x600a4a0f, 0x600a4a0f, 0x030a2101, 0x680b490e, 0x600b4313,
    0x8f6ff3bf, 0x8f4ff3bf, 0x60034b0b, 0x06406848, 0xf3bfd5fc, 0xf3bf8f6f, 0x68088f4f, 0x60084390,
    0xf0002010, 0xbd80f80b, 0x40052000, 0x0000a518, 0x0000d826, 0x40020000, 0x12345678, 0x680a4909,
    0x4a09600a, 0x60134b09, 0x6048b2c0, 0x07c06808, 0x6808d102, 0xd5f90700, 0x48056809, 0x1e414008,
    0x47704188, 0x40020004, 0x40020200, 0xfd9573f5, 0x0700001e, 0xb081b5f0, 0x46064614, 0x91004f17,
    0x49184817, 0x49186001, 0x25016001, 0x6839032b, 0x60394319, 0x8f6ff3bf, 0x8f4ff3bf, 0x68222100,
    0x687a6032, 0xd5fc0652, 0x1d361c4a, 0x29001d24, 0xd0f44611, 0x8f6ff3bf, 0x8f4ff3bf, 0x43996839,
    0x46286039, 0xffbaf7ff, 0xd1042800, 0x39089900, 0xdcd42900, 0x46282500, 0xbdf0b001, 0x40020000,
    0x40052000, 0x0000a518, 0x0000d826, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x200000b9,
    'pc_program_page': 0x200001d9,
    'pc_erase_sector': 0x2000014d,
    'pc_eraseAll': 0x20000129,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000024c,
    'begin_stack' : 0x20001000,
    'end_stack' : 0x20000470,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000270,
        0x20000370
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x24c,
    'rw_start': 0x250,
    'rw_size': 0x4,
    'zi_start': 0x254,
    'zi_size': 0x14,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0xf000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}



class YTM32Z1ME0(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0xF000,      blocksize=0x200, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x1000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
