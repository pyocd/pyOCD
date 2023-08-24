# pyOCD debugger
# Copyright (c) 2023 AirM2M
# Copyright (c) 2023 HalfSweet
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

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x4603b510, 0x04c00cd8, 0x444c4c47, 0x20006020, 0x60204c46, 0x60604846, 0x60604846, 0x69c04620,
    0x0004f000, 0xf245b940, 0x4c435055, 0x20066020, 0xf6406060, 0x60a070ff, 0xbd102000, 0x483b4601,
    0xf0406900, 0x4a390080, 0x20006110, 0x48374770, 0xf0406900, 0x49350004, 0x46086108, 0xf0406900,
    0x61080040, 0xf64ae003, 0x493320aa, 0x482f6008, 0xf00068c0, 0x28000001, 0x482cd1f5, 0xf0206900,
    0x492a0004, 0x20006108, 0x46014770, 0x69004827, 0x0002f040, 0x61104a25, 0x61414610, 0xf0406900,
    0x61100040, 0xf64ae003, 0x4a2320aa, 0x481f6010, 0xf00068c0, 0x28000001, 0x481cd1f5, 0xf0206900,
    0x4a1a0002, 0x20006110, 0xb5104770, 0x1c484603, 0x0101f020, 0x4815e023, 0xf0406900, 0x4c130001,
    0x88106120, 0xbf008018, 0x68c04810, 0x0001f000, 0xd1f92800, 0x6900480d, 0x0001f020, 0x61204c0b,
    0x68c04620, 0x0014f000, 0x4620b130, 0xf04068c0, 0x60e00014, 0xbd102001, 0x1c921c9b, 0x29001e89,
    0x2000d1d9, 0x0000e7f7, 0x00000004, 0x40022000, 0x45670123, 0xcdef89ab, 0x40003000, 0x00000000,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000041,
    'pc_program_page': 0x200000cf,
    'pc_erase_sector': 0x2000008f,
    'pc_eraseAll': 0x20000053,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000013c,
    'begin_stack' : 0x20001950,
    'end_stack' : 0x20000950,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000150,
        0x20000550
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x13c,
    'rw_start': 0x140,
    'rw_size': 0x8,
    'zi_start': 0x148,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}

class Air32F103xB(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x20000, 
                    blocksize=0x400, is_boot_memory=True,
                    algo=FLASH_ALGO),
        RamRegion(start=0x2000_0000,  length=0x18000
        )
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR32F103xx.svd")
