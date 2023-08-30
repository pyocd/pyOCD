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

FLASH_128k_ALGO = {
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

FLASH_512k_ALGO = {
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
    'flash_size': 0x80000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}

FLASH_1024k_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x4603b510, 0x04c00cd8, 0x444c4c83, 0x20006020, 0x60204c82, 0x60604882, 0x60604882, 0x64604880,
    0x64604880, 0x69c04620, 0x0004f000, 0xf245b940, 0x4c7d5055, 0x20066020, 0xf6406060, 0x60a070ff,
    0xbd102000, 0x48754601, 0xf0406900, 0x4a730080, 0x46106110, 0xf0406d00, 0x65100080, 0x47702000,
    0x6900486e, 0x0004f040, 0x6108496c, 0x69004608, 0x0040f040, 0xe0036108, 0x20aaf64a, 0x6008496a,
    0x68c04866, 0x0001f000, 0xd1f52800, 0x69004863, 0x0004f020, 0x61084961, 0x6d004608, 0x0004f040,
    0x46086508, 0xf0406d00, 0x65080040, 0xf64ae003, 0x495d20aa, 0x48596008, 0xf0006cc0, 0x28000001,
    0x4856d1f5, 0xf0206d00, 0x49540004, 0x20006508, 0x46014770, 0x44484850, 0xf5006800, 0x42812000,
    0x484ed21d, 0xf0406900, 0x4a4c0002, 0x46106110, 0x69006141, 0x0040f040, 0xe0036110, 0x20aaf64a,
    0x60104a49, 0x68c04845, 0x0001f000, 0xd1f52800, 0x69004842, 0x0002f020, 0x61104a40, 0x483fe01c,
    0xf0406d00, 0x4a3d0002, 0x46106510, 0x6d006541, 0x0040f040, 0xe0036510, 0x20aaf64a, 0x60104a3a,
    0x6cc04836, 0x0001f000, 0xd1f52800, 0x6d004833, 0x0002f020, 0x65104a31, 0x47702000, 0x4603b510,
    0xf0201c48, 0x482c0101, 0x68004448, 0x2000f500, 0xd2274283, 0x4829e023, 0xf0406900, 0x4c270001,
    0x88106120, 0xbf008018, 0x68c04824, 0x0001f000, 0xd1f92800, 0x69004821, 0x0001f020, 0x61204c1f,
    0x68c04620, 0x0014f000, 0x4620b130, 0xf04068c0, 0x60e00014, 0xbd102001, 0x1c921c9b, 0x29001e89,
    0xe026d1d9, 0x4815e023, 0xf0406d00, 0x4c130001, 0x88106520, 0xbf008018, 0x6cc04810, 0x0001f000,
    0xd1f92800, 0x6d00480d, 0x0001f020, 0x65204c0b, 0x6cc04620, 0x0014f000, 0x4620b130, 0xf0406cc0,
    0x64e00014, 0xe7d62001, 0x1c921c9b, 0x29001e89, 0x2000d1d9, 0x0000e7cf, 0x00000004, 0x40022000,
    0x45670123, 0xcdef89ab, 0x40003000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000049,
    'pc_program_page': 0x20000161,
    'pc_erase_sector': 0x200000d7,
    'pc_eraseAll': 0x20000065,

    'static_base' : 0x20000000 + 0x00000004 + 0x0000022c,
    'begin_stack' : 0x20001a40,
    'end_stack' : 0x20000a40,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000240,
        0x20000640
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x22c,
    'rw_start': 0x230,
    'rw_size': 0x8,
    'zi_start': 0x238,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x1000),
    )
}

class Air32F103xB(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x20000, 
                    blocksize=0x400, is_boot_memory=True,
                    algo=FLASH_128k_ALGO),
        RamRegion(start=0x2000_0000,  length=0x18000
        )
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR32F103xx.svd")

class Air32F103xC(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x40000, 
                    blocksize=0x400, is_boot_memory=True,
                    algo=FLASH_512k_ALGO),
        RamRegion(start=0x2000_0000,  length=0x18000
        )
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR32F103xx.svd")

class Air32F103xP(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x80000, 
                    blocksize=0x400, is_boot_memory=True,
                    algo=FLASH_512k_ALGO),
        RamRegion(start=0x2000_0000,  length=0x18000
        )
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR32F103xx.svd")

class Air32F103xE(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x80000, 
                    blocksize=0x400, is_boot_memory=True,
                    algo=FLASH_512k_ALGO),
        RamRegion(start=0x2000_0000,  length=0x18000
        )
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR32F103xx.svd")

class Air32F103xG(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x100000, 
                    blocksize=0x1000, is_boot_memory=True,
                    algo=FLASH_1024k_ALGO),
        RamRegion(start=0x2000_0000,  length=0x18000
        )
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR32F103xx.svd")
