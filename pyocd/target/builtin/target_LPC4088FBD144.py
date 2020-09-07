# pyOCD debugger
# Copyright (c) 2006-2016 Arm Limited
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
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap, DefaultFlashWeights)
from ...debug.svd.loader import SVDFile

LARGE_PAGE_START_ADDR = 0x10000
SMALL_PAGE_SIZE = 0x1000
LARGE_PAGE_SIZE = 0x8000
LARGE_TO_SMALL_RATIO = LARGE_PAGE_SIZE / SMALL_PAGE_SIZE
LARGE_ERASE_SECTOR_WEIGHT = DefaultFlashWeights.ERASE_SECTOR_WEIGHT * LARGE_TO_SMALL_RATIO
LARGE_PROGRAM_PAGE_WEIGHT = DefaultFlashWeights.PROGRAM_PAGE_WEIGHT * LARGE_TO_SMALL_RATIO
WRITE_SIZE = 512

FLASH_ALGO = {
    'load_address' : 0x10000000,
    'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x28100b00, 0x210ebf24, 0x00d0eb01, 0xf6424770, 0x494d60e0, 0x60084449, 0x2100484c, 0x21aa7001,
    0x21557301, 0x21017301, 0x1c40f800, 0x47702000, 0x47702000, 0x41f0e92d, 0x20324c45, 0x2700444c,
    0x60a5251d, 0x0700e9c4, 0xf1044e42, 0x46200114, 0x696047b0, 0x2034b980, 0xe9c460a5, 0x483a0700,
    0x0114f104, 0x68004448, 0x462060e0, 0x696047b0, 0xbf082800, 0x81f0e8bd, 0xe8bd2001, 0xb57081f0,
    0x2c100b04, 0x200ebf24, 0x04d4eb00, 0x4d302032, 0x444d4e30, 0x0114f105, 0x0400e9c5, 0x60ac4628,
    0x696847b0, 0x2034b978, 0x0400e9c5, 0x60ac4826, 0xf1054448, 0x68000114, 0x462860e8, 0x696847b0,
    0xbf082800, 0x2001bd70, 0xe92dbd70, 0x461441f0, 0xd10e0005, 0x0100e9d4, 0xe9d44408, 0x44111202,
    0x69214408, 0x69614408, 0x69a14408, 0x42404408, 0x0b2961e0, 0xbf242910, 0xeb00200e, 0x203201d1,
    0x4f144e13, 0xe9c6444e, 0x60b10100, 0x0114f106, 0x47b84630, 0xb9986970, 0xe9c62033, 0xf44f0500,
    0xe9c67000, 0x48084002, 0x0114f106, 0x68004448, 0x46306130, 0x697047b8, 0xbf082800, 0x81f0e8bd,
    0xe8bd2001, 0x000081f0, 0x00000004, 0x400fc080, 0x00000008, 0x1fff1ff1, 0x00000000, 0x00000000,

    ],

    'pc_init' : 0x1000002F,
    'pc_unInit': 0x10000051,
    'pc_program_page': 0x100000EB,
    'pc_erase_sector': 0x1000009F,
    'pc_eraseAll' : 0x10000055,

    'static_base' : 0x10000000 + 0x00000020 + 0x00000200,
    'begin_stack' : 0x10000000 + 0x00000800,
    'page_buffers': [0x10000A00, 0x10000C00],
    'begin_data' : 0x10000000 + 0x00000A00, # Analyzer uses a max of 120 B data (30 pages * 4 bytes / page)
    'page_size' : 0x00001000,
    'min_program_length' : 512,
    'analyzer_supported' : True,
    'analyzer_address' : 0x10002000  # Analyzer 0x10002000..0x10002600
}


class LPC4088(CoreSightTarget):

    VENDOR = "NXP"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0,           length=0x10000,      is_boot_memory=True,
                                                                blocksize=0x1000,
                                                                page_size=0x200,
                                                                algo=FLASH_ALGO),
        FlashRegion(    start=0x10000,     length=0x70000,      blocksize=0x8000,
                                                                page_size=0x200,
                                                                erase_sector_weight=LARGE_ERASE_SECTOR_WEIGHT,
                                                                program_page_weight=LARGE_PROGRAM_PAGE_WEIGHT,
                                                                algo=FLASH_ALGO),
        RamRegion(      start=0x10000000,  length=0x10000),
        )

    def __init__(self, session, mem_map=None):
        if mem_map is None:
            mem_map = self.MEMORY_MAP
        super(LPC4088, self).__init__(session, mem_map)
        self.ignoreReset = False
        self._svd_location = SVDFile.from_builtin("LPC408x_7x_v0.7.svd")

    def reset(self, reset_type=None):
        # Use hardware reset since software reset cause a debug logic reset
        super(LPC4088, self).reset(self.ResetType.HW)

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        super(LPC4088, self).reset_and_halt(reset_type)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.write_memory(0x400FC040, 1)
            sp = self.read_memory(0x0)
            pc = self.read_memory(0x4)
            self.write_core_register('sp', sp)
            self.write_core_register('pc', pc)
