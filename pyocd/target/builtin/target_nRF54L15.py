# Copyright (c) 2010 - 2023, Nordic Semiconductor ASA All rights reserved.
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

from ...core.memory_map import FlashRegion, RamRegion, MemoryMap
from ...debug.svd.loader import SVDFile
from ..family.target_nRF54L import NRF54L

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00,
    0xf8d24a02, 0x2b013400, 0x4770d1fb, 0x5004b000, 0x47702000, 0x47702000, 0x49072001, 0xf8c1b508,
    0xf7ff0500, 0xf8c1ffed, 0x20000540, 0xffe8f7ff, 0x0500f8c1, 0xbf00bd08, 0x5004b000, 0x2301b508,
    0xf8c14906, 0xf7ff3500, 0xf04fffdb, 0x600333ff, 0xf7ff2000, 0xf8c1ffd5, 0xbd080500, 0x5004b000,
    0x2301b538, 0x4d0c4614, 0x0103f021, 0x3500f8c5, 0xffc6f7ff, 0x44214622, 0x42911b00, 0x2000d105,
    0xffbef7ff, 0x0500f8c5, 0x4613bd38, 0x4b04f853, 0x461a5014, 0xbf00e7f1, 0x5004b000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000015,
    'pc_unInit': 0x20000019,
    'pc_program_page': 0x20000065,
    'pc_erase_sector': 0x20000041,
    'pc_eraseAll': 0x2000001d,

    'static_base' : 0x20000000 + 0x00000004 + 0x000000a0,
    'begin_stack' : 0x20000300,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x4,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001004],   # Enable double buffering
    'min_program_length' : 0x4,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x17d000,
    'sector_sizes': (
        (0x0, 0x17d000),
        (0xffd000, 0x1000),
    )
}

class NRF54L15(NRF54L):
    MEMORY_MAP = MemoryMap(
        FlashRegion(
            start=0x0,
            length=0x0017D000,
            blocksize=0x1000,
            is_boot_memory=True,
            algo=FLASH_ALGO,
        ),
        # User Information Configation Registers (UICR) as a flash region
        FlashRegion(
            start=0x00FFD000,
            length=0x1000,
            blocksize=0x4,
            is_testable=False,
            is_erasable=False,
            algo=FLASH_ALGO,
        ),
        RamRegion(start=0x20000000, length=0x40000),
    )

    def __init__(self, session):
        super(NRF54L15, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("nrf54l15.svd")
