# pyOCD debugger
# Copyright (c) 2026 Kai
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
from ...core.memory_map import FlashRegion, MemoryMap, RamRegion

_BMP561_INSTRUCTIONS = [
    0xe7fdbe00,
    0x493d483e, 0x6bc16001, 0x43912218, 0x6bc163c1, 0xd5fc0789, 0x22376841, 0x60414391, 0x22016881,
    0x60814311, 0x04126801, 0x60014311, 0x47702000, 0x47702000, 0x49324833, 0x49336001, 0x68816001,
    0x0f490309, 0xd1fa2903, 0x07496881, 0x68c1d4fc, 0x4391220c, 0x68c160c1, 0x43112206, 0x68c160c1,
    0x43112201, 0x492960c1, 0x601106d2, 0x07496881, 0x4927d4fc, 0x20006001, 0x49224770, 0x600a4a20,
    0x600a4a21, 0x0312688a, 0x2a030f52, 0x688ad1fa, 0xd4fc0752, 0x230c68ca, 0x60ca439a, 0x60ca68ca,
    0x230168ca, 0x60ca431a, 0x60024a18, 0x07406888, 0x4817d4fc, 0x20006008, 0xb5304770, 0x4c104b11,
    0x4c11601c, 0x689c601c, 0x0f640324, 0xd1fa2c03, 0x0764689c, 0x2502d4fc, 0x689ce008, 0xd4fc0764,
    0x432c68dc, 0xca1060dc, 0x1f09c010, 0xd1f42900, 0x60184807, 0xbd302000, 0x000087e4, 0x40010000,
    0x96969696, 0x40020000, 0x3c3c3c3c, 0x0000a5a5, 0x12345678, 0x00000000,
]


def _bmp561_flash_algo(flash_start: int, flash_size: int) -> dict:
    return {
        'load_address': 0x20000000,
        'instructions': list(_BMP561_INSTRUCTIONS),
        'pc_init': 0x20000005,
        'pc_unInit': 0x20000035,
        'pc_program_page': 0x200000bf,
        'pc_erase_sector': 0x2000007f,
        'pc_eraseAll': 0x20000039,
        'static_base': 0x20000000 + 0x00000004 + 0x00000114,
        'begin_stack': 0x20001520,
        'end_stack': 0x20000520,
        'page_size': 0x200,
        'analyzer_supported': False,
        'analyzer_address': 0x00000000,
        'page_buffers': [0x20000120, 0x20000320],
        'min_program_length': 0x200,
        'ro_start': 0x4,
        'ro_size': 0x114,
        'rw_start': 0x118,
        'rw_size': 0x4,
        'zi_start': 0x11c,
        'zi_size': 0x0,
        'flash_start': flash_start,
        'flash_size': flash_size,
        'sector_sizes': (
            (0x0, 0x200),
        ),
    }


FLASH_ALGO_64K = _bmp561_flash_algo(0x08000000, 0x10000)
FLASH_ALGO_DATA = _bmp561_flash_algo(0x08010000, 0x1000)


class BMP561(CoreSightTarget):
    """Geehy BMP561: 64 KB main flash + 4 KB data flash + 8 KB SRAM (Cortex-M0+)."""

    VENDOR = "Geehy"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x08000000, length=0x10000, blocksize=0x200, page_size=0x200,
            is_boot_memory=True, algo=FLASH_ALGO_64K),
        FlashRegion(start=0x08010000, length=0x1000, blocksize=0x200, page_size=0x200,
            is_boot_memory=False, algo=FLASH_ALGO_DATA),
        RamRegion(start=0x20000000, length=0x2000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
