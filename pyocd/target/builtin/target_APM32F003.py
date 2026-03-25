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

FLASH_ALGO = {
    'load_address': 0x20000EC4,
    'instructions': [
        0xe7fdbe00,
        0x4603b510, 0x4c472000, 0x48476020, 0x48476060, 0x46206060, 0x240469c0, 0x28004020, 0x2055d106,
        0x60204c43, 0x60602006, 0x60a020ff, 0xbd102000, 0x483c4601, 0x22806900, 0x4a3a4310, 0x20006110,
        0x48384770, 0x21046900, 0x49364308, 0x46086108, 0x21406900, 0x49334308, 0xe0026108, 0x493420aa,
        0x48306008, 0x07c068c0, 0x28000fc0, 0x482dd1f6, 0x21046900, 0x492b4388, 0x20006108, 0x46014770,
        0x69004828, 0x43102202, 0x61104a26, 0x61414610, 0x22406900, 0x4a234310, 0xe0026110, 0x4a2420aa,
        0x48206010, 0x07c068c0, 0x28000fc0, 0x481dd1f6, 0x22026900, 0x4a1b4390, 0x20006110, 0xb5104770,
        0x1c484603, 0x00490841, 0x4816e027, 0x24016900, 0x4c144320, 0x88106120, 0xe0028018, 0x4c1420aa,
        0x48106020, 0x07c068c0, 0x28000fc0, 0x480dd1f6, 0x08406900, 0x4c0b0040, 0x46206120, 0x241468c0,
        0x28004020, 0x4807d006, 0x432068c0, 0x60e04c05, 0xbd102001, 0x1c921c9b, 0x29001e89, 0x2000d1d5,
        0x0000e7f7, 0x40011000, 0x45670123, 0xcdef89ab, 0x40002000, 0x00000000,
    ],
    'pc_init': 0x20000EC9,
    'pc_unInit': 0x20000EF9,
    'pc_program_page': 0x20000F87,
    'pc_erase_sector': 0x20000F47,
    'pc_eraseAll': 0x20000F0B,
    'static_base': 0x20000FFC,
    'begin_stack': 0x200006C0,
    'end_stack': 0x20000000,
    'page_size': 0x400,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000AC0, 0x200006C0],
    'min_program_length': 0x400,
    'ro_start': 0x4,
    'ro_size': 0x154,
    'rw_start': 0x158,
    'rw_size': 0x4,
    'zi_start': 0x15C,
    'zi_size': 0x0,
    'flash_start': 0x00000000,
    'flash_size': 0x8000,
    'sector_sizes': (
        (0x0, 0x400),
    ),
}


class APM32F003x6(CoreSightTarget):
    """Geehy APM32F003x6 (APM32F003F6), 32 KB flash / 4 KB RAM."""

    VENDOR = "Geehy"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x00000000, length=0x8000, blocksize=0x400, page_size=0x400,
            is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x20000000, length=0x1000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
