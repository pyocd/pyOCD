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
    'load_address' : 0x20000000,
    'instructions': [
    0xe7fdbe00,
    0x0e000300, 0xd3022820, 0x1d000940, 0x28104770, 0x0900d302, 0x47701cc0, 0x47700880, 0x49414842,
    0x49426041, 0x21006041, 0x68c16001, 0x431122f0, 0x694060c1, 0xd4060680, 0x493d483e, 0x21066001,
    0x493d6041, 0x20006081, 0x48374770, 0x05426901, 0x61014311, 0x47702000, 0x4833b510, 0x24046901,
    0x61014321, 0x03a26901, 0x61014311, 0x4a314933, 0x6011e000, 0x03db68c3, 0x6901d4fb, 0x610143a1,
    0xbd102000, 0xf7ffb530, 0x4927ffbb, 0x23f068ca, 0x60ca431a, 0x610c2402, 0x06c0690a, 0x43020e00,
    0x6908610a, 0x431003e2, 0x48246108, 0xe0004a21, 0x68cd6010, 0xd4fb03ed, 0x43a06908, 0x68c86108,
    0x0f000600, 0x68c8d003, 0x60c84318, 0xbd302001, 0x4d15b570, 0x08891cc9, 0x008968eb, 0x433326f0,
    0x230060eb, 0x4b16612b, 0x692ce017, 0x612c431c, 0x60046814, 0x03e468ec, 0x692cd4fc, 0x00640864,
    0x68ec612c, 0x0f240624, 0x68e8d004, 0x60e84330, 0xbd702001, 0x1f091d00, 0x29001d12, 0x2000d1e5,
    0x0000bd70, 0x45670123, 0x40023c00, 0xcdef89ab, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa,
    0x00000201, 0x00000000
    ],
    'pc_init': 0x20000021,
    'pc_unInit': 0x2000004f,
    'pc_program_page': 0x200000d5,
    'pc_erase_sector': 0x20000089,
    'pc_eraseAll': 0x2000005d,
    'static_base': 0x20000000 + 0x00000004 + 0x00000144,
    'begin_stack': 0x20001950,
    'end_stack': 0x20000950,
    'page_size': 0x400,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000150, 0x20000550],
    'min_program_length': 0x400,
    'ro_start': 0x4,
    'ro_size': 0x144,
    'rw_start': 0x148,
    'rw_size': 0x4,
    'zi_start': 0x14c,
    'zi_size': 0x0,
    'flash_start': 0x8000000,
    'flash_size': 0x80000,
    'sector_sizes': (
        (0x0, 0x4000),
        (0x10000, 0x10000),
        (0x20000, 0x20000),
    )
}


class _APM32F411Family(CoreSightTarget):
    VENDOR = "Geehy"

    def __init__(self, session, memory_map):
        super().__init__(session, memory_map)


class APM32F411xE(_APM32F411Family):
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x08000000, length=0x10000, sector_size=0x4000, page_size=0x400,
            is_boot_memory=True, algo=FLASH_ALGO),
        FlashRegion(start=0x08010000, length=0x10000, sector_size=0x10000, page_size=0x400,
            algo=FLASH_ALGO),
        FlashRegion(start=0x08020000, length=0x60000, sector_size=0x20000, page_size=0x400,
            algo=FLASH_ALGO),
        RamRegion(start=0x20000000, length=0x20000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
