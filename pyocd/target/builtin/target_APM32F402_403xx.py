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
    0x4603b510, 0x4c452000, 0x48456020, 0x48456060, 0x46206060, 0x240469c0, 0x28004020, 0x4842d106,
    0x60204c42, 0x60602006, 0x60a04841, 0xbd102000, 0x483a4601, 0x22806900, 0x4a384310, 0x20006110,
    0x48364770, 0x21046900, 0x49344308, 0x46086108, 0x21406900, 0x49314308, 0xe0026108, 0x49334835,
    0x482e6008, 0x07c068c0, 0x28000fc0, 0x482bd1f6, 0x21046900, 0x49294388, 0x20006108, 0x46014770,
    0x69004826, 0x43102202, 0x61104a24, 0x61414610, 0x22406900, 0x4a214310, 0xe0026110, 0x4a234825,
    0x481e6010, 0x07c068c0, 0x28000fc0, 0x481bd1f6, 0x22026900, 0x4a194390, 0x20006110, 0xb5104770,
    0x1c484603, 0x00490841, 0x4814e024, 0x24016900, 0x4c124320, 0x88106120, 0xbf008018, 0x68c0480f,
    0x0fc007c0, 0xd1f92800, 0x6900480c, 0x00400840, 0x61204c0a, 0x68c04620, 0x40202414, 0xd0062800,
    0x68c04806, 0x4c054320, 0x200160e0, 0x1c9bbd10, 0x1e891c92, 0xd1d82900, 0xe7f72000, 0x40022000,
    0x45670123, 0xcdef89ab, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa, 0x00000000
    ],
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000035,
    'pc_program_page': 0x200000c3,
    'pc_erase_sector': 0x20000083,
    'pc_eraseAll': 0x20000047,
    'static_base': 0x20000000 + 0x00000004 + 0x00000138,
    'begin_stack': 0x20001940,
    'end_stack': 0x20000940,
    'page_size': 0x400,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000140, 0x20000540],
    'min_program_length': 0x400,
    'ro_start': 0x4,
    'ro_size': 0x138,
    'rw_start': 0x13c,
    'rw_size': 0x4,
    'zi_start': 0x140,
    'zi_size': 0x0,
    'flash_start': 0x8000000,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}


class _APM32F402_403Family(CoreSightTarget):
    VENDOR = "Geehy"

    def __init__(self, session, memory_map):
        super().__init__(session, memory_map)


class APM32F402xB(_APM32F402_403Family):
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x08000000, length=0x20000, blocksize=0x400, page_size=0x400,
            is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x20000000, length=0x8000)
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)


class APM32F403xB(_APM32F402_403Family):
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x08000000, length=0x20000, blocksize=0x400, page_size=0x400,
            is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x20000000, length=0x8000)
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
