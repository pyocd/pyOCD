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

_F0XX_INSTRUCTIONS = [
    0xe7fdbe00,
    0x49454846, 0x49466041, 0x21006041, 0x68c16001, 0x43112214, 0x69c060c1, 0xd4060740, 0x49414842,
    0x21066001, 0x49416041, 0x20006081, 0x483b4770, 0x22806901, 0x61014311, 0x47702000, 0x4837b530,
    0x241468c1, 0x60c14321, 0x25046901, 0x61014329, 0x22406901, 0x61014311, 0x4a334935, 0x6011e000,
    0x07db68c3, 0x6901d1fb, 0x610143a9, 0x422168c1, 0x68c1d004, 0x60c14321, 0xbd302001, 0xbd302000,
    0x4926b530, 0x231468ca, 0x60ca431a, 0x2402690a, 0x610a4322, 0x69086148, 0x43102240, 0x48246108,
    0xe0004a21, 0x68cd6010, 0xd1fb07ed, 0x43a06908, 0x68c86108, 0xd0034018, 0x431868c8, 0x200160c8,
    0xb5f0bd30, 0x1c494d15, 0x68eb0849, 0x24040049, 0x60eb4323, 0x4c162714, 0x692be01a, 0x43332601,
    0x8813612b, 0x4b108003, 0x601ce000, 0x07f668ee, 0x692bd1fb, 0x005b085b, 0x68eb612b, 0xd004423b,
    0x433868e8, 0x200160e8, 0x1c80bdf0, 0x1c921e89, 0xd1e22900, 0xbdf02000, 0x45670123, 0x40022000,
    0xcdef89ab, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa, 0x00000000,
]


def _flash_algo(page_size, flash_size):
    if page_size == 0x400:
        page_buffers = [0x20000140, 0x20000540]
        end_stack = 0x20000940
        begin_stack = 0x20001940
    else:
        page_buffers = [0x20000140, 0x20000940]
        end_stack = 0x20001140
        begin_stack = 0x20002140

    return {
        'load_address': 0x20000000,
        'instructions': list(_F0XX_INSTRUCTIONS),
        'pc_init': 0x20000005,
        'pc_unInit': 0x20000033,
        'pc_program_page': 0x200000c7,
        'pc_erase_sector': 0x20000085,
        'pc_eraseAll': 0x20000041,
        'static_base': 0x20000000 + 0x00000004 + 0x00000134,
        'begin_stack': begin_stack,
        'end_stack': end_stack,
        'page_size': page_size,
        'analyzer_supported': False,
        'analyzer_address': 0x00000000,
        'page_buffers': page_buffers,
        'min_program_length': page_size,
        'ro_start': 0x4,
        'ro_size': 0x134,
        'rw_start': 0x138,
        'rw_size': 0x4,
        'zi_start': 0x13c,
        'zi_size': 0x0,
        'flash_start': 0x08000000,
        'flash_size': flash_size,
        'sector_sizes': (
            (0x0, 0x1000),
        ),
    }


# F030/F051 1KB-page group:
# - 16/32/64 KB flash
# - 8 KB SRAM
FLASH_ALGO_F030_F051_1K_PAGE = _flash_algo(0x400, 0x10000)

# F070/F091 128KB group:
# - 128 KB flash
# - 16 KB SRAM for F070, 32 KB SRAM for F091
FLASH_ALGO_F070_F091_128K = _flash_algo(0x800, 0x20000)

# F030xC/F091xC 256KB group:
# - 256 KB flash
# - 32 KB SRAM
FLASH_ALGO_F030_F091_256K = _flash_algo(0x800, 0x40000)


def _make_map(flash_size, ram_size, algo):
    return MemoryMap(
        FlashRegion(start=0x08000000, length=flash_size, blocksize=0x1000, page_size=algo['page_size'],
            is_boot_memory=True, algo=algo),
        RamRegion(start=0x20000000, length=ram_size),
    )


class _APM32F0xxFamily(CoreSightTarget):
    VENDOR = "Geehy"

    def __init__(self, session, memory_map):
        super().__init__(session, memory_map)


# F030/F051 1KB-page group.
class APM32F030x8(_APM32F0xxFamily):
    MEMORY_MAP = _make_map(0x10000, 0x2000, FLASH_ALGO_F030_F051_1K_PAGE)

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)


# F030xC/F091xC 256KB group.
class APM32F030xC(_APM32F0xxFamily):
    MEMORY_MAP = _make_map(0x40000, 0x8000, FLASH_ALGO_F030_F091_256K)

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)


class APM32F051x8(_APM32F0xxFamily):
    MEMORY_MAP = _make_map(0x10000, 0x2000, FLASH_ALGO_F030_F051_1K_PAGE)

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)


# F070/F091 128KB group.
class APM32F072xB(_APM32F0xxFamily):
    MEMORY_MAP = _make_map(0x20000, 0x4000, FLASH_ALGO_F070_F091_128K)

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)


class APM32F091xC(_APM32F0xxFamily):
    MEMORY_MAP = _make_map(0x40000, 0x8000, FLASH_ALGO_F030_F091_256K)

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
