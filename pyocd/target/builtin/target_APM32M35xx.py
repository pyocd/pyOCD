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
    0x9002b083, 0x92009101, 0x20004904, 0x4a046008, 0x60114904, 0x60114904, 0x4770b003, 0x40022000,
    0x40022004, 0x45670123, 0xcdef89ab, 0x9000b081, 0x68084903, 0x43102280, 0x20006008, 0x4770b001,
    0x40022010, 0x480fe7ff, 0x07c06800, 0xd0012800, 0xe7f8e7ff, 0x6808490c, 0x43102204, 0x68086008,
    0x43102240, 0xe7ff6008, 0x68004806, 0x280007c0, 0xe7ffd001, 0x4904e7f8, 0x22026808, 0x60084390,
    0x47702000, 0x4002200c, 0x40022010, 0x9000b081, 0x4810e7ff, 0x07c06800, 0xd0012800, 0xe7f8e7ff,
    0x6808490d, 0x43102204, 0x68086008, 0x43102240, 0xe7ff6008, 0x68004807, 0x280007c0, 0xe7ffd001,
    0x4905e7f8, 0x22026808, 0x60084390, 0xb0012000, 0x46c04770, 0x4002200c, 0x40022010, 0x9003b085,
    0x92019102, 0x90009801, 0x1c409802, 0x90020840, 0x88009800, 0x78119a01, 0x02127852, 0x42881889,
    0xe7ffd003, 0x90042001, 0xe7ffe02d, 0x28009802, 0xe7ffd026, 0x4815e7ff, 0x07c06800, 0xd0012800,
    0xe7f8e7ff, 0x68084912, 0x43102201, 0x98006008, 0x9b038800, 0x68088018, 0x60084390, 0x88009803,
    0x88099900, 0xd10a4288, 0x9803e7ff, 0x90031c80, 0x1c809800, 0x98029000, 0x90021e40, 0xe7d5e7ff,
    0x90042000, 0x9804e7ff, 0x4770b005, 0x4002200c, 0x40022010, 0x00000000, 0x00000000
    ],
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000031,
    'pc_program_page': 0x200000e1,
    'pc_erase_sector': 0x20000091,
    'pc_eraseAll': 0x20000049,
    'static_base': 0x20000000 + 0x00000004 + 0x00000174,
    'begin_stack': 0x20001380,
    'end_stack': 0x20000380,
    'page_size': 0x100,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000180, 0x20000280],
    'min_program_length': 0x100,
    'ro_start': 0x4,
    'ro_size': 0x174,
    'rw_start': 0x178,
    'rw_size': 0x4,
    'zi_start': 0x17c,
    'zi_size': 0x4,
    'flash_start': 0x08000000,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}


class APM32M35xx(CoreSightTarget):
    VENDOR = "Geehy"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x08000000, length=0x10000, blocksize=0x400, page_size=0x100,
            is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x20000000, length=0x2000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
