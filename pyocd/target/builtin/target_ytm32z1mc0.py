# pyOCD debugger
# Copyright (c) 2022 Yuntu Microelectronics
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


FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x48664601, 0x4a656840, 0x29006050, 0x4864d003, 0xb2c860d0, 0xbf006090, 0x68404860, 0x40102280,
    0xd0f92800, 0x6840485d, 0x4010224e, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570, 0x4616460d,
    0x68004858, 0x44494958, 0x48546008, 0x49576800, 0x60084449, 0x68404856, 0x44494956, 0x48546008,
    0x21026880, 0x28004008, 0x4853d10a, 0x60084950, 0x60084852, 0x68404608, 0x00400840, 0xe0046048,
    0x494b484f, 0x484f6008, 0x20006008, 0x60084945, 0x4844bf00, 0x07806840, 0x28000f80, 0x2081d1f9,
    0x493e0240, 0x20006008, 0xffaaf7ff, 0x4601bd70, 0x4448483d, 0x4a3b6800, 0xbf006010, 0x68404839,
    0x0f800780, 0x444a4a38, 0x42906812, 0x4837d1f6, 0x68004448, 0x60104a31, 0x4a354837, 0x48376010,
    0x48346010, 0x68004448, 0x20006050, 0xb5104770, 0x48334604, 0x6008492e, 0x60084832, 0x68004827,
    0x43084931, 0x60084925, 0x60204830, 0xf7ff2010, 0xbd10ff77, 0x2400b570, 0x02e5e008, 0xf7ff4628,
    0x2800ffe6, 0x2001d001, 0x1c64bd70, 0xd3f42c10, 0xe7f92000, 0xb084b5f7, 0x460d4604, 0x90039806,
    0x20804626, 0x95019002, 0x481dbf00, 0x60084918, 0x6008481c, 0x68004811, 0x4308491b, 0x6008490f,
    0xe0072700, 0x68009803, 0x9803c601, 0x90031d00, 0xb2471c78, 0xdbf52f20, 0xf7ff2002, 0x2800ff41,
    0x2001d002, 0xbdf0b007, 0x98019902, 0x90011a40, 0x28009801, 0x2000dcd9, 0x0000e7f4, 0x40020000,
    0xfd9573f5, 0x40064000, 0x00000004, 0x00000008, 0x40052000, 0x0000000c, 0x0000b631, 0x0000c278,
    0x0000a518, 0x0000d826, 0x00010280, 0x12345678, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x2000003d,
    'pc_unInit': 0x200000b3,
    'pc_program_page': 0x20000139,
    'pc_erase_sector': 0x200000f3,
    'pc_eraseAll': 0x20000119,

    'static_base' : 0x20000000 + 0x00000004 + 0x000001d0,
    'begin_stack' : 0x200012f0,
    'end_stack' : 0x200002f0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x80,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200001f0,
        0x20000270
    ],
    'min_program_length' : 0x80,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x1d0,
    'rw_start': 0x1d4,
    'rw_size': 0x10,
    'zi_start': 0x1e4,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x8000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}


class YTM32Z1MC0(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x8000,      blocksize=0x200, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
