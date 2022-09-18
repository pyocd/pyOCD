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

MAIN_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x484a4601, 0x4a496840, 0x29006050, 0x4848d005, 0x60104a48, 0x4a45b2c8, 0xbf006090, 0x68404843,
    0x40102280, 0xd0f92800, 0x68404840, 0x4010220c, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x6900483c, 0x43082101, 0x6108493a, 0x493b483a, 0x483b6008, 0x46086008, 0x08406840,
    0x60480040, 0x49342003, 0xbf006008, 0x68804832, 0x0f800780, 0xd1f92803, 0x492f2001, 0xbf006048,
    0x68c0482d, 0xd1fb2801, 0x482bbf00, 0x21046880, 0x28044008, 0x2000d1f9, 0x60084927, 0x4923482a,
    0x20006008, 0xffacf7ff, 0x4601bd70, 0x47702000, 0x2000b510, 0x6088491d, 0x68404608, 0x201e6048,
    0xff9ef7ff, 0xb510bd10, 0x20004604, 0x60884917, 0x68404608, 0x481d6048, 0x20106020, 0xff90f7ff,
    0xb5f7bd10, 0x4606b082, 0x9c04460f, 0x20084635, 0x97009001, 0x2000bf00, 0x6088490c, 0x68404608,
    0xcc016048, 0xcc01c501, 0x2002c501, 0xff78f7ff, 0xd0022800, 0xb0052001, 0x9901bdf0, 0x1a409800,
    0x98009000, 0xdce62800, 0xe7f42000, 0x40010000, 0xfd9573f5, 0x40010200, 0x4007c000, 0x0000b631,
    0x4006a000, 0x0000c278, 0x00308200, 0x12345678, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x200000af,
    'pc_program_page': 0x200000e7,
    'pc_erase_sector': 0x200000cb,
    'pc_eraseAll': 0x200000b5,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000150,
    'begin_stack' : 0x20001960,
    'end_stack' : 0x20000960,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000160,
        0x20000560
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x150,
    'rw_start': 0x154,
    'rw_size': 0x4,
    'zi_start': 0x158,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}
DATA_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x482f4601, 0x4a2e6840, 0x29006050, 0x482dd005, 0x60104a2d, 0x4a2ab2c8, 0xbf006090, 0x68404828,
    0x40102280, 0xd0f92800, 0x68404825, 0x4010220c, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x49224821, 0x48226008, 0x46086008, 0x08406840, 0x60480040, 0xf7ff2000, 0xbd70ffd1,
    0x20004601, 0xb5104770, 0xf7ff201e, 0xbd10ffc9, 0x4604b510, 0x60204818, 0xf7ff2010, 0xbd10ffc1,
    0xb082b5f7, 0x460f4606, 0x46359c04, 0x90012008, 0xbf009700, 0xc501cc01, 0xc501cc01, 0xf7ff2002,
    0x2800ffaf, 0x2001d002, 0xbdf0b005, 0x98009901, 0x90001a40, 0x28009800, 0x2000dcec, 0x0000e7f4,
    0x40010000, 0xfd9573f5, 0x40010200, 0x0000b631, 0x4006a000, 0x0000c278, 0x12345678, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x20000065,
    'pc_program_page': 0x20000085,
    'pc_erase_sector': 0x20000075,
    'pc_eraseAll': 0x2000006b,

    'static_base' : 0x20000000 + 0x00000004 + 0x000000dc,
    'begin_stack' : 0x200012f0,
    'end_stack' : 0x200002f0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200000f0,
        0x200001f0
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0xdc,
    'rw_start': 0xe0,
    'rw_size': 0x4,
    'zi_start': 0xe4,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x100000,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x100000, 0x400),
    )
}

class YTM32B1ME0(CoreSightTarget):

    VENDOR = "YTMicro"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x100000,      blocksize=0x800, is_boot_memory=True, algo=MAIN_FLASH_ALGO),
        FlashRegion(    start=0x00100000,  length=0x040000,      blocksize=0x400, is_boot_memory=False, algo=DATA_FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x10000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def create_init_sequence(self):
        # Insert init task to correct the ROM table base address value that incorrectly has the
        # P (preset) bit 0 cleared in hardware.

        def fixup_rom_base():
            self.aps[0].rom_addr = 0xE00FF000
            self.aps[0].has_rom_table = True
        
        seq = super().create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_aps', ('fixup_rom_base', fixup_rom_base))
            )
        return seq
