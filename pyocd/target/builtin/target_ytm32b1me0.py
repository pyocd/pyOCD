# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2021 Major Lin
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
from ...coresight.cortex_m import CortexM 
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)

FLASH_ALGO = {
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
    'begin_stack' : 0x200002e8,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x8,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001008],   # Enable double buffering
    'min_program_length' : 0x8,

    # Relative region addresses and sizes
    'ro_start': 0x0,
    'ro_size': 0xdc,
    'rw_start': 0xdc,
    'rw_size': 0x4,
    'zi_start': 0xe0,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}

class YTM32B1ME0(CoreSightTarget):

    VENDOR = "YTMicro"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x0000,           length=0x100000,      blocksize=0x800, is_boot_memory=True,
            algo=FLASH_ALGO),
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
