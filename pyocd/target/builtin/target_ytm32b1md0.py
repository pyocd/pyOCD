# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2021 Chris Reed
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
    0xe00abe00,
    0xb5704770, 0x460d4604, 0x48344616, 0x60084934, 0x60084834, 0x68404608, 0x00400840, 0x48326048,
    0x21206900, 0x49304308, 0x20036108, 0xbf006008, 0x6880482d, 0x0f800780, 0xd1f92803, 0x492a482b,
    0x20006048, 0xbf006008, 0x68804827, 0x0f800780, 0xd1f92800, 0xf836f000, 0x4601bd70, 0x47702000,
    0x2006b510, 0x72084922, 0xf82cf000, 0xb510bd10, 0xf7ff4604, 0x481fffc5, 0x20046020, 0x7208491c,
    0xf820f000, 0xb5f7bd10, 0x4607b082, 0x9c04460e, 0x2008463d, 0xbf009001, 0xc501cc01, 0xc501cc01,
    0x49132002, 0xf0007208, 0x2800f80d, 0x2001d002, 0xbdf0b005, 0x1a369801, 0xffa2f7ff, 0xd1eb2e00,
    0xe7f52000, 0x480abf00, 0x21807900, 0x28004008, 0x4807d0f9, 0x210c7900, 0x47704008, 0x0000b631,
    0x4006a000, 0x0000c278, 0x4007c000, 0x00010001, 0x40010000, 0x12345678, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000007,
    'pc_unInit': 0x2000005f,
    'pc_program_page': 0x2000008b,
    'pc_erase_sector': 0x20000073,
    'pc_eraseAll': 0x20000065,

    'static_base' : 0x20000000 + 0x00000004 + 0x000000f8,
    'begin_stack' : 0x20000300,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x80,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001080],   # Enable double buffering
    'min_program_length' : 0x80,

    # Relative region addresses and sizes
    'ro_start': 0x0,
    'ro_size': 0xf8,
    'rw_start': 0xf8,
    'rw_size': 0x4,
    'zi_start': 0xfc,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x80000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}

class YTM32B1MD0(CoreSightTarget):

    VENDOR = "YTMicro"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x0000,           length=0x80000,      blocksize=0x800, is_boot_memory=True,
            algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x8000)
        )

    def __init__(self, session):
        super(YTM32B1MD0, self).__init__(session, self.MEMORY_MAP)

    def create_init_sequence(self):
        seq = super(YTM32B1MD0, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def create_cores(self):
        core0 = CortexM(self.session, self.aps[0], self.memory_map, 0)

        self.aps[0].core = core0

        core0.init()

        self.add_core(core0)
