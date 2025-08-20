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
    0x48924601, 0x4a916840, 0x48916050, 0x60104a91, 0x4a8eb2c8, 0xbf006090, 0x6840488c, 0x0fc007c0,
    0xd1052800, 0x68404889, 0x40102208, 0xd1f32808, 0x68404886, 0x40104a88, 0xd0012800, 0x47702001,
    0xe7fc2000, 0x4603b510, 0x68004884, 0x444c4c84, 0x487e6020, 0x4c836800, 0x6020444c, 0x6900487b,
    0x444c4c81, 0x48796020, 0x4c806940, 0x6020444c, 0x6840487f, 0x444c4c7f, 0x487d6020, 0x24026880,
    0x28004020, 0x487cd10a, 0x60204c79, 0x6020487b, 0x68404620, 0x00400840, 0xe0046060, 0x4c744878,
    0x48786020, 0x20006020, 0x60204c6c, 0x486bbf00, 0x07806840, 0x28000f80, 0x4873d1f9, 0x60204c63,
    0x61202001, 0x61604871, 0x4620bf00, 0x60606840, 0xbf00bf00, 0x6840485d, 0x40202480, 0xd0f92800,
    0xbd102000, 0x485e4601, 0x68004448, 0x60104a5b, 0x485abf00, 0x07806840, 0x4a590f80, 0x6812444a,
    0xd1f64290, 0x44484857, 0x4a506800, 0x48566010, 0x68004448, 0x48556110, 0x68004448, 0x48546150,
    0x22026880, 0x28004010, 0x4853d108, 0x60104a50, 0x60104852, 0x4448484f, 0x60506800, 0x47702000,
    0x4842b510, 0x21016800, 0x43080309, 0x6008493f, 0x8f6ff3bf, 0x8f4ff3bf, 0x2100484d, 0xf3bf6008,
    0xf3bf8f6f, 0x20118f4f, 0xff4af7ff, 0xb510bd10, 0x48434604, 0x6008493e, 0x60084842, 0x68004833,
    0x03092101, 0x49314308, 0xf3bf6008, 0xf3bf8f6f, 0x483f8f4f, 0xbf006020, 0x6840482c, 0x40082140,
    0xd0f92800, 0x8f6ff3bf, 0x8f4ff3bf, 0x68004827, 0x03092101, 0x49254388, 0x20106008, 0xff20f7ff,
    0xb5f7bd10, 0x4604b082, 0x9e04460d, 0x20084627, 0x95009001, 0x482abf00, 0x60084925, 0x60084829,
    0x6800481a, 0x03092101, 0x49184308, 0xf3bf6008, 0xf3bf8f6f, 0x20008f4f, 0xce02e009, 0xbf00c702,
    0x68494912, 0x40112240, 0xd0f92900, 0x28021c40, 0xf3bfdbf3, 0xf3bf8f6f, 0x480c8f4f, 0x21016800,
    0x43880309, 0x60084909, 0xf7ff2001, 0x2800fee9, 0x2001d002, 0xbdf0b005, 0x98009901, 0x90001a40,
    0x28009800, 0x2000dcc7, 0x0000e7f4, 0x40020000, 0xfd9573f5, 0x40020200, 0x0700001e, 0x40064000,
    0x00000004, 0x00000008, 0x0000000c, 0x00000010, 0x40052000, 0x00000014, 0x0000b631, 0x0000c278,
    0x0000a518, 0x0000d826, 0x00010100, 0x00030003, 0x12345678, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000049,
    'pc_unInit': 0x200000e9,
    'pc_program_page': 0x200001c7,
    'pc_erase_sector': 0x20000173,
    'pc_eraseAll': 0x20000145,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000294,
    'begin_stack' : 0x200014b0,
    'end_stack' : 0x200004b0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200002b0,
        0x200003b0
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x294,
    'rw_start': 0x298,
    'rw_size': 0x18,
    'zi_start': 0x2b0,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0xc000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}



class YTM32Z1MD0(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0xC000,      blocksize=0x200, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
