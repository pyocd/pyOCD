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
    0x48714601, 0x4a706840, 0x29006050, 0x486fd005, 0x60104a6f, 0x4a6cb2c8, 0xbf006090, 0x6840486a,
    0x40102280, 0xd0f92800, 0x68404867, 0x40104a69, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x49642000, 0xf3bf6008, 0x48628f4f, 0x69003840, 0x43082101, 0x3940495f, 0x485f6108,
    0x6008495f, 0x6008485f, 0x68404608, 0x00400840, 0x20036048, 0x39404958, 0xbf006008, 0x38404856,
    0x07806880, 0x28030f80, 0x2001d1f8, 0x39404952, 0xbf006048, 0x38404850, 0x280168c0, 0xbf00d1fa,
    0x3840484d, 0x21046880, 0x28044008, 0x2000d1f8, 0x39404949, 0x484c6008, 0x60084943, 0xf7ff2000,
    0xbd70ff9f, 0x20004601, 0xb5104770, 0x483e2400, 0x21016800, 0x43080309, 0x6008493b, 0x8f6ff3bf,
    0x8f4ff3bf, 0x21004841, 0xf3bf6008, 0xf3bf8f6f, 0x20118f4f, 0xff84f7ff, 0xf3bf1904, 0xf3bf8f6f,
    0x483a8f4f, 0x04492101, 0xf3bf6008, 0xf3bf8f6f, 0x20118f4f, 0xff74f7ff, 0x46201904, 0xb510bd10,
    0x48294604, 0x21016800, 0x43080309, 0x60084926, 0x8f6ff3bf, 0x8f4ff3bf, 0x6020482c, 0x8f6ff3bf,
    0x8f4ff3bf, 0x68004820, 0x03092101, 0x491e4388, 0x20106008, 0xff54f7ff, 0xb5f7bd10, 0x4604b082,
    0x9e04460d, 0x20084627, 0x95009001, 0x4816bf00, 0x21016800, 0x43080309, 0x60084913, 0x8f6ff3bf,
    0x8f4ff3bf, 0xe0022000, 0xc702ce02, 0x28021c40, 0xf3bfdbfa, 0xf3bf8f6f, 0x20018f4f, 0xff30f7ff,
    0xd0022800, 0xb0052001, 0x9901bdf0, 0x1a409800, 0x480f9000, 0x6008490a, 0x6008480e, 0x28009800,
    0x2000dcd5, 0x0000e7ef, 0x40010000, 0xfd9573f5, 0x40010200, 0x1f00001e, 0x4007c040, 0x0000b631,
    0x4006a000, 0x0000c278, 0x00288200, 0x12345678, 0x0000a518, 0x0000d826, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x200000c9,
    'pc_program_page': 0x2000015f,
    'pc_erase_sector': 0x20000123,
    'pc_eraseAll': 0x200000cf,

    'static_base' : 0x20000000 + 0x00000004 + 0x000001f8,
    'begin_stack' : 0x20002400,
    'end_stack' : 0x20001400,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x1f8,
    'rw_start': 0x1fc,
    'rw_size': 0x4,
    'zi_start': 0x200,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}
DATA_FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x48754601, 0x4a746840, 0x29006050, 0x4873d005, 0x60104a73, 0x4a70b2c8, 0xbf006090, 0x6840486e,
    0x40102280, 0xd0f92800, 0x6840486b, 0x40104a6d, 0xd0012800, 0x47702001, 0xe7fc2000, 0x4604b570,
    0x4616460d, 0x49682000, 0xf3bf6008, 0x48668f4f, 0x69003840, 0x43082101, 0x39404963, 0x48636108,
    0x60084963, 0x60084863, 0x68404608, 0x00400840, 0x20036048, 0x3940495c, 0xbf006008, 0x3840485a,
    0x07806880, 0x28030f80, 0x2001d1f8, 0x39404956, 0xbf006048, 0x38404854, 0x280168c0, 0xbf00d1fa,
    0x38404851, 0x21046880, 0x28044008, 0x2000d1f8, 0x3940494d, 0x48506008, 0x60084947, 0xf7ff2000,
    0xbd70ff9f, 0x20004601, 0x46024770, 0xe0064611, 0x1c406808, 0xd0012800, 0x47702001, 0x1dd01d09,
    0x30fa30ff, 0xd3f34281, 0xe7f62000, 0x4604b510, 0x68004839, 0x03092101, 0x49374308, 0xf3bf6008,
    0xf3bf8f6f, 0x483d8f4f, 0xf3bf6020, 0xf3bf8f6f, 0x48318f4f, 0x21016800, 0x43880309, 0x6008492e,
    0xf7ff2010, 0xbd10ff6d, 0x2500b570, 0x4c342400, 0x4620e00b, 0xffc9f7ff, 0xd0032800, 0xf7ff4620,
    0x1945ffd5, 0x34ff34ff, 0x482e3402, 0xd3f04284, 0xe00b4c2d, 0xf7ff4620, 0x2800ffb8, 0x4620d003,
    0xffc4f7ff, 0x34ff1945, 0x340234ff, 0x42844827, 0x4628d3f0, 0xb5f7bd70, 0x4604b082, 0x9e04460d,
    0x20084627, 0x95009001, 0x4813bf00, 0x21016800, 0x43080309, 0x60084910, 0x8f6ff3bf, 0x8f4ff3bf,
    0xe0022000, 0xc702ce02, 0x28021c40, 0xf3bfdbfa, 0xf3bf8f6f, 0x20018f4f, 0xff22f7ff, 0xd0022800,
    0xb0052001, 0x9901bdf0, 0x1a409800, 0x98009000, 0xdcda2800, 0xe7f42000, 0x40010000, 0xfd9573f5,
    0x40010200, 0x1f00001e, 0x4007c040, 0x0000b631, 0x4006a000, 0x0000c278, 0x00288200, 0x12345678,
    0x10001000, 0x10003800, 0x10011000, 0x10013800, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000041,
    'pc_unInit': 0x200000c9,
    'pc_program_page': 0x2000017b,
    'pc_erase_sector': 0x200000f1,
    'pc_eraseAll': 0x2000012d,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000210,
    'begin_stack' : 0x20002420,
    'end_stack' : 0x20001420,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x210,
    'rw_start': 0x214,
    'rw_size': 0x4,
    'zi_start': 0x218,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x10001000,
    'flash_size': 0x2800,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

class YTM32B1MC0(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x040000,      blocksize=0x200, is_boot_memory=True,  algo=MAIN_FLASH_ALGO),
        FlashRegion(    start=0x10001000,  length=0x002800,      blocksize=0x200, is_boot_memory=False, algo=DATA_FLASH_ALGO),
        FlashRegion(    start=0x10011000,  length=0x002800,      blocksize=0x200, is_boot_memory=False, algo=DATA_FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x10000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

