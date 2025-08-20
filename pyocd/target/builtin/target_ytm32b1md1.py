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
    0x489f4601, 0x4a9e6840, 0x489e6050, 0x60104a9e, 0x4a9bb2c8, 0xbf006090, 0x68404899, 0x0fc007c0,
    0xd1052800, 0x68404896, 0x40102208, 0xd1f32808, 0x68404893, 0x4010224e, 0xd0012800, 0x47702001,
    0xe7fc2000, 0x4603b510, 0x68004890, 0x444c4c90, 0x488e6020, 0x4c8f6900, 0x6020444c, 0x6840488b,
    0x444c4c8d, 0x48896020, 0x68003040, 0x444c4c8b, 0x48836020, 0x4c8a6800, 0x6020444c, 0x69004880,
    0x444c4c88, 0x487e6020, 0x4c876940, 0x6020444c, 0x68404886, 0x444c4c86, 0x20006020, 0x34404c7b,
    0xf3bf6020, 0x48798f4f, 0x24016900, 0x4c774320, 0x487e6120, 0x24026880, 0x28004020, 0x487dd10a,
    0x60204c7a, 0x6020487c, 0x68404620, 0x00400840, 0xe0046060, 0x4c754879, 0x48796020, 0x20036020,
    0x60204c6a, 0x4869bf00, 0x07806880, 0x28030f80, 0x2001d1f9, 0x60604c65, 0x4864bf00, 0x280168c0,
    0xbf00d1fb, 0x68804861, 0x40202404, 0xd1f92804, 0x4c5e2000, 0xbf006020, 0x6880485c, 0x0f800780,
    0xd1f92800, 0x4c564867, 0x48676020, 0x48676120, 0xbf006160, 0x68404620, 0xbf006060, 0x4850bf00,
    0x24806840, 0x28004020, 0x2000d0f9, 0x4601bd10, 0x44484851, 0x4a4d6800, 0xbf006050, 0x68c0484b,
    0x444a4a4d, 0x42906812, 0x4849d1f8, 0x68004448, 0x60104a46, 0x4845bf00, 0x07806880, 0x4a440f80,
    0x6812444a, 0xd1f64290, 0x44484842, 0x4a3f6800, 0x48426110, 0x68004448, 0x32404a3c, 0x48406010,
    0x68004448, 0x60104a36, 0x4448483e, 0x61106800, 0x4448483d, 0x61506800, 0x6880483c, 0x40102202,
    0xd1082800, 0x4a39483b, 0x483b6010, 0x48386010, 0x68004448, 0x20006050, 0xb5104770, 0x483c2400,
    0x60082100, 0xf7ff2012, 0x4304ff0b, 0x21014838, 0x60080489, 0xf7ff2012, 0x4304ff03, 0xbd104620,
    0x4604b510, 0x4929482d, 0x482d6008, 0xbf006008, 0x491b2000, 0x204e6088, 0xbf006048, 0x6020482c,
    0xf7ff2010, 0xbd10feed, 0xb082b5f7, 0x460f4606, 0x46359c04, 0x90012008, 0xbf009700, 0x491b481f,
    0x481f6008, 0xbf006008, 0x490d2000, 0x204e6088, 0xbf006048, 0xc501cc01, 0xc501cc01, 0xf7ff2002,
    0x2800fecf, 0x2001d002, 0xbdf0b005, 0x98009901, 0x90001a40, 0x28009800, 0x2000dce0, 0x0000e7f4,
    0x40010000, 0xfd9573f5, 0x40010200, 0x4007c000, 0x00000004, 0x00000008, 0x0000000c, 0x00000010,
    0x00000014, 0x00000018, 0x0000001c, 0x4006a000, 0x00000020, 0x0000b631, 0x0000c278, 0x0000a518,
    0x0000d826, 0x00300200, 0x00070014, 0x07d09c40, 0x12345678, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000049,
    'pc_unInit': 0x20000153,
    'pc_program_page': 0x2000022d,
    'pc_erase_sector': 0x20000205,
    'pc_eraseAll': 0x200001df,

    'static_base' : 0x20000000 + 0x00000004 + 0x000002d4,
    'begin_stack' : 0x20003500,
    'end_stack' : 0x20002500,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000300,
        0x20000400
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x2d4,
    'rw_start': 0x2d8,
    'rw_size': 0x24,
    'zi_start': 0x2fc,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x80000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}
class YTM32B1MD1(CoreSightTarget):

    VENDOR = "Yuntu Microelectronics"

    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x80000,      blocksize=0x400, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
