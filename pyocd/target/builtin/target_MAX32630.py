# pyOCD debugger
# Copyright (c) 2006-2013,2018 Arm Limited
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
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4603B510, 0x4893460C, 0x68414448, 0xF0006888, 0xB1087080, 0xBD102001, 0x4448488E, 0x60486880,
    0xE7F82000, 0x488B4602, 0x68414448, 0xF0206888, 0x60884070, 0x47702000, 0x44484886, 0x68886841,
    0x7080F000, 0x2001B108, 0x6A484770, 0x2000B148, 0x6A486248, 0x2002B128, 0x6A486248, 0x2001B108,
    0x6888E7F2, 0x4070F020, 0x5000F040, 0x20006088, 0xB510E7EA, 0x44484877, 0xF7FF6844, 0xB108FFDD,
    0xBD102001, 0xF42068A0, 0xF440407F, 0x60A0402A, 0xF04068A0, 0x60A00002, 0x68A0BF00, 0x7080F000,
    0xD1FA2800, 0xF02068A0, 0x60A04070, 0xF0006A60, 0xB1080002, 0xE7E42001, 0xE7E22000, 0x4605B570,
    0x44484864, 0xF7FF6844, 0xB108FFB7, 0xBD702001, 0xF42068A0, 0xF440407F, 0x60A040AA, 0x68A06025,
    0x0004F040, 0xBF0060A0, 0xF00068A0, 0x28007080, 0x68A0D1FA, 0x4070F020, 0x6A6060A0, 0x0002F000,
    0x2001B108, 0x2000E7E3, 0xE92DE7E1, 0x460747F0, 0x4690468A, 0x4448484F, 0x46566844, 0xF0084645,
    0xB1100003, 0xE8BD2001, 0x464587F0, 0xFF84F7FF, 0x2001B108, 0x68A0E7F7, 0x6000F020, 0x68A060A0,
    0x0010F040, 0xE00E60A0, 0xCD016027, 0x68A06320, 0x0001F040, 0xBF0060A0, 0xF00068A0, 0x28007080,
    0x1D3FD1FA, 0x2E041F36, 0xF007D303, 0x2800001F, 0x4838D1EA, 0x68C04448, 0xD1212880, 0xD31F2E10,
    0xF02068A0, 0x60A00010, 0xF04068A0, 0x60A06000, 0x6027E014, 0x6320CD01, 0x6360CD01, 0x63A0CD01,
    0x63E0CD01, 0xF04068A0, 0x60A00001, 0x68A0BF00, 0x7080F000, 0xD1FA2800, 0x3E103710, 0xD2E82E10,
    0xD3192E04, 0xF02068A0, 0x60A06000, 0xF04068A0, 0x60A00010, 0x6027E00E, 0x6320CD01, 0xF04068A0,
    0x60A00001, 0x68A0BF00, 0x7080F000, 0xD1FA2800, 0x1F361D3F, 0xD2EE2E04, 0x68A2B306, 0x6200F022,
    0x68A260A2, 0x0210F042, 0xF04F60A2, 0x21FF30FF, 0x682AE005, 0x0201EA62, 0x02094010, 0x2E001E76,
    0x6027D1F7, 0x68A26320, 0x0201F042, 0xBF0060A2, 0xF00268A2, 0x2A007280, 0xBF00D1FA, 0xF02068A0,
    0x60A04070, 0xF0006A60, 0xB1080002, 0xE76A2001, 0xE7682000, 0x00000004, 0x00000000, 0x00000000,
    # FLC_BASE,    CLK_DIV,  BRST_SIZE, FLASH_BASE, FLASH_SIZE, FLASH_SECTOR
    0x40002000, 0x00000060, 0x00000020, 0x00000000, 0x00200000, 0x00002000
                              ],
               'pc_init'            : 0x20000021,
               'pc_eraseAll'        : 0x20000093,
               'pc_erase_sector'    : 0x200000DD,
               'pc_program_page'    : 0x2000012B,
               'begin_data'         : 0x20004000,                 # Analyzer uses a max of 128B data (32 pages * 4 bytes / page)
               'page_buffers'       : [0x20006000, 0x20008000],   # Enable double buffering
               'begin_stack'        : 0x20002000,
               'static_base'        : 0x20000278,
               'min_program_length' : 4,
               'analyzer_supported' : True,
               'analyzer_address'   : 0x2000A000                  # Analyzer 0x2000A000..0x2000A600
              }

class MAX32630(CoreSightTarget):

    VENDOR = "Maxim"

    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0,           length=0x200000,  blocksize=0x2000, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x40000),
        )

    def __init__(self, session):
        super(MAX32630, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("max32630.svd")
