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
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

FLASH_ALGO = {
    'load_address' : 0x10000000,
    'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x47700a80, 0x21004842, 0x22016301, 0x63416342, 0x6b416342, 0xd0fc07c9, 0x493e6382, 0x70082002,
    0x47702000, 0x47702000, 0x4c3bb5f8, 0x25002032, 0x261f444c, 0x493960a6, 0x60206065, 0x4f384449,
    0x91004620, 0x696047b8, 0xd10b2800, 0x203460a6, 0x60206065, 0x60e04833, 0x99004620, 0x696047b8,
    0xd0002800, 0xbdf82001, 0x4d2bb5f8, 0x444d0a84, 0x492a606c, 0x60ac2032, 0x60284449, 0x460f4e28,
    0x47b04628, 0x28006968, 0x606cd10b, 0x60ac2034, 0x48246028, 0x463960e8, 0x47b04628, 0x28006968,
    0x2001d000, 0xb5f8bdf8, 0x00054614, 0x6861d10e, 0x68e26820, 0x68a11840, 0x18401889, 0x18406921,
    0x18406961, 0x184069a1, 0x61e04240, 0x0aa84e12, 0x2132444e, 0x60316070, 0x60b04910, 0x4f104449,
    0x91004630, 0x697047b8, 0xd10e2800, 0x20336075, 0x603060b4, 0x02402001, 0x480a60f0, 0x46306130,
    0x47b89900, 0x28006970, 0x2001d000, 0x0000bdf8, 0x40048040, 0x40048000, 0x00000004, 0x00000018,
    0x1fff1ff1, 0x00002ee0, 0x00000000,
    ],

    'pc_init' : 0x10000025,
    'pc_erase_sector' : 0x10000089,
    'pc_program_page' : 0x100000C7,
    'pc_eraseAll' : 0x10000049,
    # Double buffering is not supported since sector size differs from page size
    'static_base' : 0x10000000 + 0x00000020 + 0x00000128,
    'begin_data' : 0x10000000 + 0x00000800, # Analyzer uses a max of 128 B data (32 pages * 4 bytes / page)
    'begin_stack' : 0x10000800,
    'min_program_length' : 1024,
    'analyzer_supported' : True,
    'analyzer_address' : 0x10001000  # Analyzer 0x10001000..0x10000600
}

class LPC824(CoreSightTarget):

    VENDOR = "NXP"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0,           length=0x8000,       is_boot_memory=True,
                                                                blocksize=1024,
                                                                page_size=512,
                                                                algo=FLASH_ALGO),
        RamRegion(      start=0x10000000,  length=0x2000)
        )

    def __init__(self, session):
        super(LPC824, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("LPC824.xml")

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        super(LPC824, self).reset_and_halt(reset_type)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.write_memory(0x40048000, 0x2, 32)
            sp = self.read_memory(0x0)
            pc = self.read_memory(0x4)
            self.write_core_register('sp', sp)
            self.write_core_register('pc', pc)
