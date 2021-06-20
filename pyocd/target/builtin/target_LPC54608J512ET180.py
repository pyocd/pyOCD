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

FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x21002210, 0xf8c00690, 0x4a2c2630, 0xf0236813, 0x60134380, 0x1280f8c0, 0x1284f8c0, 0x68134a28,
    0x4370f423, 0xf8c06013, 0x21021380, 0x20006001, 0x20004770, 0xb5104770, 0x2000210f, 0xf844f000,
    0xbf182800, 0x4a1fbd10, 0xe8bd210f, 0x20004010, 0xb864f000, 0x0bc4b510, 0x46084621, 0xf834f000,
    0xbf182800, 0x4a17bd10, 0xe8bd4621, 0x46084010, 0xb854f000, 0x4614b570, 0xd10e0005, 0x0100e9d4,
    0xe9d44408, 0x44111202, 0x69214408, 0x69614408, 0x69a14408, 0x42404408, 0x0be861e0, 0xf0004601,
    0x2800f813, 0xbd70bf18, 0x46214b06, 0xe8bd4628, 0xf44f4070, 0xf0007280, 0x0000b818, 0x40000500,
    0x40000400, 0x00b71b00, 0xb08bb500, 0x92002232, 0x0101e9cd, 0x46684a39, 0x4790a906, 0x28009806,
    0xf600bf18, 0xb00b10c4, 0xb500bd00, 0xf04fb08b, 0x92030c33, 0xc000f8cd, 0x0101e9cd, 0x707af44f,
    0xf0f0fbb3, 0x4a2d9004, 0xa9064668, 0x98064790, 0xbf182800, 0x10c4f600, 0xbd00b00b, 0xb08bb500,
    0x93002334, 0x0101e9cd, 0x707af44f, 0xf0f0fbb2, 0x4a229003, 0xa9064668, 0x98064790, 0xbf182800,
    0x10c4f600, 0xbd00b00b, 0xb08bb500, 0x9300233b, 0x0101e9cd, 0x707af44f, 0xf0f0fbb2, 0x4a179003,
    0xa9064668, 0x98064790, 0xbf182800, 0x10c4f600, 0xbd00b00b, 0xb08bb500, 0x92002235, 0x0101e9cd,
    0x46684a0e, 0x4790a906, 0x28009806, 0xf600bf18, 0xb00b10c4, 0xb500bd00, 0x2338b08b, 0x93009203,
    0x0101e9cd, 0x46684a05, 0x4790a906, 0x28009806, 0xf600bf18, 0xb00b10c4, 0x0000bd00, 0x03000205,
    0x00000000
                                ],

    # Relative function addresses
    'pc_init': 0x20000021,
    'pc_program_page': 0x20000095,
    'pc_erase_sector': 0x20000075,
    'pc_eraseAll': 0x20000057,
    'begin_stack' : 0x20001000,
    'begin_data' : 0x20003000,
    'page_buffers' : [0x20003000],
    'static_base' : 0x200001dc,
    'page_size' : 0x00000100,
    'min_program_length' : 256,
    'analyzer_supported' : False
}

class LPC54608(CoreSightTarget):

    VENDOR = "NXP"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(name='flash',   start=0,           length=0x80000,  is_boot_memory=True,
                                                                        blocksize=0x8000,
                                                                        page_size=0x100,
                                                                        algo=FLASH_ALGO),
        RamRegion(  name='sramx',   start=0x04000000,  length=0x8000),
        RamRegion(  name='sram0',   start=0x20000000,  length=0x10000),
        RamRegion(  name='sram1',   start=0x20010000,  length=0x10000),
        RamRegion(  name='sram2',   start=0x20020000,  length=0x8000)
        )

    def __init__(self, session):
        super(LPC54608, self).__init__(session, self.MEMORY_MAP)
        self.ignoreReset = False
        self._svd_location = SVDFile.from_builtin("LPC54608.xml")

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        super(LPC54608, self).reset_and_halt(reset_type)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.write_memory(0x40000000, 0x2, 32)
            sp = self.read_memory(0x0)
            pc = self.read_memory(0x4)
            self.write_core_register('sp', sp)
            self.write_core_register('pc', pc)
