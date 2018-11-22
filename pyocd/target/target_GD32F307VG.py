"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from ..flash.flash import Flash
from ..core.coresight_target import (SVDFile, CoreSightTarget)
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)
import logging

DBG_CTL0 = 0xE0042004
#0111 1110 0011 1111 1111 1111 0000 0000
DBGCTL0_VAL = 0x7E3FFF00

flash_algo = {
				'load_address' : 0x20000000,

				# Flash algorithm as a hex string
				'instructions': [
								0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
								0xf36f4964, 0x44490012, 0x48636008, 0x60012100, 0x60424a62, 0x60414962, 0x64416442, 0x074069c0,
								0x4860d408, 0x5155f245, 0x21066001, 0xf6406041, 0x608171ff, 0x47702000, 0x69014857, 0x0180f041,
								0x6d016101, 0x0180f041, 0x20006501, 0x48524770, 0xf0416901, 0x61010104, 0xf0416901, 0x61010140,
								0x22aaf64a, 0xe000494f, 0x68c3600a, 0xd1fb07db, 0xf0236903, 0x61030304, 0xf0436d03, 0x65030304,
								0xf0436d03, 0x65030340, 0x600ae000, 0x07db6cc3, 0x6d01d1fb, 0x0104f021, 0x20006501, 0x493d4770,
								0x4449b510, 0x680c4a3f, 0xf504493b, 0xf64a2400, 0x42a023aa, 0x690cd212, 0x0402f044, 0x6148610c,
								0xf0406908, 0x61080040, 0x6013e000, 0x07c068c8, 0x6908d1fb, 0x0002f020, 0xe0116108, 0xf0446d0c,
								0x650c0402, 0x6d086548, 0x0040f040, 0xe0006508, 0x6cc86013, 0xd1fb07c0, 0xf0206d08, 0x65080002,
								0xbd102000, 0xb5104b23, 0x1cc9444b, 0x4b22681c, 0x2400f504, 0x0103f021, 0xd31942a0, 0x691ce035,
								0x0401f044, 0x6814611c, 0x68dc6004, 0xd1fc07e4, 0xf024691c, 0x611c0401, 0xf01468dc, 0xd0040f14,
								0xf04068d8, 0x60d80014, 0x1d00e01a, 0x1f091d12, 0xd1e42900, 0x6d1ce01b, 0x0401f044, 0x6814651c,
								0x6cdc6004, 0xd1fc07e4, 0xf0246d1c, 0x651c0401, 0xf0146cdc, 0xd0050f14, 0xf0406cd8, 0x64d80014,
								0xbd102001, 0x1d121d00, 0x29001f09, 0x2000d1e3, 0x0000bd10, 0x00000004, 0x40022000, 0x45670123,
								0xcdef89ab, 0x40003000, 0x00000000, 0x00000000
								],

				# Relative function addresses
				'pc_init':         0x20000021,
				'pc_unInit':       0x20000059,
				'pc_program_page': 0x20000125,
				'pc_erase_sector': 0x200000bf,
				'pc_eraseAll':     0x2000006f,

				'static_base' :    0x20000000 + 0x00000020 + 0x000001a8,
				'begin_stack' :    0x20000400,
				'begin_data' :     0x20000000 + 0x1000,
				'analyzer_supported' : True,
				'analyzer_address' : 0x20003000,
				'page_buffers' : [0x20001000, 0x20001800],   # Enable double buffering
				'min_program_length' : 0x4
			}

class Flash_gd32f307vg(Flash):

    def __init__(self, target):
        super(Flash_gd32f307vg, self).__init__(target, flash_algo)

class GD32F307VG(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x08000000,  length=0x80000,      blocksize=0x800, is_boot_memory=True),
		FlashRegion(    start=0x08080000,  length=0x80000,      blocksize=0x1000),
        RamRegion(      start=0x20000000,  length=0x18000)
        )

    def __init__(self, link):
        super(GD32F307VG, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile(vendor="GigaDevice", filename="GD32F30x_CL.svd", is_local=False)

    def create_init_sequence(self):
        seq = super(GD32F307VG, self).create_init_sequence()

        seq.insert_after('create_cores',
            ('setup_dbgmcu', self.setup_dbgmcu)
            )

        return seq

    def setup_dbgmcu(self):
        logging.debug('gd32f307vg init')
        self.write_memory(DBG_CTL0, DBGCTL0_VAL)



