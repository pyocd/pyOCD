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
from ..core.coresight_target import CoreSightTarget
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)

flash_algo = { 'load_address' : 0x20000000,
               'instructions' : [
                                 0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
                                 0x4c11b430, 0xbc3046a4, 0x20004760, 0x20004770, 0x23004770, 0x461ab510, 0x20144619, 0xfff0f7ff,
                                 0xbd102000, 0x2300b510, 0x461a4601, 0xf7ff2012, 0x2000ffe7, 0x460bbd10, 0x4601b510, 0xf7ff2022,
                                 0x2000ffdf, 0x0000bd10, 0x1fff1001, 0x00000000,
                                ],
               'pc_init'          : 0x2000002B,
               'pc_eraseAll'      : 0x20000033,
               'pc_erase_sector'  : 0x20000045,
               'pc_program_page'  : 0x20000057,
               'static_base'      : 0x2000006C,
               'begin_data'       : 0x20002000, # Analyzer uses a max of 256 B data (64 pages * 4 bytes / page)
               'begin_stack'      : 0x20004000,
               'page_size'        : 256,
               'analyzer_supported' : True,
               'analyzer_address' : 0x20001000 # Analyzer 0x20001000..0x20001600
              };


class Flash_w7500(Flash):

    def __init__(self, target):
        super(Flash_w7500, self).__init__(target, flash_algo)

class W7500(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x00000000,  length=0x20000,      blocksize=0x100, isBootMemory=True),
        RamRegion(      start=0x20000000,  length=0x4000)
        )

    def __init__(self, link):
        super(W7500, self).__init__(link, self.memoryMap)

