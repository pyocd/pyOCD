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

DBGMCU_CR = 0xE0042004
#0111 1110 0011 1111 1111 1111 0000 0000
DBGMCU_VAL = 0x7E3FFF00

flash_algo = { 'load_address' : 0x20000000,
               'instructions' : [
                                  0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
                                  0x49384839, 0x49396041, 0x20006041, 0x49364770, 0x60c82034, 0x47702000, 0x47702000, 0xb5004a32,
                                  0x06006910, 0xf7ffd501, 0x68d0ffeb, 0xd1fc07c0, 0xf0406910, 0x61100004, 0xf0406910, 0x61100040,
                                  0x07c068d0, 0x6910d1fc, 0x0004f020, 0x20006110, 0x4a25bd00, 0x4603b500, 0x06006910, 0xf7ffd501,
                                  0x68d1ffcf, 0xd1fc07c9, 0xf0406910, 0x61100002, 0x69106153, 0x0040f040, 0x68d06110, 0xd1fc07c0,
                                  0xf0206910, 0x61100002, 0xbd002000, 0x4d16b570, 0x460e4603, 0x24006928, 0xd5010600, 0xffb0f7ff,
                                  0x07c068e8, 0xe014d1fc, 0x0001f040, 0x88106128, 0x68e88018, 0xd1fc07c0, 0x88198810, 0xd0054288,
                                  0xf0206928, 0x61280001, 0xbd702001, 0x1c9b1c92, 0x69281c64, 0x0f56ebb4, 0xf020d3e6, 0x61280001,
                                  0xbd702000, 0x45670123, 0x40022000, 0xcdef89ab, 0x00000000,
                                ],
               'pc_init'          : 0x2000002F,
               'pc_eraseAll'      : 0x2000003D,
               'pc_erase_sector'  : 0x20000073,
               'pc_program_page'  : 0x200000AD,
               'static_base'      : 0x20000200,
               'begin_data'       : 0x20001000, # Analyzer uses a max of 1 KB data (256 pages * 4 bytes / page)
               'page_buffers'    : [0x20001000, 0x20001800],   # Enable double buffering
               'begin_stack'      : 0x20002800,
               'min_program_length' : 2,
               'analyzer_supported' : True,
               'analyzer_address' : 0x20003000 # Analyzer 0x20003000..0x20003600
              };


class Flash_stm32f103rc(Flash):

    def __init__(self, target):
        super(Flash_stm32f103rc, self).__init__(target, flash_algo)

class STM32F103RC(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x08000000,  length=0x80000,      blocksize=0x800, isBootMemory=True),
        RamRegion(      start=0x20000000,  length=0x10000)
        )

    def __init__(self, link):
        super(STM32F103RC, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile(vendor="STMicro", filename="STM32F103xx.svd", is_local=False)

    def init(self):
        logging.debug('stm32f103rc init')
        super(STM32F103RC, self).init()
        self.writeMemory(DBGMCU_CR, DBGMCU_VAL);



