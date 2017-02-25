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

#DBGMCU clock
RCC_APB2ENR_CR = 0x40021018
RCC_APB2ENR_DBGMCU = 0x00400000

DBGMCU_CR = 0x40015804
DBGMCU_APB1_CR = 0x40015808
DBGMCU_APB2_CR = 0x4001580C

#0000 0000 0000 0000 0000 0000 0000 0100
#BGMCU_CR_VAL = 0x00000000

#0000 0010 0010 0000 0001 1101 0011 0011
DBGMCU_APB1_VAL = 0x02201D33

#0000 0000 0000 0111 0000 1000 0000 0000
DBGMCU_APB2_VAL = 0x00070800


flash_algo = { 'load_address' : 0x20000000,
               'instructions' : [
                                  0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
                                  0x49544853, 0x48546048, 0x20006048, 0xb5104770, 0x20344603, 0x60e04c4f, 0xbd102000, 0x20004601,
                                  0xb5004770, 0x23002200, 0x6902484a, 0x40102080, 0xd1012880, 0xffe4f7ff, 0x4846bf00, 0x07d868c3,
                                  0xd1fa0fc0, 0x69024843, 0x43022004, 0x61024841, 0x20406902, 0x483f4302, 0xbf006102, 0x68c3483d,
                                  0x0fc007d8, 0x483bd1fa, 0x21046902, 0x43884610, 0x48384602, 0x20006102, 0xb510bd00, 0x22004603,
                                  0x48342400, 0x20806902, 0x28804010, 0xf7ffd101, 0xbf00ffb7, 0x68c4482f, 0x0fc007e0, 0x482dd1fa,
                                  0x20026902, 0x482b4302, 0x61436102, 0x20406902, 0x48284302, 0xbf006102, 0x68c44826, 0x0fc007e0,
                                  0x4824d1fa, 0x21026902, 0x43884610, 0x48214602, 0x20006102, 0xb5f7bd10, 0x22004615, 0x27002600,
                                  0x462c9b00, 0x6902481b, 0x40102080, 0xd1012880, 0xff86f7ff, 0x4817bf00, 0x07f068c6, 0xd1fa0fc0,
                                  0x4814e01b, 0x20016902, 0x48124302, 0x88206102, 0xbf008018, 0x68c6480f, 0x0fc007f0, 0x8820d1fa,
                                  0x42888819, 0x480bd006, 0x08526902, 0x61020052, 0xbdfe2001, 0x1ca41c9b, 0x98011c7f, 0x42b80840,
                                  0x4804d8df, 0x08526902, 0x61020052, 0xe7f02000, 0x45670123, 0x40022000, 0xcdef89ab, 0x00000000,
                                ],
               'pc_init'          : 0x2000002F,
               'pc_eraseAll'      : 0x20000043,
               'pc_erase_sector'  : 0x2000009B,
               'pc_program_page'  : 0x200000F7,
               'static_base'      : 0x200001A0,
               'begin_data'       : 0x20000400, # Analyzer uses a max of 256 B data (64 pages * 4 bytes / page)
               'page_buffers'     : [0x20000400, 0x20000800],   # Enable double buffering
               'begin_stack'      : 0x20001000,
               'min_program_length' : 2,
               'analyzer_supported' : True,
               'analyzer_address' : 0x20001400 # Analyzer 0x20001400..0x20001A00
              };


class Flash_stm32f051(Flash):

    def __init__(self, target):
        super(Flash_stm32f051, self).__init__(target, flash_algo)

class STM32F051(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x08000000,  length=0x10000,      blocksize=0x400, isBootMemory=True),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, link):
        super(STM32F051, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile(vendor="STMicro", filename="STM32F0xx.svd", is_local=False)

    def init(self):
        logging.debug('stm32f051 init')
        super(STM32F051, self).init()
        enclock = self.readMemory(RCC_APB2ENR_CR)
        enclock |= RCC_APB2ENR_DBGMCU
        self.writeMemory(RCC_APB2ENR_CR, enclock);
        self.writeMemory(DBGMCU_APB1_CR, DBGMCU_APB1_VAL);
        self.writeMemory(DBGMCU_APB2_CR, DBGMCU_APB2_VAL);
