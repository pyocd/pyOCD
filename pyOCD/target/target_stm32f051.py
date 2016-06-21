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

from .coresight_target import (SVDFile, CoreSightTarget)
from .memory_map import (FlashRegion, RamRegion, MemoryMap)
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
