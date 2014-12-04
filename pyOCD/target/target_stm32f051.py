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

from cortex_m import CortexM, DHCSR, DBGKEY, C_DEBUGEN, C_MASKINTS, C_STEP, DEMCR, VC_CORERESET, NVIC_AIRCR, NVIC_AIRCR_VECTKEY, NVIC_AIRCR_SYSRESETREQ
from cortex_m import C_HALT
from pyOCD.target.target import TARGET_RUNNING, TARGET_HALTED
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



class STM32F051(CortexM):

    memoryMapXML =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x08000000" length="0x10000"> <property name="blocksize">0x400</property></memory>
    <memory type="ram" start="0x20000000" length="0x2000"> </memory>
</memory-map>
"""
    
    def __init__(self, transport):
        super(STM32F051, self).__init__(transport)
        self.auto_increment_page_size = 0x400

    def init(self):
        logging.debug('stm32f051 init')
        CortexM.init(self)
        enclock = self.readMemory(RCC_APB2ENR_CR)
        enclock |= RCC_APB2ENR_DBGMCU
        self.writeMemory(RCC_APB2ENR_CR, enclock);
        self.writeMemory(DBGMCU_APB1_CR, DBGMCU_APB1_VAL);
        self.writeMemory(DBGMCU_APB2_CR, DBGMCU_APB2_VAL);