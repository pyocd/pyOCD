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
from pyOCD.target.target import TARGET_RUNNING, TARGET_HALTED
import logging

DBGMCU_CR = 0xE0042004
#0111 1110 0011 1111 1111 1111 0000 0000
DBGMCU_VAL = 0x7E3FFF00

class STM32F103RC(CortexM):

    memoryMapXML =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x08000000" length="0x80000"> <property name="blocksize">0x800</property></memory>
    <memory type="ram" start="0x20000000" length="0x10000"> </memory>
</memory-map>
"""
    
    def __init__(self, transport):
        super(STM32F103RC, self).__init__(transport)

    def init(self):
    	logging.debug('stm32f103rc init')
        CortexM.init(self)
        self.writeMemory(DBGMCU_CR, DBGMCU_VAL);



