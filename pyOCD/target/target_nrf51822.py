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

from cortex_m import CortexM
from pyOCD.target.target import TARGET_RUNNING, TARGET_HALTED

class NRF51822(CortexM):

    memoryMapXML =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x0" length="0x40000"> <property name="blocksize">0x400</property></memory>
    <memory type="ram" start="0x20000000" length="0x4000"> </memory>
</memory-map>
"""
    
    def __init__(self, transport):
        super(NRF51822, self).__init__(transport)
        self.auto_increment_page_size = 0x400
    
    def reset(self):
        # halt processor
        self.halt()
        #Regular reset will kick NRF out of DBG mode
        #self.writeMemory(0x40000544, 1)
        #reset
        #CortexM.reset(self)
        
        #Soft Reset will keep NRF in debug mode
        self.writeMemory(0xe000ed0c, 0x05FA0000 | 0x00000004)
    
    def resetStopOnReset(self):        
        #CortexM.resetStopOnReset(self)
        # read address of reset handler
        reset_handler = self.readMemory(4)
        
        # reset and halt the target
        self.reset()
        self.halt()
        
        # set a breakpoint to the reset handler and reset the target
        self.setBreakpoint(reset_handler)
        self.reset()
        
        # wait until the bp is reached
        while (self.getState() == TARGET_RUNNING):
            pass
        
        # remove the breakpoint
        self.removeBreakpoint(reset_handler)

