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

class LPC1768(CortexM):

    memoryMapXML =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x0" length="0x80000"> <property name="blocksize">0x400</property></memory>
    <memory type="ram" start="0x10000000" length="0x8000"> </memory>
    <memory type="ram" start="0x2007C000" length="0x8000"> </memory>
</memory-map>
"""
    
    def __init__(self, transport):
        super(LPC1768, self).__init__(transport)
        self.auto_increment_page_size = 0x1000
        
    def reset(self, software_reset = False):
        # halt processor
        self.halt()
        # not remap 0x0000-0x0020 to anything but the flash
        self.writeMemory(0x400FC040, 1)
        CortexM.reset(self)
        
    def resetStopOnReset(self, software_reset = False):
        # halt processor
        self.halt()
        # not remap 0x0000-0x0020 to anything but the flash
        self.writeMemory(0x400FC040, 1)
        CortexM.resetStopOnReset(self)
    
