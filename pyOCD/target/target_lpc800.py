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


class LPC800(CortexM):

    memoryMapXML =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x0" length="0x8000"> <property name="blocksize">0x400</property></memory>
    <memory type="ram" start="0x10000000" length="0x1000"> </memory>
</memory-map>
"""
    
    def __init__(self, transport):
        super(LPC800, self).__init__(transport)

    def resetStopOnReset(self, software_reset = None, map_to_user = True):
        CortexM.resetStopOnReset(self, software_reset)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.writeMemory(0x40048000, 0x2, 32)
            sp = self.readMemory(0x0)
            pc = self.readMemory(0x4)
            self.writeCoreRegisterRaw('sp', sp)
            self.writeCoreRegisterRaw('pc', pc)
