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
from .memory_map import (FlashRegion, RamRegion, MemoryMap)


class LPC800(CortexM):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x8000,       blocksize=0x400, isBootMemory=True),
        RamRegion(      start=0x10000000,  length=0x1000)
        )

    def __init__(self, link):
        super(LPC800, self).__init__(link, self.memoryMap)

    def resetStopOnReset(self, software_reset=None, map_to_user=True):
        CortexM.resetStopOnReset(self, software_reset)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.writeMemory(0x40048000, 0x2, 32)
            sp = self.readMemory(0x0)
            pc = self.readMemory(0x4)
            self.writeCoreRegisterRaw('sp', sp)
            self.writeCoreRegisterRaw('pc', pc)
