"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

class LPC4330(CortexM):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x14000000,  length=0x4000000,    blocksize=0x400, isBootMemory=True),
        RamRegion(      start=0x10000000,  length=0x20000),
        RamRegion(      start=0x10080000,  length=0x12000),
        RamRegion(      start=0x20000000,  length=0x8000),
        RamRegion(      start=0x20008000,  length=0x8000)
        )

    def __init__(self, link):
        super(LPC4330, self).__init__(link, self.memoryMap)
        self.ignoreReset = False

    def setFlash(self, flash):
        self.flash = flash

    def reset(self, software_reset=False):
        # Always use software reset for LPC4330 since the hardware version
        # will reset the DAP.
        CortexM.reset(self, True)

    def resetStopOnReset(self, software_reset=False):
        if self.ignoreReset:
            return

        # Set core up to run some code in RAM that is guaranteed to be valid
        # since FLASH could be corrupted and that is what user is trying to fix.
        self.writeMemory(0x10000000, 0x10087ff0)    # Initial SP
        self.writeMemory(0x10000004, 0x1000000d)    # Reset Handler
        self.writeMemory(0x10000008, 0x1000000d)    # Hard Fault Handler
        self.writeMemory(0x1000000c, 0xe7fee7fe)    # Infinite loop
        self.writeMemory(0x40043100, 0x10000000)    # Shadow 0x0 to RAM

        # Always use software reset for LPC4330 since the hardware version
        # will reset the DAP.
        CortexM.resetStopOnReset(self, True)

        # Map shadow memory to SPIFI FLASH
        self.writeMemory(0x40043100, 0x80000000)

        # The LPC4330 flash init routine can be used to remount FLASH.
        self.ignoreReset = True
        self.flash.init()
        self.ignoreReset = False

        # Set SP and PC based on interrupt vector in SPIFI_FLASH
        sp = self.readMemory(0x14000000)
        pc = self.readMemory(0x14000004)
        self.writeCoreRegisterRaw('sp', sp)
        self.writeCoreRegisterRaw('pc', pc)
