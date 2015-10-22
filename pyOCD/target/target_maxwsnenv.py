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
import logging

class MAXWSNENV(CortexM):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x40000,      blocksize=0x800, isBootMemory=True),
        RamRegion(      start=0x20000000,  length=0x8000),
        RamRegion(      start=0x40000000,  length=0x100000),
        RamRegion(      start=0xe0000000,  length=0x100000)
        )

    def __init__(self, link):
        super(MAXWSNENV, self).__init__(link, self.memoryMap)

    def dsb(self):
        logging.info("Triggering Destructive Security Bypass...")

        self.link.vendor(1)

        # Reconnect debugger
        self.link.init()

    def fge(self):
        logging.info("Triggering Factory Global Erase...")

        self.link.vendor(2)

        # Reconnect debugger
        self.link.init()
