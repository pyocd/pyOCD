"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2016 ARM Limited

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

from .memory_map import (FlashRegion, RamRegion, MemoryMap)
from .target_lpc4088 import LPC4088


class LPC4088dm(LPC4088):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x10000,      blocksize=0x1000, isBootMemory=True),
        FlashRegion(    start=0x10000,     length=0x70000,      blocksize=0x8000),
        FlashRegion(    start=0x28000000,  length=0x1000000,    blocksize=0x400),
        RamRegion(      start=0x10000000,  length=0x10000),
        )

    def __init__(self, link):
        super(LPC4088dm, self).__init__(link, self.memoryMap)
