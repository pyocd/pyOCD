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

from target_kinetis import Kinetis
from .memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from .coresight_target import SVDFile
import logging


class K82F25615(Kinetis):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,          length=0x40000,     blocksize=0x1000, isBootMemory=True),
        RomRegion(      start=0x04000000, end=0x07ffffff), # QSPI0 alias
        RamRegion(      start=0x08000000, end=0x0fffffff), # SDRAM alias
        RamRegion(      start=0x1fff0000, length=0x40000), # RAM
        RomRegion(      start=0x1c000000, end=0x1c007fff), # ROM
        RamRegion(      start=0x18000000, end=0x1bffffff), # FlexBus alias
        RomRegion(      start=0x68000000, end=0x6fffffff), # QSPI0
        RamRegion(      start=0x70000000, end=0x7fffffff), # SDRAM (write-back)
        RamRegion(      start=0x80000000, end=0x8fffffff), # SDRAM (write-through)
        RamRegion(      start=0x98000000, end=0x9fffffff), # FlexBus (write-through)
        RamRegion(      start=0xa0000000, end=0xdfffffff)  # FlexBus (not executable)
        )

    def __init__(self, transport):
        super(K82F25615, self).__init__(transport, self.memoryMap)
        self.mdm_idr = 0x001c0000
        self._svd_location = SVDFile(vendor="Freescale", filename="MK82F25615.svd")

