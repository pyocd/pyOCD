"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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
from .memory_map import (FlashRegion, RamRegion, MemoryMap)
from .coresight_target import SVDFile
import logging


class K66F18(Kinetis):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x200000,     blocksize=0x1000, isBootMemory=True),
        RamRegion(      start=0x1fff0000,  length=0x40000),
        RamRegion(      start=0x14000000,  length=0x1000)
        )

    def __init__(self, transport):
        super(K66F18, self).__init__(transport, self.memoryMap)
        self.mdm_idr = 0x001c0000
        self._svd_location = SVDFile(vendor="Freescale", filename="MK66F18.svd")

