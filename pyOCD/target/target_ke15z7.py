"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 Freescale Semiconductor, Inc.

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

RCM_MR = 0x4007f010
RCM_MR_BOOTROM_MASK = 0x6

class KE15Z7(Kinetis):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x40000,       blocksize=0x800, isBootMemory=True),
        RamRegion(      start=0x1fffe000,  length=0x8000)
        )

    def __init__(self, link):
        super(KE15Z7, self).__init__(link, self.memoryMap)
        self.mdm_idr = 0x001c0020
        self._svd_location = SVDFile(vendor="Freescale", filename="MKE15Z7.svd")

    def init(self):
        super(KE15Z7, self).init()

        # Disable ROM vector table remapping.
        self.write32(RCM_MR, RCM_MR_BOOTROM_MASK)

