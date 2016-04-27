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

class KE18F16(Kinetis):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x80000,       blocksize=0x1000, isBootMemory=True),
        RamRegion(      start=0x1fff8000,  length=0x10000)
        )

    def __init__(self, link):
        super(KE18F16, self).__init__(link, self.memoryMap)
        self.mdm_idr = 0x001c0000
        self._svd_location = SVDFile(vendor="Freescale", filename="MKE18F16.svd")

    def init(self):
        super(KE18F16, self).init()

        # Disable ROM vector table remapping.
        self.write32(RCM_MR, RCM_MR_BOOTROM_MASK)

