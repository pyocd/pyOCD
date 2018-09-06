# pyOCD debugger
# Copyright (c) 2018 Arm Limited
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ..core.coresight_target import CoreSightTarget
from .target_STM32F412xE import (DBGMCU, Flash_stm32f412xx)
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ..debug.svd import SVDFile

class STM32F412xG(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion( start=0x08000000, length=0x10000, blocksize=0x4000,  isBootMemory=True),
        FlashRegion( start=0x08010000, length=0x10000, blocksize=0x10000),
        FlashRegion( start=0x08020000, length=0x60000, blocksize=0x20000),
        RamRegion(   start=0x20000000, length=0x40000)
        )

    def __init__(self, transport):
        super(STM32F412xG, self).__init__(transport, self.memoryMap)
        self._svd_location = SVDFile(vendor="STMicro", filename="STM32F41x.svd")
        
    def init(self):
        super(STM32F412xG, self).init()
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1_FZ, DBGMCU.APB1_FZ_VALUE)
        self.write32(DBGMCU.APB2_FZ, DBGMCU.APB2_FZ_VALUE)

