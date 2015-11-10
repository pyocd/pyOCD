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
from .memory_map import (FlashRegion, RamRegion, MemoryMap)
import logging


class KL05Z(Kinetis):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x8000,       blocksize=0x400, isBootMemory=True),
        RamRegion(      start=0x1ffffc00,  length=0x1000)
        )

    def __init__(self, link):
        super(KL05Z, self).__init__(link, self.memoryMap)
        self.mdm_idr = 0x001c0020

