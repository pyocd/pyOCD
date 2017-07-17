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
from ..flash.flash import Flash
from ..core.coresight_target import CoreSightTarget
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)
import logging

class Flash_rtl8195am(Flash):

    def __init__(self, target):
        return

class RTL8195AM(CoreSightTarget):

    memoryMap = MemoryMap(
        RamRegion(      start=0x00000000,  length=0x400000),
        RamRegion(      start=0x10000000,  length=0x80000),
        RamRegion(      start=0x30000000,  length=0x200000),
        RamRegion(      start=0x40000000,  length=0x40000)
        )

    def __init__(self, link):
        super(RTL8195AM, self).__init__(link, self.memoryMap)

    def init(self):
        logging.debug('rtl8195am init')
        super(RTL8195AM, self).init()
