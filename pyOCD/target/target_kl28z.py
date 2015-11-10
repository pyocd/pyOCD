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
from pyOCD.pyDAPAccess import DAPAccess

SIM_SDID = 0x40075024
SIM_SDID_KEYATTR_MASK = 0x70
SIM_SDID_KEYATTR_SHIFT = 4

KEYATTR_DUAL_CORE = 1

class KL28x(Kinetis):

    singleMap = MemoryMap(
        FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, isBootMemory=True),
        RamRegion(name='ram', start=0x1fff8000, length=0x20000),
        RamRegion(name='usb ram', start=0x40100000, length=0x800)
        )

    dualMap = MemoryMap(
        FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, isBootMemory=True),
        RamRegion(name='core1 imem alias', start=0x1d200000, length=0x40000, blocksize=0x800),
        RamRegion(name='core0 ram', start=0x1fffa000, length=0x12000),
        FlashRegion(name='core1 imem', start=0x2d200000, length=0x40000, blocksize=0x800),
        RamRegion(name='core1 dmem', start=0x2d300000, length=0x8000),
        RamRegion(name='usb ram', start=0x40100000, length=0x800)
        )

    def __init__(self, link):
        super(KL28x, self).__init__(link, self.singleMap)
        self.mdm_idr = 0x001c0020
        self.is_dual_core = False

    def init(self):
        super(KL28x, self).init()

        # Check if this is the dual core part.
        sdid = self.readMemory(SIM_SDID)
        keyattr = (sdid & SIM_SDID_KEYATTR_MASK) >> SIM_SDID_KEYATTR_SHIFT
        logging.debug("KEYATTR=0x%x SDID=0x%08x", keyattr, sdid)
        self.is_dual_core = (keyattr == KEYATTR_DUAL_CORE)
        if self.is_dual_core:
            self.memory_map = self.dualMap
            logging.info("KL28 is dual core")

    def reset(self, software_reset=None):
        try:
            super(KL28x, self).reset(software_reset)
        except DAPAccess.TransferError:
            # KL28 causes a SWD transfer fault for the AIRCR write when
            # it resets. Just ignore this error.
            pass


