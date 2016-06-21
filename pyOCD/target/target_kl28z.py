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
import logging
from ..coresight import ap
from ..coresight.cortex_m import CortexM
from .coresight_target import SVDFile
import os.path
from time import (time, sleep)

SIM_SDID = 0x40075024
SIM_SDID_KEYATTR_MASK = 0x70
SIM_SDID_KEYATTR_SHIFT = 4

KEYATTR_DUAL_CORE = 1

RCM_MR = 0x4007f010
RCM_MR_BOOTROM_MASK = 0x6

RECOVER_TIMEOUT = 1.0 # 1 second

class KL28x(Kinetis):

    singleMap = MemoryMap(
        FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, isBootMemory=True),
        RamRegion(name='ram', start=0x1fff8000, length=0x20000),
        RamRegion(name='usb ram', start=0x40100000, length=0x800)
        )

    dualMap = MemoryMap(
        FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, isBootMemory=True),
        RomRegion(name='core1 imem alias', start=0x1d200000, length=0x40000),
        RamRegion(name='core0 ram', start=0x1fffa000, length=0x18000),
        RomRegion(name='core1 imem', start=0x2d200000, length=0x40000),
        RamRegion(name='core1 dmem', start=0x2d300000, length=0x8000),
        RamRegion(name='usb ram', start=0x40100000, length=0x800)
        )

    def __init__(self, link):
        super(KL28x, self).__init__(link, self.singleMap)
        self.mdm_idr = 0x001c0020
        self.is_dual_core = False

        self._svd_location = SVDFile(vendor="Freescale", filename="MKL28T7_CORE0.svd", is_local=False)

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

            # Add second core's AHB-AP.
            self.core1_ap = ap.AHB_AP(self.dp, 2)
            self.aps[2] = self.core1_ap
            self.core1_ap.init(True)

            # Add second core. It is held in reset until released by software.
            self.core1 = CortexM(self.link, self.dp, self.core1_ap, self.memory_map, core_num=1)
            self.cores[1] = self.core1
            self.core1.init()

        # Disable ROM vector table remapping.
        self.write32(RCM_MR, RCM_MR_BOOTROM_MASK)




