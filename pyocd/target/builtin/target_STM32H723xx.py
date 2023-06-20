# pyOCD debugger
# Copyright (c) 2023 David van Rijn
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

import time
import logging
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...coresight.cortex_m import CortexM
from ...coresight.minimal_mem_ap import MinimalMemAP as MiniAP

LOG = logging.getLogger(__name__)

class DBGMCU:

    # Via APB-ap (AP2)
    #BASE =   0xe00e1000
    # via AHB-ap (AP0,1)
    BASE =   0x5c001000

    IDC =  BASE + 0x000
    CR =   BASE + 0x004
    CR_VALUE = (0x3f | # keep running in stop sleep and standby
               0x07 << 20 | # enable all debug components
               0x07
               )

    ABP3 = BASE + 0x034

class FlashPeripheral:
    def __init__(self):
        self.flashaddr = 0x2000+0x12000000+0x40000000
        self.flash_keyr = self.flashaddr + 4
        self.flash_optkeyr = self.flashaddr + 8
        self.flash_optcr = self.flashaddr + 0x18
        self.flash_cr = self.flashaddr + 0xc
        self.flash_sr = self.flashaddr + 0x10
        self.flash_optsr_cur = self.flashaddr + 0x1c
        self.flash_optsr_prg = self.flashaddr + 0x20


FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
        0xe7fdbe00,
        0x4603b510, 0x00def44f, 0x60e04c7f, 0x487ebf00, 0xf0006900, 0x28000004, 0x487cd1f9, 0x60604c7a,
        0x6060487b, 0xbd102000, 0x48774601, 0xf04068c0, 0x4a750001, 0x200060d0, 0xbf004770, 0x69004872,
        0x0001f000, 0xd1f92800, 0x486fbf00, 0xf0006900, 0x28000001, 0x486cd1f9, 0xf02068c0, 0x496a0030,
        0x460860c8, 0xf04068c0, 0x60c80008, 0x68c04608, 0x0080f040, 0xbf0060c8, 0x69004863, 0x0001f000,
        0xd1f92800, 0x68c04860, 0x0008f020, 0x60c8495e, 0x47702000, 0xf3c14601, 0xf1b14243, 0xd3376f00,
        0x6f01f1b1, 0xbf00d234, 0x69004857, 0x0004f000, 0xd1f92800, 0x68c04854, 0x60e0f420, 0x60d84b52,
        0x68c04618, 0x7330f647, 0x4b4f4398, 0x461860d8, 0x230468c0, 0x2302ea43, 0x4b4b4318, 0x461860d8,
        0xf04068c0, 0x60d80080, 0x4847bf00, 0xf0006900, 0x28000004, 0x4844d1f9, 0xf02068c0, 0x4b420004,
        0x461860d8, 0xf4006900, 0xb1080080, 0x47702001, 0xe7fc2000, 0x4603b5f0, 0x461c4616, 0x22004635,
        0x6f00f1b3, 0xf1b3d310, 0xd20d6f01, 0x4836bf00, 0xf0006900, 0x28000004, 0xbf00d1f9, 0x69004832,
        0x0001f000, 0xd1f92800, 0x00def44f, 0x60f84f2e, 0xf1b3e056, 0xd3536f00, 0x6f01f1b3, 0x482ad250,
        0xf64768c0, 0x43b87730, 0x60f84f27, 0x60f82002, 0xd30c2920, 0xe0062200, 0xf855686f, 0x60670b08,
        0x0b08f844, 0x2a041c52, 0x3920dbf6, 0x4620e017, 0x2200462f, 0xf817e004, 0xf800cb01, 0x1c52cb01,
        0xd3f8428a, 0xe0042200, 0x0cfff04f, 0xcb01f800, 0xf1c11c52, 0x45940c20, 0x2100d8f6, 0xbf00bf00,
        0x69004811, 0x0004f000, 0xd1f92800, 0x480ebf00, 0xf0006900, 0x28000001, 0x480bd1f9, 0xf4006900,
        0xb9683080, 0x6f00f1b3, 0xf1b3d308, 0xd2056f01, 0x68c04805, 0x0002f020, 0x60f84f03, 0xbdf02001,
        0xd1a62900, 0xe7fa2000, 0x52002000, 0x45670123, 0xcdef89ab, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x2000002d,
    'pc_program_page': 0x20000119,
    'pc_erase_sector': 0x20000099,
    'pc_eraseAll': 0x2000003f,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000214,
    'begin_stack' : 0x20001a20,
    'end_stack' : 0x20000a20,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000220,
        0x20000620
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x214,
    'rw_start': 0x218,
    'rw_size': 0x4,
    'zi_start': 0x21c,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x20000),
    )
}



class STM32H723xx(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x08000000, length=0x100000, sector_size=0x8000,
                                                        page_size=0x400,
                                                        is_boot_memory=True,
                                                        algo=FLASH_ALGO),
        #ITCM
        RamRegion(   start=0x00000000, length=0x10000,
                  is_cachable=False,
                  access="rwx"),
        #DTCM
        RamRegion(   start=0x20000000, length=0x20000,
                  is_cachable=False,
                  access="rw"),
        #sram1
        RamRegion(   start=0x30000000, length=0x4000,
                  is_powered_on_boot=False),
        #sram2
        RamRegion(   start=0x30004000, length=0x4000,
                  is_powered_on_boot=False),
        #sram4
        RamRegion(   start=0x38000000, length=0x4000),
        )



    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def assert_reset_for_connect(self):
        self.dp.assert_reset(1)

    def safe_reset_and_halt(self):
        assert self.dp.is_reset_asserted()

        # At this point we can't access full AP as it is not initialized yet.
        # Let's create a minimalistic AP and use it.
        ap = MiniAP(self.dp)
        ap.init()

        DEMCR_value = ap.read32(CortexM.DEMCR)

        # Halt on reset.
        ap.write32(CortexM.DEMCR,
                   CortexM.DEMCR_VC_CORERESET |
                   CortexM.DEMCR_TRCENA
                   )
        ap.write32(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)

        self.dp.assert_reset(0)
        time.sleep(0.01)

        DEV_ID = ap.read32(DBGMCU.IDC) & 0xfff
        assert DEV_ID == 0x483, f"IDC.DEV_ID 0x{DEV_ID:03x} did not match expected. 0x483"
        ap.write32(DBGMCU.CR, DBGMCU.CR_VALUE)

        CR = ap.read32(DBGMCU.CR)
        LOG.info("CR: 0x%08x", CR)

        # Restore DEMCR original value.
        ap.write32(CortexM.DEMCR, DEMCR_value)

    def create_init_sequence(self):
        # this was copied from target_STM32F767xx.py but seems to apply here as well
        #
        # STM32 under some low power/broken clock states doesn't allow AHP communication.
        # Low power modes are quite popular on stm32 (including MBed OS defaults).
        # 'attach' mode is broken by default, as STM32 can't be connected on low-power mode
        #  successfully without previous DBGMCU setup (It is not possible to write DBGMCU).
        # It is also not possible to run full pyOCD discovery code under-reset.
        #
        # As a solution we can setup DBGMCU under reset, halt core and release reset.
        # Unfortunately this code has to be executed _before_ discovery stage
        # and without discovery stage we don't have access to AP/Core.
        # As a solution we can create minimalistic AP implementation and use it
        # to setup core halt.
        # So the sequence for 'halt' connect mode will look like
        # -> Assert reset
        # -> Connect DebugPort
        # -> Setup MiniAp
        # -> Setup halt on reset
        # -> Enable support for debugging in low-power modes
        # -> Release reset
        # -> [Core is halted and reset is released]
        # -> Continue [discovery, create cores, etc]
        seq = super().create_init_sequence()
        if self.session.options.get('connect_mode') in ('halt', 'under-reset'):
            seq.insert_before('dp_init', ('assert_reset_for_connect', self.assert_reset_for_connect))
            seq.insert_after('dp_init', ('safe_reset_and_halt', self.safe_reset_and_halt))

        return seq

    def _unlock_flash_peripheral(self):
        bank = FlashPeripheral()
        LOG.info('unlocking flash peripheral')
        self.reset_and_halt()
        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)

        if self.read32(bank.flash_cr) & 1 != 0:
            self.write32(bank.flash_keyr,    0x4567_0123)
            self.write32(bank.flash_keyr,    0xCDEF_89AB)
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)
        if self.read32(bank.flash_optcr) & 1 != 0:
            self.write32(bank.flash_optkeyr, 0x0819_2A3B)
            self.write32(bank.flash_optkeyr, 0x4C5D_6E7F)



    def is_locked(self):
        bank = FlashPeripheral()
        optsr = self.read32(bank.flash_optsr_prg)
        rdp = optsr & 0x0000_ff00
        if rdp == 0xaa:
            return False;
        if rdp == 0xcc:
            LOG.warning("MCU permanently locked. No unlock possible")
        return True

    def disable_read_protection(self):
        bank = FlashPeripheral()
        self._unlock_flash_peripheral()

        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)

        optsr = self.read32(bank.flash_optsr_prg)
        self.write32(bank.flash_optsr_prg, optsr & 0xffff_00ff | 0x0000_aa00)
        self.write32(bank.flash_optcr, 2)
        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)
        self.reset_and_halt()

    def mass_erase(self):
        bank = FlashPeripheral()
        self._unlock_flash_peripheral()

        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)

        self.write32(bank.flash_cr, 1<<3 | 3<<4)
        self.write32(bank.flash_cr, 1<<3 | 3<<4 | 1<<7)
        LOG.info("mass_erase")
        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)
        LOG.info("mass_erase done")





