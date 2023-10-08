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
    def __init__(self, bank=0):
        assert bank < 2, "only two banks on this device"

        # only per-bank registers are offset
        offset = 0x100 if bank == 1 else 0
        self.bank = bank
        self.flashaddr = 0x2000+0x12000000+0x40000000
        self.flash_keyr      = self.flashaddr + 0x04 + offset
        self.flash_optkeyr   = self.flashaddr + 0x08
        self.flash_optcr     = self.flashaddr + 0x18
        self.flash_cr        = self.flashaddr + 0x0c + offset
        self.flash_sr        = self.flashaddr + 0x10 + offset
        self.flash_optsr_cur = self.flashaddr + 0x1c + offset
        self.flash_optsr_prg = self.flashaddr + 0x20 + offset



FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x8f4ff3bf, 0xf64a4770, 0x49fe20aa, 0x10406008, 0x20066008, 0x60081d09, 0x20aaf64a, 0x600849fa,
    0x60081040, 0x1d092006, 0xf2406008, 0x49f710ff, 0x207f6008, 0x60081f09, 0xb5104770, 0x460c4603,
    0xf44fb672, 0x49f27080, 0x20076008, 0x600849f1, 0x00def44f, 0xbf006148, 0x690048ee, 0x0004f000,
    0xd1f92800, 0x68c048eb, 0x0001f000, 0x48eab120, 0x604849e8, 0x604848e9, 0x00def44f, 0x600849e8,
    0x48e7bf00, 0x68001f00, 0x0004f000, 0xd1f82800, 0x380848e3, 0xf0006800, 0xb1380001, 0x49e048de,
    0x60083910, 0x49db48dd, 0x0104f8c1, 0xffabf7ff, 0x49d848dc, 0x49da6148, 0x20006008, 0x4601bd10,
    0x47702000, 0x49d348d8, 0xbf006148, 0x690048d1, 0x0004f000, 0xd1f92800, 0x49d148d3, 0xbf006008,
    0x1f0048cf, 0xf0006800, 0x28000004, 0xbf00d1f8, 0x690048c8, 0x0004f000, 0xd1f92800, 0x68c048c5,
    0x0030f020, 0x60c849c3, 0x68c04608, 0x0008f040, 0x460860c8, 0xf04068c0, 0x60c80080, 0x48bdbf00,
    0xf0006900, 0x28000004, 0x48bad1f9, 0xf02068c0, 0x49b80008, 0xbf0060c8, 0x1f0048b9, 0xf0006800,
    0x28000004, 0x48b6d1f8, 0x68003808, 0x0030f020, 0xf8c149b0, 0x4608010c, 0x010cf8d0, 0x0008f040,
    0x010cf8c1, 0xf8d04608, 0xf040010c, 0xf8c10080, 0xbf00010c, 0x1f0048aa, 0xf0006800, 0x28000004,
    0x48a7d1f8, 0x68003808, 0x0008f020, 0xf8c149a1, 0x2000010c, 0xb5704770, 0x461a4603, 0x3600f503,
    0xe0922400, 0x4543f3c2, 0x6f00f1b2, 0xf1b2d33f, 0xd23c6f01, 0x69404897, 0x310e499b, 0x49954308,
    0xe0016148, 0xff1ff7ff, 0x69004892, 0x0004f000, 0xd1f72800, 0x68c0488f, 0x7130f647, 0x498d4388,
    0xf04460c8, 0xea400004, 0xf0402005, 0x68c90030, 0x49884308, 0x460860c8, 0xf04068c0, 0x60c80080,
    0xf7ffe001, 0x4883ff00, 0xf0006900, 0x28000004, 0x4880d1f7, 0xf02068c0, 0x497e0004, 0x460860c8,
    0xf0006900, 0x28000001, 0x2001d04c, 0x487cbd70, 0x497d6800, 0x4308310e, 0xf8c14976, 0xe0010114,
    0xfee1f7ff, 0x1f004876, 0xf0006800, 0x28000004, 0x4873d1f6, 0x68003808, 0x7130f647, 0x496d4388,
    0x010cf8c1, 0x0104f044, 0x0008f1a5, 0x2000ea41, 0x0030f040, 0xf8d14967, 0x4308110c, 0xf8c14965,
    0x4608010c, 0x010cf8d0, 0x0080f040, 0x010cf8c1, 0xf7ffe001, 0x4862feb8, 0x68001f00, 0x0004f000,
    0xd1f62800, 0x3808485e, 0xf0206800, 0x49590004, 0x010cf8c1, 0x1f00485a, 0xf0006800, 0xb1080001,
    0xe7b32001, 0x3200f502, 0x42b2bf00, 0xaf6af67f, 0xe7ab2000, 0x4df7e92d, 0x46924605, 0x9c01462f,
    0x46d0463a, 0xf1b72300, 0xd30a6f00, 0x6f01f1b7, 0x4848d207, 0x494c6940, 0x4308310e, 0x61484945,
    0x4847e007, 0x49486800, 0x4308310e, 0xf8c14941, 0xe0ae0114, 0xfe77f7ff, 0x6f00f1b2, 0xf1b2d30a,
    0xd2076f01, 0x68c0483b, 0x7130f647, 0x49394388, 0xe00860c8, 0x3808483a, 0xf6476800, 0x43887130,
    0xf8c14934, 0xf1b2010c, 0xd3066f00, 0x6f01f1b2, 0x2032d203, 0x60c8492f, 0x2032e003, 0x39084930,
    0x2c206008, 0x2300d30f, 0xf8d8e009, 0xf8d81000, 0x60110004, 0xf1086050, 0x32080808, 0x2b041c5b,
    0x3c20dbf3, 0x4616e015, 0x230046c3, 0xf81be004, 0xf8060b01, 0x1c5b0b01, 0xd3f842a3, 0xe0032300,
    0xf80620ff, 0x1c5b0b01, 0x0020f1c4, 0xd8f74298, 0xf7ff2400, 0xf1b2fe25, 0xd30c6f00, 0x6f01f1b2,
    0xe001d209, 0xfe1ff7ff, 0x69004812, 0x0004f000, 0xd1f72800, 0xe001e009, 0xfe15f7ff, 0x1f004810,
    0xf0006800, 0x28000004, 0x480ad1f6, 0x20006900, 0xf1b2b358, 0xd31e6f00, 0x6f01f1b2, 0x4805d21b,
    0xe01368c0, 0x58004800, 0x58004c00, 0x40002c04, 0x580244d4, 0x52002000, 0x45670123, 0xcdef89ab,
    0x52002114, 0x0fee0000, 0x0fef0000, 0x0002f020, 0x60c84945, 0x4845e006, 0xf0206800, 0x49420002,
    0x010cf8c1, 0xe8bd2000, 0xf1b28dfe, 0xd3096f00, 0x6f01f1b2, 0x483cd206, 0xf02068c0, 0x493a0002,
    0xe00660c8, 0x68004839, 0x0002f020, 0xf8c14936, 0x2c00010c, 0xaf4ef47f, 0xe7e42000, 0x68004834,
    0x0001f040, 0x60084932, 0x30104831, 0x49316800, 0x492f4008, 0x60083110, 0x6800482d, 0x4008492e,
    0x6008492b, 0x68004608, 0x2080f420, 0x48286008, 0x68003010, 0x00fef420, 0x31104925, 0x20006008,
    0x31604923, 0x48226008, 0xf0206800, 0x49200018, 0x481f6008, 0x68003010, 0x3110491d, 0x46086008,
    0x60086800, 0x68004608, 0x7000f440, 0x05c86008, 0x6008491a, 0xb5004770, 0xf7ff2200, 0x4812fd84,
    0xe0016902, 0x69024810, 0x0001f002, 0xd1f92800, 0x1d00480e, 0xe0026802, 0x1d00480c, 0xf0026802,
    0x28000001, 0x4808d1f8, 0xe00168c2, 0x68c24806, 0x28002000, 0x4805d1fa, 0xe0016802, 0x68024803,
    0x28002000, 0xbd00d1fa, 0x52002000, 0x5200210c, 0x58024400, 0xf87fc00c, 0xfef6ffff, 0xe000ed08,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x2000003f,
    'pc_unInit': 0x200000c3,
    'pc_program_page': 0x200002d9,
    'pc_erase_sector': 0x2000019b,
    'pc_eraseAll': 0x200000c9,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000560,
    'begin_stack' : 0x20001d70,
    'end_stack' : 0x20000d70,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000570,
        0x20000970
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x560,
    'rw_start': 0x564,
    'rw_size': 0x4,
    'zi_start': 0x568,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x200000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}


class STM32H743xx(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x0800_0000, length=0x10_0000, sector_size=0x8000,
                                                    page_size=0x400,
                                                    is_boot_memory=True,
                                                    algo=FLASH_ALGO),

        FlashRegion( start=0x0810_0000, length=0x10_0000, sector_size=0x8000,
                                                        page_size=0x400,
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
        RamRegion(   start=0x30000000, length=0x20000,
                  is_powered_on_boot=False),
        #sram2
        RamRegion(   start=0x30020000, length=0x20000,
                  is_powered_on_boot=False),

        #sram3
        RamRegion(   start=0x30040000, length=0x8000,
                  is_powered_on_boot=False),
        #sram4
        RamRegion(   start=0x38000000, length=0x10000),
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
        assert DEV_ID == 0x450, f"IDC.DEV_ID 0x{DEV_ID:03x} did not match expected. 0x450"
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

    def _unlock_flash_peripheral(self, flash_banks=[0,1]):

        banks = [FlashPeripheral(n) for n in flash_banks]

        LOG.info('unlocking flash peripheral')
        self.reset_and_halt()

        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)

            if self.read32(bank.flash_cr) & 1 != 0:
                self.write32(bank.flash_keyr,    0x4567_0123)
                self.write32(bank.flash_keyr,    0xCDEF_89AB)
                while self.read32(bank.flash_sr) & 1:
                    time.sleep(0.1)

        # shared, so only once
        if self.read32(bank.flash_optcr) & 1 != 0:
            self.write32(bank.flash_optkeyr, 0x0819_2A3B)
            self.write32(bank.flash_optkeyr, 0x4C5D_6E7F)


    def is_locked(self, flash_banks=[0,1]):
        banks = [FlashPeripheral(n) for n in flash_banks]

        # return true if either bank
        for bank in banks:
            optsr = self.read32(bank.flash_optsr_prg)
            rdp = optsr & 0x0000_ff00
            if rdp == 0xcc:
                LOG.warning(f"BANK {bank.bank} permanently locked. No unlock possible")
            if rdp != 0xaa:
                return True
        return False

    def disable_read_protection(self, flash_banks=[0,1]):
        self._unlock_flash_peripheral(flash_banks)
        banks = [FlashPeripheral(n) for n in flash_banks]

        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)

            optsr = self.read32(bank.flash_optsr_prg)
            self.write32(bank.flash_optsr_prg, optsr & 0xffff_00ff | 0x0000_aa00)

        # on trigger on both changes
        self.write32(bank.flash_optcr, 2)
        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)

        self.reset_and_halt()

    def mass_erase(self, flash_banks=[0,1]):
        self._unlock_flash_peripheral(flash_banks)
        banks = [FlashPeripheral(n) for n in flash_banks]

        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)

            self.write32(bank.flash_cr, 1<<3 | 3<<4)
            self.write32(bank.flash_cr, 1<<3 | 3<<4 | 1<<7)
            LOG.info("mass_erase banks %i", bank.bank)

        # banks can be erased at the same time
        # so start both,
        # then wait for both
        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)
            LOG.info("mass_erase bank %i done", bank.bank)



