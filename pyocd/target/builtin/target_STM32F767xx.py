# pyOCD debugger
# Copyright (c) 2020 Bartek Wolowiec
# Copyright (c) 2021 Chris Reed
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

LOG = logging.getLogger(__name__)

class DBGMCU:
    CR = 0xE0042004
    CR_VALUE = 0x7 # DBG_STANDBY | DBG_STOP | DBG_SLEEP


class MiniAP(object):
    """Minimalistic Access Port implementation."""
    AP0_CSW_ADDR = 0x00
    AP0_CSW_ADDR_VAL = 0x03000012
    AP0_TAR_ADDR = 0x04
    AP0_IDR_ADDR = 0xFC
    AP0_DRW_ADDR = 0x0C

    def __init__(self, dp):
        self.dp = dp

    def init(self):
        # Init AP #0
        IDR = self.dp.read_ap(MiniAP.AP0_IDR_ADDR)
        # Check expected MEM-AP
        assert IDR == 0x74770001
        self.dp.write_ap(MiniAP.AP0_CSW_ADDR, MiniAP.AP0_CSW_ADDR_VAL)

    def read32(self, addr):
        self.dp.write_ap(MiniAP.AP0_TAR_ADDR, addr)
        return self.dp.read_ap(MiniAP.AP0_DRW_ADDR)

    def write32(self, addr, val):
        self.dp.write_ap(MiniAP.AP0_TAR_ADDR, addr)
        self.dp.write_ap(MiniAP.AP0_DRW_ADDR, val)


FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x8f4ff3bf, 0x02c04770, 0x28400dc0, 0x0980d302, 0x47701d00, 0xd3022820, 0x1cc00940, 0x08c04770,
    0x48494770, 0x60414947, 0x60414948, 0x60012100, 0x22f068c1, 0x60c14311, 0x06806940, 0x4845d406,
    0x60014943, 0x60412106, 0x60814943, 0x47702000, 0x6901483d, 0x43110542, 0x20006101, 0xb5104770,
    0x69014839, 0x43212404, 0x69016101, 0x431103a2, 0x493a6101, 0xe0004a37, 0x68c36011, 0xd4fb03db,
    0x43a16901, 0x20006101, 0xb530bd10, 0xffbbf7ff, 0x68ca492d, 0x431a23f0, 0x240260ca, 0x690a610c,
    0x0e0006c0, 0x610a4302, 0x03e26908, 0x61084310, 0x8f4ff3bf, 0x4a274829, 0x6010e000, 0x03ed68cd,
    0x6908d4fb, 0x610843a0, 0x060068c8, 0xd0030f00, 0x431868c8, 0x200160c8, 0xb5f0bd30, 0x1cc94c1a,
    0x68e50889, 0x23f00089, 0x60e5431d, 0x61232300, 0x06ff2701, 0xe0214d19, 0x4e196923, 0x61234333,
    0x0af602c6, 0x681319f6, 0xf3bf6033, 0x4e118f4f, 0x6035e000, 0x03db68e3, 0x6923d4fb, 0x005b085b,
    0x68e36123, 0x0f1b061b, 0x68e0d005, 0x430821f0, 0x200160e0, 0x1d00bdf0, 0x1d121f09, 0xd1db2900,
    0xbdf02000, 0x45670123, 0x40023c00, 0xcdef89ab, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa,
    0x00000201, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000043,
    'pc_unInit': 0x20000071,
    'pc_program_page': 0x200000fb,
    'pc_erase_sector': 0x200000ab,
    'pc_eraseAll': 0x2000007f,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000164,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001400],   # Enable double buffering
    'min_program_length' : 0x400
    }

class STM32F767xx(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    # MemoryMap for dual bank configuration (Details in AN4826).
    # Dual memory configuration is controled by nDBANK bit in FLASH_OPTCR.
    # In both configuration there is 2MB of flash memory. The difference is in
    # flash sectors structure.
    # For Single bank there is 12 sectors, for dual bank there is 24 sectors.
    # For dual bank configurations sectors are half size.
    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x08000000, length=0x20000,  sector_size=0x8000,
                                                        page_size=0x400,
                                                        is_boot_memory=True,
                                                        algo=FLASH_ALGO),

        FlashRegion( start=0x08020000, length=0x20000,  sector_size=0x20000,
                                                        page_size=0x400,
                                                        algo=FLASH_ALGO),

        FlashRegion( start=0x08040000, length=0x1C0000,  sector_size=0x40000,
                                                        page_size=0x400,
                                                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x80000)
        )

    def __init__(self, session):
        super(STM32F767xx, self).__init__(session, self.MEMORY_MAP)

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
        ap.write32(CortexM.DEMCR, CortexM.DEMCR_VC_CORERESET)
        ap.write32(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)

        # Prevent disabling bus clock/power in low power modes.
        ap.write32(DBGMCU.CR, DBGMCU.CR_VALUE)

        self.dp.assert_reset(0)
        time.sleep(0.01)

        # Restore DEMCR original value.
        ap.write32(CortexM.DEMCR, DEMCR_value)

    def create_init_sequence(self):
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
        seq = super(STM32F767xx, self).create_init_sequence()
        if self.session.options.get('connect_mode') in ('halt', 'under-reset'):
            seq.insert_before('dp_init', ('assert_reset_for_connect', self.assert_reset_for_connect))
            seq.insert_after('dp_init', ('safe_reset_and_halt', self.safe_reset_and_halt))

        return seq

    def post_connect_hook(self):
        FLASH_OPTCR_ADDR = 0x40023C14
        FLASH_OPTCR_NDBANK = 1<<29
        flash_optcr = self.read32(FLASH_OPTCR_ADDR)
        if flash_optcr & FLASH_OPTCR_NDBANK:
            LOG.info('Single bank configuration detected [FLASH_OPTCR=0x%08x].', flash_optcr)
        else:
            LOG.error('Dual bank configuration detected [FLASH_OPTCR=0x%08x]. '
                      'Currently only single bank configuration is fully supported!', flash_optcr)
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)


