# pyOCD debugger
# Copyright (c) 2023 Brian Pugh
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
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...coresight.cortex_m import CortexM
from ...coresight.minimal_mem_ap import MinimalMemAP as MiniAP


class DBGMCU:
    CR = 0xE00E1004
    CR_VALUE = 0x7 # DBG_STANDBY | DBG_STOP | DBG_SLEEP

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x4770ba40, 0x4770bac0, 0x0030ea4f, 0x00004770, 0x8f4ff3bf, 0xb5104770, 0x48ea4603, 0x61604cea,
    0x48e9bf00, 0xf0006900, 0x28000001, 0x48e7d1f9, 0x60604ce5, 0x606048e6, 0x4ce648e2, 0xbf006020,
    0x1f0048e4, 0xf0006800, 0x28000001, 0x48dfd1f8, 0x3c104ce0, 0x48de6020, 0xf8c44cdb, 0x46200104,
    0x200069c0, 0x4601bd10, 0x68c048d7, 0x0001f040, 0x60d04ad5, 0x380848d7, 0xf0406800, 0xf8c20001,
    0x2000010c, 0xbf004770, 0x690048cf, 0x0001f000, 0xd1f92800, 0x49cc48cb, 0x46086148, 0xf02068c0,
    0x60c80001, 0x68c04608, 0x0008f040, 0x460860c8, 0xf04068c0, 0x60c80020, 0x48c3bf00, 0xf0006900,
    0x28000001, 0x48c0d1f9, 0xf02068c0, 0x49be0008, 0xbf0060c8, 0x1f0048bf, 0xf0006800, 0x28000001,
    0x48b8d1f8, 0x600849bb, 0xf8d048b7, 0xf020010c, 0x49b50001, 0x010cf8c1, 0xf8d04608, 0xf040010c,
    0xf8c10008, 0x4608010c, 0x010cf8d0, 0x0020f040, 0x390849b0, 0xbf006008, 0x1f0048ae, 0xf0006800,
    0x28000001, 0x48abd1f8, 0x68003808, 0x0008f020, 0xf8c149a5, 0x2000010c, 0xb5104770, 0xf3c14601,
    0xf1b13247, 0xd3366f00, 0x6f01f1b1, 0x489ed233, 0x4ba16940, 0x4b9c4318, 0xbf006158, 0x6900489a,
    0x0004f000, 0xd1f92800, 0x68c04897, 0x50fef420, 0x60d84b95, 0x68c04618, 0xea432304, 0x43181382,
    0x60d84b91, 0x68c04618, 0x0020f040, 0xbf0060d8, 0x6900488d, 0x0004f000, 0xd1f92800, 0x68c0488a,
    0x0004f020, 0x60d84b88, 0x69004618, 0x0001f000, 0x2001b3f0, 0x4887bd10, 0x4b876800, 0x4b824318,
    0x0114f8c3, 0x4883bf00, 0x68001f00, 0x0004f000, 0xd1f82800, 0x3808487f, 0xf4206800, 0x4b7a50fe,
    0x010cf8c3, 0x3808487b, 0xf1a26800, 0x24040380, 0x1383ea44, 0x4b744318, 0x010cf8c3, 0xf8d04618,
    0xf040010c, 0xf8c30020, 0xbf00010c, 0x1f004871, 0xf0006800, 0x28000004, 0x486ed1f8, 0x68003808,
    0x0004f020, 0xf8c34b68, 0x486a010c, 0xe0001f00, 0x6800e005, 0x0001f000, 0x2001b108, 0xf7ffe7ba,
    0x2000fee7, 0xb5f0e7b6, 0x46164603, 0x4635461a, 0xbf002400, 0x6900485c, 0x0001f000, 0xd1f92800,
    0x4f594858, 0xbf006178, 0x1f00485a, 0xf0006800, 0x28000001, 0x4853d1f8, 0x60384f56, 0x4852e09c,
    0xf02068c0, 0x4f500001, 0x463860f8, 0xf04068c0, 0x60f80002, 0x3808484f, 0xf0206800, 0xf8c70001,
    0x4638010c, 0x010cf8d0, 0x0002f040, 0x010cf8c7, 0xd30c2910, 0xe0062400, 0x6868682f, 0x60506017,
    0x32083508, 0x2c021c64, 0x3910dbf6, 0x2400e028, 0xf815e004, 0xf8020b01, 0x1c640b01, 0xd3f8428c,
    0xe0032400, 0xf80220ff, 0x1c640b01, 0x0010f1c1, 0xd8f742a0, 0x6f00f1b3, 0xf1b3d309, 0xd2066f01,
    0x68c04831, 0x0040f040, 0x60f84f2f, 0x4831e007, 0x68003808, 0x0040f040, 0xf8c74f2b, 0x2100010c,
    0xfe76f7ff, 0x6f00f1b3, 0xf1b3d30a, 0xd2076f01, 0x4825bf00, 0xf0006900, 0x28000001, 0xe007d1f9,
    0x4824bf00, 0x68001f00, 0x0001f000, 0xd1f82800, 0x6900481d, 0x4f1f2000, 0x683f1f3f, 0xb1b04300,
    0x6f00f1b3, 0xf1b3d309, 0xd2066f01, 0x68c04816, 0x0002f020, 0x60f84f14, 0x4816e007, 0x68003808,
    0x0002f020, 0xf8c74f10, 0x2001010c, 0xf1b3bdf0, 0xd3096f00, 0x6f01f1b3, 0x480bd206, 0xf02068c0,
    0x4f090002, 0xe00760f8, 0x3808480a, 0xf0206800, 0x4f050002, 0x010cf8c7, 0xf47f2900, 0x2000af60,
    0x0000e7e4, 0x0faf0000, 0x52002000, 0x45670123, 0xcdef89ab, 0x52002114, 0x0fef0000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x2000001b,
    'pc_unInit': 0x2000006b,
    'pc_program_page': 0x2000024b,
    'pc_erase_sector': 0x2000013f,
    'pc_eraseAll': 0x2000008b,

    'static_base' : 0x20000000 + 0x00000004 + 0x000003dc,
    'begin_stack' : 0x200113f0,
    'end_stack' : 0x200103f0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x8000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200003f0,
        0x200083f0
    ],
    'min_program_length' : 0x8000,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x3dc,
    'rw_start': 0x3e0,
    'rw_size': 0x4,
    'zi_start': 0x3e4,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}

class STM32H7B0xx(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    MEMORY_MAP = MemoryMap(
        # Datasheet says there's 128KB, but there's actually 256KB
        FlashRegion( start=0x08000000, length=0x40000,  sector_size=0x2000,
                                                        page_size=0x8000,
                                                        is_boot_memory=True,
                                                        algo=FLASH_ALGO,
                                                        name="bank_1"),
        # Datasheet does not reference a flash bank 2,
        # but there's an additional 256KB here, as well.
        FlashRegion( start=0x08100000, length=0x40000,  sector_size=0x2000,
                                                        page_size=0x8000,
                                                        algo=FLASH_ALGO,
                                                        name="bank_2"),
        RamRegion(   start=0x20000000, length=0x20000, name="dtcm"),
        RamRegion(   start=0x24000000, length=0x40000, name="axi_sram_1"),
        RamRegion(   start=0x24040000, length=0x60000, name="axi_sram_2"),
        RamRegion(   start=0x240A0000, length=0x60000, name="axi_sram_3"),
        RamRegion(   start=0x30000000, length=0x10000, name="ahb_sram_1"),
        RamRegion(   start=0x30010000, length=0x10000, name="ahb_sram_2"),
        RamRegion(   start=0x38000000, length=0x8000, name="sdr_sram"),
        RamRegion(   start=0x38800000, length=0x1000, name="backup_sram"),
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
        seq = super().create_init_sequence()
        if self.session.options.get('connect_mode') in ('halt', 'under-reset'):
            seq.insert_before('dp_init', ('assert_reset_for_connect', self.assert_reset_for_connect))
            seq.insert_after('dp_init', ('safe_reset_and_halt', self.safe_reset_and_halt))

        return seq

    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
