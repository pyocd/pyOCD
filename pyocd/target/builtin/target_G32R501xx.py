# pyOCD debugger
# Copyright (c) 2026 Kai
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

import logging

from ...core.memory_map import FlashRegion, MemoryMap, RamRegion
from ...coresight.ap import APv1Address, AccessPort
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM
from ...coresight.minimal_mem_ap import MinimalMemAP as MiniAP

LOG = logging.getLogger(__name__)

# Main body of the flash algorithm, excluding the final key constants.
MAIN_INSTRUCTIONS = [
    0xe7fdbe00,
    0x4178f100, 0x1280f5a0, 0x2f20f5b1, 0x0385f244, 0x912fea5f, 0x2f20f5b2, 0x922fea5f, 0x3f50ebb3,
    0x0002ea41, 0x911fea5f, 0x47704308, 0x0004f240, 0x0220f244, 0x0000f2c0, 0x1000f859, 0x0202f2c5,
    0x60114448, 0x60516841, 0x60916881, 0x60d168c1, 0xf8c26901, 0x69411080, 0x1084f8c2, 0xf8c26981,
    0x69c01088, 0x008cf8c2, 0xbf004770, 0xf240b580, 0xf2440104, 0xf2c00320, 0xf8590100, 0xf2c52001,
    0x44490302, 0x684a601a, 0x688a605a, 0x68ca609a, 0x690a60da, 0x2080f8c3, 0xf8c3694a, 0x698a2084,
    0x2088f8c3, 0xf8c369c9, 0xf64e108c, 0xf2ce5188, 0x680a0100, 0x020cf042, 0x2101600a, 0x111cee00,
    0x4152f246, 0x0102f2c5, 0xf042880a, 0x800a0268, 0x0285f244, 0xebb22100, 0xee003f50, 0xd00b111c,
    0x4178f100, 0x2f20f5b1, 0xf5a0d306, 0x0c401080, 0xd9012804, 0xbd802000, 0x21322000, 0x0001f2c5,
    0xf8a6f000, 0x2000b920, 0xf8a7f000, 0xd0f12800, 0xbd802001, 0x47702000, 0xb085b5f0, 0x77fff64d,
    0x6400f04f, 0xf6c0ad01, 0xbf000709, 0x46212006, 0xf898f000, 0xbf004606, 0xf899f000, 0xd1fb2802,
    0xf000b986, 0xb968f899, 0xf44f4620, 0x462a6100, 0xf897f000, 0x42bcb930, 0x5400f504, 0x2000d9e6,
    0xbdf0b005, 0xb0052001, 0xbf00bdf0, 0xb084b5b0, 0xf2444604, 0xebb00085, 0xd00c3f54, 0x4078f104,
    0x2f20f5b0, 0xf5a4d307, 0x0c401080, 0xd9022804, 0xb0042000, 0x2006bdb0, 0xf0004621, 0x4605f863,
    0xf865f000, 0xd1fb2802, 0xf000b955, 0xb938f865, 0x466a4620, 0x6100f44f, 0xf863f000, 0xd0e72800,
    0xb0042001, 0xbf00bdb0, 0x45f0e92d, 0x4606b083, 0xf0004248, 0xf04f0007, 0x18440800, 0x4615d034,
    0x0a85f244, 0xbf00e00a, 0x60306828, 0x60706868, 0xf1063c08, 0xf1050608, 0xd0230508, 0x3f56ebba,
    0xf106d009, 0xf5b04078, 0xd3042f20, 0x1080f5a6, 0x28040c40, 0x4630d8e8, 0x22024629, 0xf8cd2300,
    0xf8cd8000, 0xf0008004, 0x4607f831, 0xf81ff000, 0xd1fb2802, 0xf000b91f, 0x2800f81f, 0xf04fd0d8,
    0xe0010801, 0x0800f04f, 0xb0034640, 0x85f0e8bd, 0x0c01f244, 0x0c00f2c1, 0xf2444760, 0xf2c10c31,
    0x47600c00, 0x1ce1f244, 0x0c00f2c1, 0xf2444760, 0xf2c10c1d, 0x47600c00, 0x0c11f244, 0x0c00f2c1,
    0xf6444760, 0xf2c16c41, 0x47600c00, 0x4c79f244, 0x0c00f2c1, 0x00004760, 0x00000000,
]

DECRYPT_KEYS = [
    (0x50024020, 0xFFFFFFFF),
    (0x50024024, 0xFFFFFFDC),
    (0x50024028, 0xFFFFFFFF),
    (0x5002402C, 0xFFFFFFFF),
    (0x500240A0, 0xFFFFFFFF),
    (0x500240A4, 0xFFFEDFFF),
    (0x500240A8, 0xFFFFFFFF),
    (0x500240AC, 0xFFFFFFFF),
]

DECRYPT_KEY_VALUES = [value for _, value in DECRYPT_KEYS]
CORE1_SET_ADDR = 0x08050000
CORE0_SET_ADDR = 0xFFFFFFFF
FLASH_INSTRUCTIONS = MAIN_INSTRUCTIONS + DECRYPT_KEY_VALUES

FLASH_ALGO = {
    'load_address': 0x00000000,
    'instructions': FLASH_INSTRUCTIONS,
    'pc_init': 0x00000071,
    'pc_unInit': 0x00000119,
    'pc_program_page': 0x000001cd,
    'pc_erase_sector': 0x00000171,
    'pc_eraseAll': 0x0000011d,
    'static_base': 0x00000000 + 0x00000004 + 0x00000298,
    'begin_stack': 0x000082c0,
    'end_stack': 0x000042c0,
    'begin_data': 0x00000000 + 0x1000,
    'page_size': 0x2000,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x000002c0, 0x000022c0],
    'min_program_length': 0x2000,
    'ro_start': 0x4,
    'ro_size': 0x298,
    'rw_start': 0x29c,
    'rw_size': 0x24,
    'zi_start': 0x2c0,
    'zi_size': 0x0,
    'flash_start': 0x0,
    'flash_size': 0x20308000,
    'sector_sizes': (
        (0x0, 0x2000),
    ),
}

MEMORY_MAP_G32R501XX = MemoryMap(
    FlashRegion(
        start=0x08000000,
        length=0xA0000,
        sector_size=0x2000,
        page_size=0x1000,
        is_boot_memory=True,
        algo=FLASH_ALGO,
    ),
    RamRegion(start=0x00000000, length=0xC000, access="rwx", is_cachable=False),
    RamRegion(start=0x20000000, length=0x4000, access="rwx", is_cachable=False),
    RamRegion(start=0x20100000, length=0x2000, access="rwx", init="0"),
    RamRegion(start=0x20200000, length=0x2000, access="rwx", init="0"),
    RamRegion(start=0x20300000, length=0x8000, access="rwx", init="0"),
)


class G32R501xxBase(CoreSightTarget):
    VENDOR = "Geehy"

    def __init__(self, session, memory_map):
        super().__init__(session, memory_map)

    def r501_dcs_setup(self):
        ap = MiniAP(self.dp)
        ap.init()

        ap.write32(0x50020000, 0x5AFFFFFF)
        ap.write32(0x50020004, 0xFFFFFF03)
        ap.write32(0x50020008, 0xFFFFFFFF)

        LOG.info("R501 DCS Key Set ...")
        for addr, value in DECRYPT_KEYS:
            ap.write32(addr, value)
            LOG.info("0x%08X -> [0x%08X]", addr, value)

        itcm_size = ap.read32(0x50020064)
        if itcm_size not in (3, 8):
            LOG.error("Insufficient ITCM RAM size for FLM algorithm. Please check CFGSMS configuration.")
            return

        LOG.info("R501 setup completed successfully.")

    def set_core0_vector_table(self):
        if CORE0_SET_ADDR == 0xFFFFFFFF:
            return

        core0 = self.cores.get(0)
        if core0 is None:
            LOG.warning("Skipping SP/PC setup because core0 is not available.")
            return

        core0.halt()
        sp_value, pc_value = core0.read_memory_block32(CORE0_SET_ADDR, 2)
        LOG.info("Applying core0 vector table from 0x%08X", CORE0_SET_ADDR)
        LOG.info("  MSP = 0x%08X", sp_value)
        LOG.info("  PC  = 0x%08X", pc_value)
        core0.write_core_register("msp", sp_value)
        core0.write_core_register("pc", pc_value)

    def bootmode_setup(self):
        self.write32(0x50020000, 0xA5FFFFFF)
        LOG.info("Entering Standalone Boot Mode")

    def init_cpu(self):
        # This mirrors the 0.36-era user script sequence that prepares RAM/code execution context
        # required by the flash algorithm after reset.
        self.write32(0xE000ED08, 0x10000000)

        value = self.read32(0xE000ED88)
        value |= 0x0C
        self.write32(0xE000ED88, value)

        value8 = self.read8(0x50010600)
        value8 |= 0xF0
        self.write8(0x50010600, value8)

        value16 = self.read16(0x50026452)
        value16 |= 0x68
        self.write16(0x50026452, value16)

        value = self.read32(0xE0059040)
        value |= 0x01
        self.write32(0xE0059040, value)

        value = self.read32(0xE0059044)
        value |= 0x01
        self.write32(0xE0059044, value)

        self.write32(0x50020074, 0x01)
        self.write16(0x500264C0, 0x0001)

        if (self.read32(0x50020B00) & 0x01) == 0x01:
            value = self.read32(0x50010830)
            value |= 0xFFFF
            self.write32(0x50010830, value)

        if (self.read32(0x50020B00) & 0x03) == 0x03:
            self.write32(0x50010000, 0x00000900)
            self.write32(0x50020844, 0x00000000)

            value = self.read32(0x0810B910)
            if ((value & 0xFF000000) >> 24) != 0x5A:
                self.write32(0x50020828, 18)
            if ((value & 0xFF000000) >> 24) == 0x5A:
                self.write32(0x50020828, (value >> 0x08) & 0xFF)

            temp_val = self.read32(0x0810B878)
            if (temp_val & 0xFF03) == 0x5A00:
                value = self.read32(0x500280D4)
                value |= 0x8000
                self.write32(0x500280D4, value)

            temp_val = self.read32(0x0810B894)
            if (temp_val & 0xFFFF) == 0x5A5A:
                self.write32(0x50028024, self.read32(0x0810B884))
                self.write32(0x50028028, self.read32(0x0810B888))
                self.write32(0x5002801C, self.read32(0x0810B88C))
                self.write32(0x50028020, self.read32(0x0810B890))

            if ((value & 0xFF000000) >> 24) == 0x5A:
                mask = value & 0xF0000
                self.write32(0x50021100, mask)
                self.write32(0x50021104, mask)
                self.write32(0x50020844, value & 0xFC)

            value2 = self.read32(0x0810B910)
            if ((value2 & 0xFF000003) == 0x5A000003) and (self.read32(0x5002082C) & 0x01):
                reg_val = self.read32(0x5002081C)
                reg_val |= 0x02
                self.write32(0x5002081C, reg_val)

        self.write32(0x50010000, 0x00000F00)

        value = self.read32(0x0810B800)
        self.write32(0x50020510, value)
        value = self.read32(0x0810B804)
        self.write32(0x50020514, value)
        value = self.read32(0x0810B80C)
        self.write32(0x50020524, value)
        value = self.read32(0x0810B814)
        self.write32(0x5002052C, value)
        value = self.read32(0x0810B818)
        self.write32(0x50020530, value)
        value = self.read32(0x0810B81C)
        self.write32(0x50020534, value)
        value = self.read32(0x0810B824)
        self.write32(0x5002053C, value)
        value = self.read32(0x0810B828)
        self.write32(0x50020540, value)
        value = self.read32(0x0810B82C)
        self.write32(0x50020544, value)
        value = self.read32(0x0810B830)
        self.write32(0x50020548, value)
        value = self.read32(0x0810B834)
        self.write32(0x5002054C, value)
        value = self.read32(0x0810B840)
        self.write32(0x50020558, value)
        value = self.read32(0x0810B844)
        self.write32(0x5002055C, value)
        value = self.read32(0x0810B84C)
        self.write32(0x50020564, value)
        value = self.read32(0x0810B850)
        self.write32(0x50020568, value)
        value = self.read32(0x0810B858)
        self.write32(0x50020570, value)
        value = self.read32(0x0810B860)
        self.write32(0x50020574, value)
        value = self.read32(0x0810B864)
        self.write32(0x50020578, value)
        value = self.read32(0x0810B868)
        self.write32(0x5002057C, value)
        value = self.read32(0x0810B86C)
        self.write32(0x50020580, value)
        value = self.read32(0x0810B870)
        self.write32(0x50020584, value)

        value = self.read32(0x0810B914)
        if ((value & 0xFF000000) >> 24) == 0x5A:
            self.write32(0x5002075C, value)

        temp = self.read32(0x50010604)
        self.write32(0x20307F30, temp)
        temp = self.read32(0x50010650)
        self.write32(0x20307F34, temp)
        temp = self.read32(0x50010608)
        self.write32(0x20307F28, temp)
        temp = self.read32(0x50010654)
        self.write32(0x20307F2C, temp)

        error_status = self.read32(0x50024014)
        if ((error_status & 0xFF000000) >> 24) == 0x5A:
            pin_sel = (error_status & 0x00000030) >> 4
            if pin_sel == 0x0:
                gpamux2 = self.read32(0x40030010)
                gpamux2 = (gpamux2 & ~(0x03 << 16)) | (0x01 << 16)
                self.write32(0x40030010, gpamux2)

                gpagmux2 = self.read32(0x40030044)
                gpagmux2 = (gpagmux2 & ~(0x03 << 16)) | (0x03 << 16)
                self.write32(0x40030044, gpagmux2)

                lock = self.read32(0x40030078)
                lock |= (0x01 << 24)
                self.write32(0x40030078, lock)
            elif pin_sel == 0x1:
                gpamux2 = self.read32(0x40030010)
                gpamux2 = (gpamux2 & ~(0x03 << 24)) | (0x01 << 24)
                self.write32(0x40030010, gpamux2)

                gpagmux2 = self.read32(0x40030044)
                gpagmux2 = (gpagmux2 & ~(0x03 << 24)) | (0x03 << 24)
                self.write32(0x40030044, gpagmux2)

                lock = self.read32(0x40030078)
                lock |= (0x01 << 28)
                self.write32(0x40030078, lock)
            elif pin_sel == 0x2:
                gpamux2 = self.read32(0x40030010)
                gpamux2 = (gpamux2 & ~(0x03 << 26)) | (0x01 << 26)
                self.write32(0x40030010, gpamux2)

                gpagmux2 = self.read32(0x40030044)
                gpagmux2 = (gpagmux2 & ~(0x03 << 26)) | (0x03 << 26)
                self.write32(0x40030044, gpagmux2)

                lock = self.read32(0x40030078)
                lock |= (0x01 << 29)
                self.write32(0x40030078, lock)

        config_val = self.read32(0x0810B914) & 0xFF
        if config_val == 0x00:
            self.write32(0x40030018, 0xFFCFFFFF)
            self.write32(0x40030098, 0x0F6001FF)
        elif config_val == 0x01:
            self.write32(0x40030018, 0xFFCFFFFF)
            self.write32(0x40030098, 0x00607FFF)
        elif config_val == 0x02:
            self.write32(0x40030018, 0x31CF3FFF)
            self.write32(0x40030098, 0x0000007B)
        elif config_val == 0x03:
            self.write32(0x40030018, 0x31CF3BFF)
            self.write32(0x40030098, 0x0000007B)
        elif config_val == 0x04:
            self.write32(0x40030018, 0x310D30FF)
            self.write32(0x40030098, 0x0000007B)

        if (self.read32(0x0810BA00) & 0xFFFF) == 0xA5A5:
            if (self.read32(0x50020B00) & 0x03) == 0x03:
                self.write32(0x5002800C, self.read32(0x0810BA04))
                self.write32(0x50028000, self.read32(0x0810BA08))
                self.write32(0x50028004, self.read32(0x0810BA0C))

        value = self.read32(0x50020A78)
        value |= 0x0F
        self.write32(0x50020A78, value)

        self.write32(0x50028010, self.read32(0x0810BA5C))
        self.write32(0x50028014, self.read32(0x0810BA60))
        self.write32(0x50028018, self.read32(0x0810BA64))
        self.write32(0x50028068, self.read32(0x0810BA68))
        self.write32(0x5002806C, self.read32(0x0810BA6C))
        self.write32(0x50028070, self.read32(0x0810BA70))

        self.write32(0x4002007C, self.read32(0x0810BA10))
        self.write32(0x4002047C, self.read32(0x0810BA14))
        self.write32(0x4002087C, self.read32(0x0810BA18))

        self.write16(0x40020076, self.read32(0x0810BA1C))
        self.write16(0x40020476, self.read32(0x0810BA20))
        self.write16(0x40020876, self.read32(0x0810BA24))

        self.write32(0x400200E0, self.read32(0x0810BA28))
        self.write32(0x400200E4, self.read32(0x0810BA2C))
        self.write32(0x400200E8, self.read32(0x0810BA30))
        self.write32(0x400204E0, self.read32(0x0810BA34))
        self.write32(0x400204E4, self.read32(0x0810BA38))
        self.write32(0x400204E8, self.read32(0x0810BA3C))
        self.write32(0x400208E0, self.read32(0x0810BA40))
        self.write32(0x400208E4, self.read32(0x0810BA44))

        value = self.read32(0x50020A84)
        value |= 0x00030000
        self.write32(0x50020A84, value)

        self.write32(0x5000180C, self.read32(0x0810BA50))
        self.write32(0x50001C0C, self.read32(0x0810BA54))

        value = self.read32(0x50020B00)
        value &= ~(0x03)
        self.write32(0x50020B00, value)

        for addr in range(0xE000E180, 0xE000E1C0, 4):
            self.write32(addr, 0xFFFFFFFF)
        for addr in range(0xE000E280, 0xE000E2C0, 4):
            self.write32(addr, 0xFFFFFFFF)

        LOG.info("CPU and peripheral initialization completed")

    def apply_startup_configuration(self):
        self.r501_dcs_setup()
        self.bootmode_setup()
        self.init_cpu()
        self.set_core0_vector_table()

    def post_connect_hook(self):
        # Integrate the essential 0.36-era user-script startup flow directly into the builtin target
        # so regular pyocd commands work without requiring an external project directory.
        self.apply_startup_configuration()

    def reset_and_halt(self, reset_type=None):
        super().reset_and_halt(reset_type or self.ResetType.SYSRESETREQ)
        self.halt()
        self.apply_startup_configuration()
        LOG.info("Reset & Halt completed, DCS setup done.")

    def create_init_sequence(self):
        seq = super().create_init_sequence()
        seq.wrap_task(
            'discovery',
            lambda seq: seq.replace_task('find_aps', self.find_aps).replace_task('create_cores', self.create_cores),
        )
        return seq

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return
        self.dp.read_ap(0xFC)
        self.dp.valid_aps = (0, 1, 2)
        AccessPort.create(self.dp, APv1Address(0))

    def create_cores(self):
        core = CortexM(self.session, self.aps[0], self.memory_map, 0)
        core.default_reset_type = self.ResetType.CORE
        self.aps[0].core = core
        core.init()
        self.add_core(core)
        self.selected_core = 0
        LOG.info("core0 is created and initialized.")


class G32R501Dxx(G32R501xxBase):
    MEMORY_MAP = MEMORY_MAP_G32R501XX

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def create_cores(self):
        core0 = CortexM(self.session, self.aps[0], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.CORE
        self.aps[0].core = core0
        core0.init()
        self.add_core(core0)
        LOG.info("core0 is created and initialized.")

        LOG.info("Enabling clock and setting startup address for core1 via AP0...")
        ap0 = self.aps[0]
        ap0.init()
        ap0.write32(0x50020054, CORE1_SET_ADDR)
        value = ap0.read32(0x50020058)
        ap0.write32(0x50020058, value | 0x2)

        core1 = CortexM(self.session, self.aps[1], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.CORE
        self.aps[1].core = core1
        core1.init()
        self.add_core(core1)
        self.selected_core = 0
        LOG.info("core1 is created and initialized.")


class G32R501xx(G32R501xxBase):
    MEMORY_MAP = MEMORY_MAP_G32R501XX

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def create_cores(self):
        super().create_cores()
