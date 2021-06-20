# pyOCD debugger
# Copyright (c) 2020 NXP
# Copyright (c) 2006-2013,2018 Arm Limited
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

import logging

from ..family.target_kinetis import Kinetis
from ..family.flash_kinetis import Flash_Kinetis
from ...core.memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from ...coresight import ap
from ...debug.svd.loader import SVDFile

LOG = logging.getLogger(__name__)

SIM_SDID = 0x40075024
SIM_SDID_KEYATTR_MASK = 0x70
SIM_SDID_KEYATTR_SHIFT = 4

KEYATTR_DUAL_CORE = 1

RCM_MR = 0x4007f010
RCM_MR_BOOTROM_MASK = 0x6

SCG_CSR = 0x4007B010

SCG_RCCR = 0x4007B014
SCS_MASK = 0x0F000000
SCS_SHIFT = 24
DIVCORE_MASK = 0x000F0000
DIVCORE_SHIFT = 16
DIVSLOW_MASK = 0x0000000F
DIVSLOW_SHIFT = 0

SCG_FIRCCSR = 0x4007B300
FIRCEN_MASK = 1

SCG_FIRCCFG = 0x4007B308

RECOVER_TIMEOUT = 1.0 # 1 second

FLASH_ALGO = {
    'load_address' : 0x20000000,
    'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4832b510, 0x60414930, 0x60814931, 0x22806801, 0x22204391, 0x60014311, 0x4448482e, 0xf860f000,
    0xd0002800, 0xbd102001, 0x47702000, 0xb5104829, 0x44484929, 0xf922f000, 0xd1042800, 0x21004825,
    0xf0004448, 0x4a25f9c3, 0x230168d1, 0x4319029b, 0xbd1060d1, 0x4c1fb570, 0x444c4605, 0x4b1e4601,
    0x68e24620, 0xf89ef000, 0xd1052800, 0x46292300, 0x68e24620, 0xf916f000, 0x68ca4918, 0x029b2301,
    0x60ca431a, 0xb570bd70, 0x460b460c, 0x46014606, 0xb0844810, 0x44484615, 0xf8bef000, 0xd10a2800,
    0x90029001, 0x480b2101, 0x462b9100, 0x46314622, 0xf0004448, 0x4909f957, 0x230168ca, 0x431a029b,
    0xb00460ca, 0x0000bd70, 0xd928c520, 0x40076000, 0x0000ffff, 0x00000004, 0x6b65666b, 0xf0003000,
    0xd00a2800, 0x68c9492b, 0x0e094a2b, 0x447a0049, 0x03095a51, 0x2064d103, 0x20044770, 0xb4104770,
    0x60032300, 0x21026041, 0x02896081, 0x492360c1, 0x158a7a0c, 0x610240a2, 0x61837ac9, 0xbc106141,
    0x47704618, 0xd0022800, 0x20006181, 0x20044770, 0x28004770, 0x2004d101, 0xb4104770, 0x42191e5b,
    0x421ad101, 0xbc10d002, 0x47702065, 0x428b6803, 0x6840d804, 0x18181889, 0xd2024288, 0x2066bc10,
    0xbc104770, 0x47702000, 0x4288490d, 0x206bd001, 0x20004770, 0x28004770, 0x290fd008, 0x2a04d802,
    0xe005d104, 0xd8012913, 0xd0012a08, 0x47702004, 0x47702000, 0x40075040, 0x00000512, 0x40020020,
    0x6b65666b, 0x4605b5f8, 0x460c4616, 0xf7ff4618, 0x2800ffdb, 0x2308d12b, 0x46214632, 0xf7ff4628,
    0x0007ffb8, 0x19a6d123, 0x1e7668e9, 0x91004630, 0xf922f000, 0xd0032900, 0x1c409e00, 0x1e764346,
    0xd81342b4, 0x4478480a, 0x60046800, 0x20094909, 0xf00071c8, 0x4607f8f9, 0x280069a8, 0x4780d000,
    0xd1032f00, 0x190468e8, 0xd9eb42b4, 0xbdf84638, 0x00000416, 0x40020000, 0xd1012a00, 0x47702004,
    0x461cb5ff, 0x4615b081, 0x2304460e, 0x98014622, 0xff7ff7ff, 0xd11a0007, 0xd0172c00, 0x4478480d,
    0x600e6801, 0x6800cd02, 0x490b6041, 0x71c82006, 0xf8caf000, 0x98014607, 0x28006980, 0x4780d000,
    0xd1032f00, 0x1d361f24, 0xd1e72c00, 0xb0054638, 0x0000bdf0, 0x000003be, 0x40020000, 0x4604b510,
    0xf7ff4608, 0x2800ff71, 0x2c00d106, 0x4904d005, 0x71c82044, 0xf8a8f000, 0x2004bd10, 0x0000bd10,
    0x40020000, 0xb081b5ff, 0x460e4614, 0x23084605, 0xff3ff7ff, 0xd12a2800, 0x686868a9, 0xf8acf000,
    0x42719000, 0x40014240, 0x42b7424f, 0x9800d101, 0x2c00183f, 0x1bbdd01a, 0xd90042a5, 0x490d4625,
    0x447908e8, 0x600e6809, 0x2201490b, 0x0a0271ca, 0x728872ca, 0x72489804, 0xf876f000, 0xd1062800,
    0x1b649800, 0x183f1976, 0xd1e42c00, 0xb0052000, 0x0000bdf0, 0x0000031a, 0x40020000, 0xd00c2800,
    0xd00a2a00, 0xd21a2908, 0x447b000b, 0x18db791b, 0x0705449f, 0x0d0b0907, 0x2004110f, 0x68c04770,
    0x6840e00a, 0x6880e008, 0x6800e006, 0x2001e004, 0x6900e002, 0x6940e000, 0x20006010, 0x206a4770,
    0x00004770, 0xd1012b00, 0x47702004, 0x461cb5f8, 0x460e4615, 0x9f082304, 0xfedbf7ff, 0xd1192800,
    0xd0172d00, 0x447a4a0f, 0x60066810, 0x2102480e, 0x990671c1, 0x681172c1, 0x60886820, 0xf824f000,
    0xd0082800, 0x29009907, 0x600ed000, 0xd0012f00, 0x60392100, 0x1d24bdf8, 0x1d361f2d, 0xd1e12d00,
    0x0000bdf8, 0x00000276, 0x40020000, 0xd1012800, 0x47702004, 0x4803b510, 0x71c22240, 0xf0007181,
    0xbd10f803, 0x40020000, 0x2170480a, 0x21807001, 0x78017001, 0xd5fc0609, 0x06817800, 0x2067d501,
    0x06c14770, 0x2068d501, 0x07c04770, 0x2069d0fc, 0x00004770, 0x40020000, 0x09032200, 0xd373428b,
    0x428b0a03, 0x0b03d358, 0xd33c428b, 0x428b0c03, 0xe012d321, 0x430b4603, 0x2200d47f, 0x428b0843,
    0x0903d374, 0xd35f428b, 0x428b0a03, 0x0b03d344, 0xd328428b, 0x428b0c03, 0x22ffd30d, 0xba120209,
    0x428b0c03, 0x1212d302, 0xd0650209, 0x428b0b03, 0xe000d319, 0x0bc30a09, 0xd301428b, 0x1ac003cb,
    0x0b834152, 0xd301428b, 0x1ac0038b, 0x0b434152, 0xd301428b, 0x1ac0034b, 0x0b034152, 0xd301428b,
    0x1ac0030b, 0x0ac34152, 0xd301428b, 0x1ac002cb, 0x0a834152, 0xd301428b, 0x1ac0028b, 0x0a434152,
    0xd301428b, 0x1ac0024b, 0x0a034152, 0xd301428b, 0x1ac0020b, 0xd2cd4152, 0x428b09c3, 0x01cbd301,
    0x41521ac0, 0x428b0983, 0x018bd301, 0x41521ac0, 0x428b0943, 0x014bd301, 0x41521ac0, 0x428b0903,
    0x010bd301, 0x41521ac0, 0x428b08c3, 0x00cbd301, 0x41521ac0, 0x428b0883, 0x008bd301, 0x41521ac0,
    0x428b0843, 0x004bd301, 0x41521ac0, 0xd2001a41, 0x41524601, 0x47704610, 0x0fcae05d, 0x4249d000,
    0xd3001003, 0x40534240, 0x469c2200, 0x428b0903, 0x0a03d32d, 0xd312428b, 0x018922fc, 0x0a03ba12,
    0xd30c428b, 0x11920189, 0xd308428b, 0x11920189, 0xd304428b, 0xd03a0189, 0xe0001192, 0x09c30989,
    0xd301428b, 0x1ac001cb, 0x09834152, 0xd301428b, 0x1ac0018b, 0x09434152, 0xd301428b, 0x1ac0014b,
    0x09034152, 0xd301428b, 0x1ac0010b, 0x08c34152, 0xd301428b, 0x1ac000cb, 0x08834152, 0xd301428b,
    0x1ac0008b, 0xd2d94152, 0x428b0843, 0x004bd301, 0x41521ac0, 0xd2001a41, 0x46634601, 0x105b4152,
    0xd3014610, 0x2b004240, 0x4249d500, 0x46634770, 0xd300105b, 0xb5014240, 0x46c02000, 0xbd0246c0,
    0x40020004, 0x00000000, 0x00000000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x00000000,
    0x00800000, 0x00000000,
    ],

    'pc_init' : 0x20000021,
    'pc_unInit': 0x20000049,
    'pc_program_page': 0x200000A7,
    'pc_erase_sector': 0x20000075,
    'pc_eraseAll' : 0x2000004D,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000624,
    'begin_stack' : 0x20000000 + 0x00000800,
    'begin_data' : 0x20000000 + 0x00000A00,
    'page_size' : 0x00000200,

    # All keys above are auto-generated. The following are added or modified.
    'analyzer_supported' : True,                 # [modified] default is False
    'analyzer_address' : 0x1fffa000,             # [modified] default is zero. Use 8K block before flash algo. Can be any unused SRAM.
    'page_buffers' : [0x20000a00, 0x20001200],   # [added] Use areas above algo. Note 'begin_data' is unused if double buffering. Can be any unused SRAM.
    'min_program_length' : 4                     # [added] See FSL_FEATURE_FLASH_PFLASH_BLOCK_WRITE_UNIT_SIZE in KSDK features header file
}

class Flash_kl28z(Flash_Kinetis):
    def __init__(self, target):
        super(Flash_kl28z, self).__init__(target, FLASH_ALGO)
        self._saved_firccsr = 0
        self._saved_rccr = 0

    def prepare_target(self):
        """!
        This function sets up target clocks to ensure that flash is clocked at the maximum
        of 24MHz. Doing so gets the best flash programming performance. The FIRC clock source
        is used so that there is no dependency on an external crystal frequency.
        """
        # Enable FIRC.
        value = self.target.read32(SCG_FIRCCSR)
        self._saved_firccsr = value
        value |= FIRCEN_MASK
        self.target.write32(SCG_FIRCCSR, value)

        # Switch system to FIRC, core=48MHz (/1), slow=24MHz (/2).
        # Flash and the bus are clocked from the slow clock, and its max is 24MHz,
        # so there is no benefit from raising the core clock further.
        self._saved_rccr = self.target.read32(SCG_RCCR)
        self.target.write32(SCG_RCCR, (0x3 << SCS_SHIFT) | (1 << DIVSLOW_SHIFT))

        csr = self.target.read32(SCG_CSR)
        LOG.debug("SCG_CSR = 0x%08x", csr)

    def restore_target(self):
        """! Restore clock registers to original values."""
        self.target.write32(SCG_FIRCCSR, self._saved_firccsr)
        self.target.write32(SCG_RCCR, self._saved_rccr)


class KL28x(Kinetis):

    SINGLE_MAP = MemoryMap(
        FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, is_boot_memory=True,
            flash_class=Flash_kl28z,
            algo=FLASH_ALGO),
        RamRegion(name='ram', start=0x1fff8000, length=0x20000),
        RamRegion(name='usb ram', start=0x40100000, length=0x800)
        )

    DUAL_MAP = MemoryMap(
        FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, is_boot_memory=True,
            flash_class=Flash_kl28z,
            algo=FLASH_ALGO),
        RomRegion(name='core1 imem alias', start=0x1d200000, length=0x40000),
        RamRegion(name='core0 ram', start=0x1fffa000, length=0x18000),
        RomRegion(name='core1 imem', start=0x2d200000, length=0x40000),
        RamRegion(name='core1 dmem', start=0x2d300000, length=0x8000),
        RamRegion(name='usb ram', start=0x40100000, length=0x800)
        )

    def __init__(self, session):
        super(KL28x, self).__init__(session, self.SINGLE_MAP)
        self.is_dual_core = False

        self._svd_location = SVDFile.from_builtin("MKL28T7_CORE0.svd")

    def create_init_sequence(self):
        seq = super(KL28x, self).create_init_sequence()

        seq.wrap_task('discovery',
            lambda seq: seq
                # The KL28 will lock up if an invalid AP is accessed, so replace the AP scan with a
                # fixed list of known APs.
                .replace_task('find_aps', self.create_kl28_aps)
                # Before creating cores, determine which memory map should be used.
                .insert_before('create_cores',
                    ('detect_dual_core', self.detect_dual_core)
                    )
            )

        return seq

    def create_kl28_aps(self):
        """! @brief Set the fixed list of valid AP numbers for KL28."""
        self.dp.valid_aps = [0, 1, 2]

    def detect_dual_core(self):
        if not isinstance(self.aps[0], ap.MEM_AP):
            return

        # Check if this is the dual core part.
        sdid = self.aps[0].read_memory(SIM_SDID)
        keyattr = (sdid & SIM_SDID_KEYATTR_MASK) >> SIM_SDID_KEYATTR_SHIFT
        LOG.debug("KEYATTR=0x%x SDID=0x%08x", keyattr, sdid)
        self.is_dual_core = (keyattr == KEYATTR_DUAL_CORE)
        if self.is_dual_core:
            LOG.info("KL28 is dual core")
            self.memory_map = self.DUAL_MAP

    def post_connect_hook(self):
        if not isinstance(self.aps[0], ap.MEM_AP):
            return
        # Disable ROM vector table remapping.
        self.aps[0].write32(RCM_MR, RCM_MR_BOOTROM_MASK)




