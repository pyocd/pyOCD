# pyOCD debugger
# Copyright (c) 2022 NXP
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...coresight.cortex_m_v8m import CortexM_v8M

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x0100f24a, 0x0101f2c4, 0xf0206808, 0xf04000a0, 0x60080020, 0x70fff64f, 0xf24c6088, 0xf6cd5020,
    0x60481028, 0xf4106808, 0xd00b6f00, 0xf4106808, 0xd0076f00, 0xf4106808, 0xd0036f00, 0xf4106808,
    0xd1ef6f00, 0xf4106808, 0xd10b6f80, 0xf4106808, 0xd1076f80, 0xf4106808, 0xd1036f80, 0xf4106808,
    0xd0ef6f80, 0xf2c42008, 0x68020002, 0x130ff240, 0x6002439a, 0xf0426802, 0x60020203, 0x40c0f44f,
    0xf012580a, 0xd10b0f80, 0xf012580a, 0xd1070f80, 0xf012580a, 0xd1030f80, 0xf012580a, 0xd0ef0f80,
    0x42c0f44f, 0x20002334, 0x4770508b, 0x47702000, 0xf2c42000, 0x21400002, 0x21006101, 0x21806141,
    0xbf006001, 0xf0116801, 0xd10b0f80, 0xf0116801, 0xd1070f80, 0xf0116801, 0xd1030f80, 0xf0116801,
    0xd0ef0f80, 0xf0006800, 0x47700001, 0xf2c42100, 0x22340102, 0x2242600a, 0x2200610a, 0x2280614a,
    0xbf00600a, 0xf012680a, 0xd10b7f40, 0xf012680a, 0xd1077f40, 0xf012680a, 0xd1037f40, 0xf012680a,
    0xd0ef7f40, 0x32fff04f, 0x2200e9c0, 0x2202e9c0, 0xf1b06808, 0xdd093fff, 0x28006808, 0x6808db06,
    0xdb032800, 0xf1b06808, 0xdcf13fff, 0x4000f04f, 0xbf006008, 0xf0106808, 0xd10b0f80, 0xf0106808,
    0xd1070f80, 0xf0106808, 0xd1030f80, 0xf0106808, 0xd0ef0f80, 0xf0006808, 0x47700001, 0x4df0e92d,
    0x29004603, 0x0000f04f, 0xe8bdbf08, 0xf2408df0, 0xf2c40c00, 0xf04f0c02, 0xf04f4b00, 0xe0060a00,
    0x0a80f10a, 0xbf24458a, 0xe8bd2000, 0x46148df0, 0xf8cc2234, 0x22232000, 0x2010f8cc, 0xf8cc2280,
    0xf8cc0014, 0xbf002000, 0x2000f8dc, 0x7f40f012, 0xf8dcd10e, 0xf0122000, 0xd1097f40, 0x2000f8dc,
    0x7f40f012, 0xf8dcd104, 0xf0122000, 0xd0eb7f40, 0x0280f104, 0xbf002500, 0x8025f854, 0x0e85eb04,
    0x8025f843, 0x0685eb03, 0x7004f8de, 0x60773510, 0x7008f8de, 0x60b72d20, 0x700cf8de, 0xf8de60f7,
    0x61377010, 0x7014f8de, 0xf8de6177, 0x61b77018, 0x701cf8de, 0xf8de61f7, 0x62377020, 0x7024f8de,
    0xf8de6277, 0x62b77028, 0x702cf8de, 0xf8de62f7, 0x63377030, 0x7034f8de, 0xf8de6377, 0x63b77038,
    0x703cf8de, 0xd1c763f7, 0xbf003380, 0x7000f8dc, 0x3ffff1b7, 0xf8dcdd0c, 0x2f007000, 0xf8dcdb08,
    0x2f007000, 0xf8dcdb04, 0xf1b77000, 0xdced3fff, 0xb000f8cc, 0x7000f8dc, 0x0f80f017, 0xf8dcd10e,
    0xf0177000, 0xd1090f80, 0x7000f8dc, 0x0f80f017, 0xf8dcd104, 0xf0177000, 0xd0eb0f80, 0x7000f8dc,
    0x0f01f017, 0xaf6cf43f, 0xe8bd2001, 0xbf008df0, 0x460cb5b0, 0xf36f4605, 0x4611501f, 0xf0004622,
    0x2800f805, 0x4425bf08, 0xbdb04628, 0x4604b530, 0x46032000, 0x1c5be000, 0xd2034293, 0x5ccd5ce0,
    0xd0f81b40, 0x0000bd30, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x200000b1,
    'pc_program_page': 0x20000181,
    'pc_erase_sector': 0x200000f1,
    'pc_eraseAll': 0x200000b5,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000308,
    'begin_stack' : 0x20001710,
    'end_stack' : 0x20000710,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000310,
        0x20000510
    ],
    'min_program_length' : 0x200,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x308,
    'rw_start': 0x30c,
    'rw_size': 0x4,
    'zi_start': 0x310,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}


class KW45B41Z(CoreSightTarget):

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0, length=0x100000, blocksize=0x2000, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(name="TCM_SYS", start=0x20000000, length=0x1c000),
        RamRegion(name="TCM_CODE", start=0x4000000, length=0x4000)
    )

    def __init__(self, session):
        super(KW45B41Z, self).__init__(session, self.MEMORY_MAP)

    def create_init_sequence(self):
        seq = super(KW45B41Z, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('find_aps', self.create_aps)\
                           .replace_task('create_cores', self.create_core)
            )
        return seq

    def create_aps(self):
        self.dp.valid_aps = [0, 31, 30]

    def create_core(self):
        core = CortexM_v8M(self.session, self.aps[0], self.memory_map, address=0x80030000)
        core.default_reset_type = self.ResetType.HW
        self.aps[0].core = core
        core.init()
        self.add_core(core)

        self.dp.write_dp(0x020000f0, 2)
        ret = self.dp.read_ap(3)
        print(hex(ret))

        self.dp.write_dp(0x02000000, 2)
        self.dp.read_dp(0)

        # Active DebugMailbox
        self.dp.write_ap(0x21, 0)
        self.dp.read_ap(0)

        # // Enter Debug Session
        self.dp.write_ap(0x07, 1)
        self.dp.read_ap(0)
