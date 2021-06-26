# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile
import logging

LOG = logging.getLogger(__name__)
RESET_MASK = 0x50021104
RESET_MASK_SYSRSTREQ0_EN = 1 << 4

FLASH_ALGO_QSPI = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x41f0e92d, 0x460e4605, 0x24004617, 0xf9cbf000, 0xb1144604, 0xe8bd2001, 0x200081f0, 0x4601e7fb,
    0x47702000, 0x2000b510, 0xf9d9f000, 0xbd102000, 0x4604b510, 0x417ff024, 0x1000f5a1, 0xf0002100,
    0x2000f9d9, 0xb570bd10, 0x460d4604, 0xf0244616, 0xf5a1417f, 0x462a1000, 0xf0004631, 0xbd70fa07,
    0x43f8e92d, 0x46884607, 0xf0274615, 0xf5a6467f, 0x24001600, 0x2204e022, 0x46304669, 0xfa5cf000,
    0x0000f89d, 0x42885d29, 0xf89dd111, 0x1c601001, 0x42815c28, 0xf89dd10b, 0x1ca01002, 0x42815c28,
    0xf89dd105, 0x1ce01003, 0x42815c28, 0xf506d004, 0x44201000, 0x83f8e8bd, 0x1d241d36, 0xd3da4544,
    0x0008eb07, 0xe92de7f6, 0x460643f8, 0x4614460f, 0x457ff026, 0x1500f5a5, 0x0800f04f, 0x2204e01a,
    0x46284669, 0xfa28f000, 0x0000f89d, 0xd10b42a0, 0x0001f89d, 0xd10742a0, 0x0002f89d, 0xd10342a0,
    0x0003f89d, 0xd00242a0, 0xe8bd2001, 0x1d2d83f8, 0x0804f108, 0xd3e245b8, 0xe7f62000, 0x9800b501,
    0xbd086800, 0x9800b503, 0xbd0c6001, 0x4604b570, 0x46290625, 0xf7ff48fe, 0xf045fff5, 0x48fc0101,
    0xfff0f7ff, 0xf7ff48fa, 0x4605ffe9, 0xbf00e000, 0xf7ff48f7, 0xf000ffe3, 0x28020002, 0xbd70d0f7,
    0x2006b510, 0xffe2f7ff, 0xf7ff20e4, 0xbd10ffdf, 0xbf00b510, 0x64b0f04f, 0x48ed4621, 0xffd2f7ff,
    0x0101f044, 0xf7ff48ea, 0x48e9ffcd, 0xffc6f7ff, 0xe0004604, 0x48e6bf00, 0xffc0f7ff, 0x0002f000,
    0xd0f72802, 0x301048e2, 0xffb8f7ff, 0x0001f000, 0xd1df2800, 0xe92dbd10, 0xb0844dff, 0x46904683,
    0x9f12469a, 0xf1b89e10, 0xd0060f00, 0x0001f1a8, 0x0003f000, 0x0008f040, 0x2000e000, 0xb12f9003,
    0xf0001e78, 0xf0400007, 0xe0000008, 0x90022000, 0x1e70b12e, 0x0007f000, 0x0008f040, 0x2000e000,
    0x25009001, 0x444949cb, 0x98137809, 0xb2c04348, 0x48c79000, 0x99051d00, 0xff84f7ff, 0xbf00b33e,
    0xe0042400, 0x0004f81a, 0x2505ea40, 0x2e041c64, 0x4630da01, 0x2004e000, 0xd8f342a0, 0x48bc4629,
    0xf7ff3018, 0x2500ff6f, 0xe0042404, 0x0004f81a, 0x2505ea40, 0x2e081c64, 0x4630da01, 0x2008e000,
    0xd8f342a0, 0x48b24629, 0xf7ff301c, 0xea4fff5b, 0x9802610b, 0x5100ea41, 0xea419803, 0x98014100,
    0x3100ea41, 0xf0009800, 0xea41001f, 0x462915c0, 0xf7ff48a7, 0xf045ff47, 0x48a50101, 0xff42f7ff,
    0xf7ff48a3, 0x4605ff3b, 0x48a1bf00, 0xff36f7ff, 0x0002f000, 0xd0f82802, 0x489db31f, 0xf7ff3010,
    0x4605ff2d, 0xe0032400, 0x55059811, 0x1c640a2d, 0xda012f04, 0xe0004638, 0x42a02004, 0x4894d8f4,
    0xf7ff3014, 0x4605ff1b, 0xe0032404, 0x55059811, 0x1c640a2d, 0xda012f08, 0xe0004638, 0x42a02008,
    0xb008d8f4, 0x8df0e8bd, 0xb087b500, 0x21032000, 0xe9cdaa05, 0x46030200, 0xe9cd4602, 0x46011002,
    0xf7ff209f, 0xf89dff48, 0x28ba0015, 0xf89dd003, 0x28bb0015, 0x2000d135, 0xaa052102, 0x0200e9cd,
    0x46024603, 0x1002e9cd, 0x20b54601, 0xff33f7ff, 0x0015f89d, 0xd103288f, 0x0014f89d, 0xd02028ff,
    0xf88d208f, 0x20ff0018, 0x0019f88d, 0xf7ff2006, 0x2000fedd, 0xe9cd2302, 0x90023000, 0x4602ab06,
    0x90034601, 0xf7ff20b1, 0xf7ffff16, 0x2066fef1, 0xfeccf7ff, 0xfeecf7ff, 0xf7ff2099, 0xf7fffec7,
    0xb007fee7, 0xb510bd00, 0x2401b086, 0x21032000, 0xe9cdaa05, 0x46030200, 0xe9cd4602, 0x46011002,
    0xf7ff209f, 0xf89dfef8, 0x28ba0015, 0xf89dd003, 0x28bb0015, 0x2400d100, 0xb0064620, 0xb510bd10,
    0x20064604, 0xfea2f7ff, 0xf7ff20c7, 0xf7fffe9f, 0xbd10febf, 0xb085b530, 0x460d4604, 0xf7ff2006,
    0x2000fe95, 0xe9cda904, 0x46030100, 0x46212203, 0x0502e9cd, 0xf7ff20d8, 0xf7fffece, 0xb005fea9,
    0xb510bd30, 0x4842bf00, 0xf7ff3890, 0xf000fe77, 0x28004000, 0x483ed0f7, 0xf7ff3890, 0x4604fe6f,
    0x1480f024, 0x483a4621, 0xf7ff3890, 0xbd10fe6b, 0x4837b510, 0xf7ff3890, 0x4604fe61, 0x0480f044,
    0x48334621, 0xf7ff3890, 0xbd10fe5d, 0x45f0e92d, 0x4606b089, 0x4617468a, 0x4654463d, 0xe05046b0,
    0xd30d2d04, 0xf88d7820, 0x78600017, 0x0016f88d, 0xf88d78a0, 0x78e00015, 0x0014f88d, 0xe02b1f2d,
    0xd10d2d03, 0xf88d7820, 0x78600017, 0x0016f88d, 0xf88d78a0, 0x20ff0015, 0x0014f88d, 0xe01b2500,
    0xd10c2d02, 0xf88d7820, 0x78600017, 0x0016f88d, 0xf88d20ff, 0xf88d0015, 0x25000014, 0x2d01e00c,
    0x7820d10a, 0x0017f88d, 0xf88d20ff, 0xf88d0016, 0xf88d0015, 0x25000014, 0xf7ff2006, 0x2000fe17,
    0x2304aa07, 0x2001e9cd, 0x90039300, 0x2203ab05, 0x20024641, 0xfe4ff7ff, 0xfe2af7ff, 0x0804f108,
    0x19f01d24, 0xd8ab4540, 0xb0092000, 0x85f0e8bd, 0x4010a090, 0x00000005, 0xb088b570, 0x460c4605,
    0x20004616, 0xaa062104, 0x1200e9cd, 0x2203ab04, 0x1002e9cd, 0x46104629, 0xfe2df7ff, 0x0018f89d,
    0xf89d7020, 0x70600019, 0x001af89d, 0xf89d70a0, 0x70e0001b, 0xb0082000, 0x0000bd70, 0x00000000,
    0x00000800
    ],

    # Relative function addresses
    'pc_init': 0x20000021,
    'pc_unInit': 0x2000003f,
    'pc_program_page': 0x20000067,
    'pc_erase_sector': 0x20000051,
    'pc_eraseAll': 0x20000045,

    'static_base' : 0x20000000 + 0x00000020 + 0x0000057c,
    'begin_stack' : 0x20000800,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001100],   # Enable double buffering
    'min_program_length' : 0x100,

    # Flash information
    'flash_start': 0x200000,
    'flash_size': 0x800000,
    'sector_sizes': (
        (0x0, 0x10000),
    )
}


class MuscaS1(CoreSightTarget):

    VENDOR = "Arm"

    MEMORY_MAP = MemoryMap(
        RamRegion(name='nemram',     start=0x0A000000, length=0x00200000, access='rx',
                        # is_boot_memory=True,
                        # is_external=False,
                        # is_default=True
                        ),
        RamRegion(name='semram',     start=0x1A000000, length=0x00200000, access='rxs',
                        # is_boot_memory=True,
                        # is_external=False,
                        # is_default=True,
                        alias='nemram'),
        FlashRegion(name='nqspi',       start=0x00200000, length=0x02000000, access='rx',
                        blocksize=0x10000,
                        page_size=0x10000,
                        is_boot_memory=True,
                        is_external=True,
                        is_default=True,
                        algo=FLASH_ALGO_QSPI),
        FlashRegion(name='sqspi',       start=0x10200000, length=0x02000000, access='rxs',
                        blocksize=0x10000,
                        page_size=0x10000,
                        is_boot_memory=True,
                        is_external=True,
                        is_default=True,
                        algo=FLASH_ALGO_QSPI,
                        alias='nqspi'),
        RamRegion(  name='ncoderam',    start=0x00000000, length=0x00200000, access='rwx'),
        RamRegion(  name='scoderam',    start=0x10000000, length=0x00200000, access='rwxs',
                        alias='ncoderam'),
        RamRegion(  name='nsysram',     start=0x20000000, length=0x00080000, access='rwx'),
        RamRegion(  name='ssysram',     start=0x30000000, length=0x00080000, access='rwxs',
                        alias='nsysram'),
        # This issue in Musca-B1 seems to have been fixed:
        # # Due to an errata, the first 8 kB of sysram is not accessible to the debugger.
        # # RamRegion(name='nsysram', start=0x20002000, length=0x0007e000, access='rwx'),
        # # RamRegion(name='ssysram', start=0x30002000, length=0x0007e000, access='rwxs',
        # #                 alias = 'nsysram'),
        )

    def __init__(self, session):
        super(MuscaS1, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("Musca_S1.svd")

    def create_init_sequence(self):
        seq = super(MuscaS1, self).create_init_sequence()

        seq.insert_before('halt_on_connect',
            ('enable_sysresetreq',        self._enable_sysresetreq),
            )

        return seq

    def _enable_sysresetreq(self):
        LOG.info("Enabling SYSRSTREQ0_EN")
        reset_mask = self.read32(RESET_MASK)
        reset_mask |= RESET_MASK_SYSRSTREQ0_EN
        self.write32(RESET_MASK, reset_mask)
