# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

FLASH_ALGO = {
    'load_address' : 0x20000000,
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x41f0e92d, 0x460e4605, 0x24004617, 0xf974f000, 0xf9c1f000, 0xb1144604, 0xe8bd2001, 0x200081f0,
    0x4601e7fb, 0x47702000, 0x2000b510, 0xf9cbf000, 0xbd102000, 0x4604b510, 0x1000f5a4, 0xf0002100,
    0x2000f9cd, 0xb570bd10, 0x460d4604, 0xf5a44616, 0x462a1000, 0xf0004631, 0xbd70f9fd, 0x43f8e92d,
    0x46884606, 0x46374615, 0x1700f5a7, 0xe0202400, 0x46692204, 0xf0004638, 0xf89dfa53, 0x5d290000,
    0xd1114288, 0x1001f89d, 0x5c281c60, 0xd10b4281, 0x1002f89d, 0x5c281ca0, 0xd1054281, 0x1003f89d,
    0x5c281ce0, 0xd0024281, 0xe8bd1938, 0x1d3f83f8, 0x45441d24, 0xeb06d3dc, 0xe7f60008, 0x43f8e92d,
    0x46884606, 0x46354614, 0x1500f5a5, 0xe0192700, 0x46692204, 0xf0004628, 0xf89dfa23, 0x42a00000,
    0xf89dd10b, 0x42a00001, 0xf89dd107, 0x42a00002, 0xf89dd103, 0x42a00003, 0x19e8d002, 0x83f8e8bd,
    0x1d3f1d2d, 0xd3e34547, 0xe7f72000, 0x9800b501, 0xbd086800, 0x9800b503, 0xbd0c6001, 0x4604b570,
    0x46290625, 0xf7ff48fc, 0xf045fff5, 0x48fa0101, 0xfff0f7ff, 0xf7ff48f8, 0x4605ffe9, 0xbf00e000,
    0xf7ff48f5, 0xf000ffe3, 0x28020002, 0xbd70d0f7, 0x2006b510, 0xffe2f7ff, 0xf7ff20e4, 0xbd10ffdf,
    0xbf00b510, 0x64b0f04f, 0x48eb4621, 0xffd2f7ff, 0x0101f044, 0xf7ff48e8, 0x48e7ffcd, 0xffc6f7ff,
    0xe0004604, 0x48e4bf00, 0xffc0f7ff, 0x0002f000, 0xd0f72802, 0x301048e0, 0xffb8f7ff, 0x0001f000,
    0xd1df2800, 0xe92dbd10, 0xb0844dff, 0x46904683, 0x9f12469a, 0xf1b89e10, 0xd0060f00, 0x0001f1a8,
    0x0003f000, 0x0008f040, 0x2000e000, 0xb12f9003, 0xf0001e78, 0xf0400007, 0xe0000008, 0x90022000,
    0x1e70b12e, 0x0007f000, 0x0008f040, 0x2000e000, 0x25009001, 0x444949c9, 0x98137809, 0xb2c04348,
    0x48c59000, 0x99051d00, 0xff84f7ff, 0xbf00b33e, 0xe0042400, 0x0004f81a, 0x2505ea40, 0x2e041c64,
    0x4630da01, 0x2004e000, 0xd8f342a0, 0x48ba4629, 0xf7ff3018, 0x2500ff6f, 0xe0042404, 0x0004f81a,
    0x2505ea40, 0x2e081c64, 0x4630da01, 0x2008e000, 0xd8f342a0, 0x48b04629, 0xf7ff301c, 0xea4fff5b,
    0x9802610b, 0x5100ea41, 0xea419803, 0x98014100, 0x3100ea41, 0xf0009800, 0xea41001f, 0x462915c0,
    0xf7ff48a5, 0xf045ff47, 0x48a30101, 0xff42f7ff, 0xf7ff48a1, 0x4605ff3b, 0x489fbf00, 0xff36f7ff,
    0x0002f000, 0xd0f82802, 0x489bb31f, 0xf7ff3010, 0x4605ff2d, 0xe0032400, 0x55059811, 0x1c640a2d,
    0xda012f04, 0xe0004638, 0x42a02004, 0x4892d8f4, 0xf7ff3014, 0x4605ff1b, 0xe0032404, 0x55059811,
    0x1c640a2d, 0xda012f08, 0xe0004638, 0x42a02008, 0xb008d8f4, 0x8df0e8bd, 0xb087b500, 0x21032000,
    0xe9cdaa05, 0x46030200, 0xe9cd4602, 0x46011002, 0xf7ff209f, 0xf89dff48, 0x28200016, 0xf89dd139,
    0x28ba0015, 0x2000d135, 0xaa052102, 0x0200e9cd, 0x46024603, 0x1002e9cd, 0x20b54601, 0xff33f7ff,
    0x0015f89d, 0xd103288f, 0x0014f89d, 0xd02028ff, 0xf88d208f, 0x20ff0018, 0x0019f88d, 0xf7ff2006,
    0x2000fedd, 0xe9cd2302, 0x90023000, 0x4602ab06, 0x90034601, 0xf7ff20b1, 0xf7ffff16, 0x2066fef1,
    0xfeccf7ff, 0xfeecf7ff, 0xf7ff2099, 0xf7fffec7, 0xb007fee7, 0xb510bd00, 0x2400b086, 0x21032000,
    0xe9cdaa05, 0x46030200, 0xe9cd4602, 0x46011002, 0xf7ff209f, 0xf89dfef8, 0x28ba0015, 0x2401d000,
    0xb0064620, 0xb510bd10, 0x20064604, 0xfea6f7ff, 0xf7ff20c7, 0xf7fffea3, 0xbd10fec3, 0xb085b530,
    0x460d4604, 0xf7ff2006, 0x2000fe99, 0xe9cda904, 0x46030100, 0x46212203, 0x0502e9cd, 0xf7ff20d8,
    0xf7fffed2, 0xb005fead, 0xb510bd30, 0x4842bf00, 0xf7ff3890, 0xf000fe7b, 0x28004000, 0x483ed0f7,
    0xf7ff3890, 0x4604fe73, 0x1480f024, 0x483a4621, 0xf7ff3890, 0xbd10fe6f, 0x4837b510, 0xf7ff3890,
    0x4604fe65, 0x0480f044, 0x48334621, 0xf7ff3890, 0xbd10fe61, 0x45f0e92d, 0x4606b089, 0x4617468a,
    0x4654463d, 0xe05046b0, 0xd30d2d04, 0xf88d7820, 0x78600017, 0x0016f88d, 0xf88d78a0, 0x78e00015,
    0x0014f88d, 0xe02b1f2d, 0xd10d2d03, 0xf88d7820, 0x78600017, 0x0016f88d, 0xf88d78a0, 0x20ff0015,
    0x0014f88d, 0xe01b2500, 0xd10c2d02, 0xf88d7820, 0x78600017, 0x0016f88d, 0xf88d20ff, 0xf88d0015,
    0x25000014, 0x2d01e00c, 0x7820d10a, 0x0017f88d, 0xf88d20ff, 0xf88d0016, 0xf88d0015, 0x25000014,
    0xf7ff2006, 0x2000fe1b, 0x2304aa07, 0x2001e9cd, 0x90039300, 0x2203ab05, 0x20024641, 0xfe53f7ff,
    0xfe2ef7ff, 0x0804f108, 0x19f01d24, 0xd8ab4540, 0xb0092000, 0x85f0e8bd, 0x4010a090, 0x00000005,
    0xb088b570, 0x460c4605, 0x20004616, 0xaa062104, 0x1200e9cd, 0x2203ab04, 0x1002e9cd, 0x46104629,
    0xfe31f7ff, 0x0018f89d, 0xf89d7020, 0x70600019, 0x001af89d, 0xf89d70a0, 0x70e0001b, 0xb0082000,
    0x0000bd70, 0x00000000, 0x00000000
    ],
    
    # Function addresses
    'pc_init': 0x20000021,
    'pc_unInit': 0x20000043,
    'pc_program_page': 0x20000067,
    'pc_erase_sector': 0x20000055,
    'pc_eraseAll': 0x20000049,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000564,
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

class MuscaA1(CoreSightTarget):

    VENDOR = "Arm"
    
    MEMORY_MAP = MemoryMap(
        # Due to an errata, only the first 256 kB of QSPI is memory mapped. The remainder
        # of the 8 MB region can be read and written via register accesses only.
        FlashRegion(name='nqspi',    start=0x00200000, length=0x00040000, access='rx',
                        blocksize=0x10000,
                        page_size=0x10000,
                        is_boot_memory=True,
                        is_external=True,
                        algo=FLASH_ALGO),
        FlashRegion(name='sqspi',    start=0x10200000, length=0x00040000, access='rxs',
                        blocksize=0x10000,
                        page_size=0x10000,
                        is_boot_memory=True,
                        is_external=True,
                        algo=FLASH_ALGO,
                        alias='nqspi'),
        # Because of the above mentioned errata, these "*qspix" regions don't really exist
        # in the memory map, but are present to allow the full QSPI to be programmed by the
        # flash algo.
        FlashRegion(name='nqspix',   start=0x00240000, length=0x007c0000, access='',
                        blocksize=0x10000,
                        page_size=0x10000,
                        is_default=False,
                        is_testable=False,
                        is_external=True,
                        algo=FLASH_ALGO),
        FlashRegion(name='sqspix',   start=0x10240000, length=0x007c0000, access='s',
                        blocksize=0x10000,
                        page_size=0x10000,
                        is_default=False,
                        is_testable=False,
                        is_external=True,
                        algo=FLASH_ALGO,
                        alias='nqspix'),
        RamRegion(  name='ncoderam', start=0x00000000, length=0x00200000, access='rwx'),
        RamRegion(  name='scoderam', start=0x10000000, length=0x00200000, access='rwxs',
                        alias='ncoderam'),
        # Due to an errata, the first 8 kB of sysram is not accessible to the debugger.
        RamRegion(  name='nsysram',  start=0x20002000, length=0x0001e000, access='rwx'),
        RamRegion(  name='ssysram',  start=0x30002000, length=0x0001e000, access='rwxs',
                        alias='nsysram'),
        )

    def __init__(self, session):
        super(MuscaA1, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("Musca.svd")

