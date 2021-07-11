# pyOCD debugger
# Copyright (c) 2021 Huada Semiconductor Corporation
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


class DBGMCU:
    STCTL = 0x40015004
    STCTL_VALUE = 0x9

FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4770ba40, 0x4770bac0, 0xbf002100, 0xbf00e001, 0x48071c49, 0xd3fa4281, 0x4a062001, 0x21006110,
    0xbf00e001, 0x29641c49, 0x2000d3fb, 0x00004770, 0x00002710, 0x40000880, 0x481bb510, 0x084068c0,
    0x1c400040, 0x60c84918, 0x68c04608, 0x43882170, 0x49153050, 0x460860c8, 0x158968c0, 0x18404388,
    0x60c84911, 0x48112400, 0xe0076020, 0x680020c0, 0x0fc007c0, 0xd1012800, 0xf92af000, 0x6900480a,
    0x310121ff, 0x28004008, 0x4807d0f0, 0x217068c0, 0x49054388, 0x460860c8, 0x084068c0, 0x60c80040,
    0xffb2f7ff, 0xbd102000, 0x40000800, 0x00001234, 0x4604b530, 0x48204d1f, 0x084068c0, 0x1c400040,
    0x60c8491d, 0x68c04608, 0x43882170, 0x491a3040, 0x460860c8, 0x158968c0, 0x18404388, 0x60c84916,
    0x2000bf00, 0xe00b6020, 0x02402001, 0xd2074284, 0x680020c0, 0x0fc007c0, 0xd1012800, 0xf8e8f000,
    0x6900480d, 0x310121ff, 0x28004008, 0x1e68d102, 0xd1e91e05, 0xff78f7ff, 0x68c04807, 0x43882170,
    0x60c84905, 0x68c04608, 0x00400840, 0x200060c8, 0x0000bd30, 0x00030d40, 0x40000800, 0x4603b510,
    0x4c074806, 0x48076020, 0x46206020, 0x15a468c0, 0x190043a0, 0x60e04c02, 0xbd102000, 0xffff0123,
    0x40000800, 0xffff3210, 0x4605b5fc, 0x20ff4c43, 0x4e433040, 0x46306170, 0x084068c0, 0x1c400040,
    0x463060f0, 0x267068c0, 0x303043b0, 0x60f04e3c, 0x68c04630, 0x43b015b6, 0x4e391980, 0x950160f0,
    0x2300bf00, 0x4c35e021, 0x98016816, 0x98016006, 0x90011d00, 0xbf001d12, 0x69004831, 0x40302610,
    0xd1022800, 0x1e041e60, 0x2c00d1f6, 0x2001d101, 0x482bbdfc, 0x07006900, 0x28000f00, 0x2001d001,
    0x2010e7f6, 0x61704e26, 0x08881c5b, 0xd8da4298, 0x0f800788, 0xd01b2800, 0x1ace9200, 0x078b1970,
    0xe0100f9b, 0x78369e00, 0x9e007006, 0x1c401c76, 0xbf009600, 0x69364e1a, 0x403e2710, 0xd0f92e00,
    0x4f172610, 0x461e617e, 0x2e001e5b, 0xbf00d1ea, 0x68c04813, 0x43b02670, 0x60f04e11, 0x68c04630,
    0x00400840, 0x4c0d60f0, 0x480dbf00, 0x26ff6900, 0x40303601, 0xd1022800, 0x1e041e60, 0x2c00d1f5,
    0x2001d101, 0x4806e7b4, 0x07006900, 0x28000f00, 0x2001d001, 0x2000e7ac, 0x0000e7aa, 0x00030d40,
    0x40000800, 0x48074601, 0x22ff68c0, 0x43903201, 0x60d04a04, 0x60d02001, 0x60d02000, 0x60101e40,
    0x47702000, 0x40000800, 0x4603b570, 0x2500460c, 0x2100461d, 0x782ee006, 0x5c501c6d, 0xd0004286,
    0x1c49e002, 0xd3f642a1, 0x1858bf00, 0x0000bd70, 0x4825b510, 0x20c06842, 0x07006800, 0x20c00f84,
    0x05006800, 0x2c000f03, 0x1192d101, 0x2c01e008, 0x1292d101, 0x2c02e004, 0x1312d101, 0x1392e000,
    0xd1012b00, 0xe0002001, 0x2b0f2000, 0x2101d101, 0x2100e000, 0x28004308, 0xf000d002, 0xe022f827,
    0x0fc007d8, 0xd0042800, 0xd11c2a00, 0xf81ef000, 0x2002e019, 0x28024018, 0x2a01d104, 0xf000d113,
    0xe010f815, 0x40182004, 0xd1042804, 0xd10a2a02, 0xf80cf000, 0x2008e007, 0x28084018, 0x2a03d103,
    0xf000d101, 0xbd10f803, 0x4000cc00, 0x302420ff, 0x60884902, 0x60884802, 0x00004770, 0x4000cc00,
    0x00003210, 0x00000000
    ],

    'pc_init': 0x2000015d,
    'pc_unInit': 0x200002a5,
    'pc_program_page': 0x20000189,
    'pc_erase_sector': 0x200000d1,
    'pc_eraseAll': 0x20000059,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000384,
    'begin_stack' : 0x20000600,
    'begin_data' : 0x20000000 + 0xA00,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20000A00, 0x20000C00],   # Enable double buffering
    'min_program_length' : 0x200,
  }


class HC32F120x6TA(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32F120x6TA, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32F120.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.STCTL, DBGMCU.STCTL_VALUE)


class HC32F120x8TA(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x10000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32F120x8TA, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32F120.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.STCTL, DBGMCU.STCTL_VALUE)


class HC32M120(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, session):
        super(HC32M120, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32M120.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.STCTL, DBGMCU.STCTL_VALUE)
