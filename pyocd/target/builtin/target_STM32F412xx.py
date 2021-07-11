# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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
    CR = 0xE0042004
    CR_VALUE = 0x7 # DBG_STANDBY | DBG_STOP | DBG_SLEEP

    APB1_FZ = 0xE0042008
    APB1_FZ_VALUE = 0x07E01DFF

    APB2_FZ = 0xE004200C
    APB2_FZ_VALUE = 0x00070003


FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x03004601, 0x28200e00, 0x0940d302, 0xe0051d00, 0xd3022810, 0x1cc00900, 0x0880e000, 0xd50102c9,
    0x43082110, 0x48424770, 0x60414940, 0x60414941, 0x60012100, 0x22f068c1, 0x60c14311, 0x06806940,
    0x483ed406, 0x6001493c, 0x60412106, 0x6081493c, 0x47702000, 0x69014836, 0x43110542, 0x20006101,
    0xb5104770, 0x69014832, 0x43212404, 0x69016101, 0x431103a2, 0x49336101, 0xe0004a30, 0x68c36011,
    0xd4fb03db, 0x43a16901, 0x20006101, 0xb530bd10, 0xffb6f7ff, 0x68ca4926, 0x431a23f0, 0x240260ca,
    0x690a610c, 0x0e0006c0, 0x610a4302, 0x03e26908, 0x61084310, 0x4a214823, 0x6010e000, 0x03ed68cd,
    0x6908d4fb, 0x610843a0, 0x060068c8, 0xd0030f00, 0x431868c8, 0x200160c8, 0xb570bd30, 0x1cc94d14,
    0x68eb0889, 0x26f00089, 0x60eb4333, 0x612b2300, 0xe0174b15, 0x431c692c, 0x6814612c, 0x68ec6004,
    0xd4fc03e4, 0x0864692c, 0x612c0064, 0x062468ec, 0xd0040f24, 0x433068e8, 0x200160e8, 0x1d00bd70,
    0x1f091d12, 0xd1e52900, 0xbd702000, 0x45670123, 0x40023c00, 0xcdef89ab, 0x00005555, 0x40003000,
    0x00000fff, 0x0000aaaa, 0x00000201, 0x00000000
    ],

    'pc_init' : 0x20000047,
    'pc_unInit': 0x20000075,
    'pc_program_page': 0x200000fb,
    'pc_erase_sector': 0x200000af,
    'pc_eraseAll' : 0x20000083,

    'static_base' : 0x20000000 + 0x00000020 + 0x0000014c,
    'begin_stack' : 0x20000000 + 0x00000800,
    'begin_data' : 0x20003000,
    'page_buffers' : [0x20003000, 0x20004000],
    'min_program_length' : 2,
    'analyzer_supported' : True,
    'analyzer_address' : 0x20002000
  }

class STM32F412xE(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x08000000, length=0x10000, sector_size=0x4000,
                        page_size=0x1000,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        FlashRegion( start=0x08010000, length=0x10000, sector_size=0x10000,
                        page_size=0x1000,
                        algo=FLASH_ALGO),
        FlashRegion( start=0x08020000, length=0x60000, sector_size=0x20000,
                        page_size=0x1000,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x40000)
        )

    def __init__(self, session):
        super(STM32F412xE, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32F41x.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1_FZ, DBGMCU.APB1_FZ_VALUE)
        self.write32(DBGMCU.APB2_FZ, DBGMCU.APB2_FZ_VALUE)

class STM32F412xG(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x08000000, length=0x10000, sector_size=0x4000,
                        page_size=0x1000,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        FlashRegion( start=0x08010000, length=0x10000, sector_size=0x10000,
                        page_size=0x1000,
                        algo=FLASH_ALGO),
        FlashRegion( start=0x08020000, length=0xE0000, sector_size=0x20000,
                        page_size=0x1000,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x40000)
        )

    def __init__(self, session):
        super(STM32F412xG, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32F41x.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1_FZ, DBGMCU.APB1_FZ_VALUE)
        self.write32(DBGMCU.APB2_FZ, DBGMCU.APB2_FZ_VALUE)
