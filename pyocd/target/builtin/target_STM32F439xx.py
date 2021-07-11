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

# Chip erase takes a really long time.
CHIP_ERASE_WEIGHT = 15.0

class DBGMCU:
    CR = 0xE0042004
    CR_VALUE = 0x7 # DBG_STANDBY | DBG_STOP | DBG_SLEEP

    APB1_FZ = 0xE0042008
    APB1_FZ_VALUE = 0x06e01dff

    APB2_FZ = 0xE004200C
    APB2_FZ_VALUE = 0x00070003


FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x03004601, 0x28200e00, 0x0940d302, 0xe0051d00, 0xd3022810, 0x1cc00900, 0x0880e000, 0xd50102c9,
    0x43082110, 0x48464770, 0x60414944, 0x60414945, 0x60012100, 0x22f068c1, 0x60c14311, 0x06806940,
    0x4842d406, 0x60014940, 0x60412106, 0x60814940, 0x47702000, 0x6901483a, 0x43110542, 0x20006101,
    0xb5304770, 0x69014836, 0x43212404, 0x69016101, 0x43290365, 0x69016101, 0x431103a2, 0x49356101,
    0xe0004a32, 0x68c36011, 0xd4fb03db, 0x43a16901, 0x69016101, 0x610143a9, 0xbd302000, 0xf7ffb530,
    0x4927ffaf, 0x23f068ca, 0x60ca431a, 0x610c2402, 0x06c0690a, 0x43020e00, 0x6908610a, 0x431003e2,
    0x48246108, 0xe0004a21, 0x68cd6010, 0xd4fb03ed, 0x43a06908, 0x68c86108, 0x0f000600, 0x68c8d003,
    0x60c84318, 0xbd302001, 0x4d15b570, 0x08891cc9, 0x008968eb, 0x433326f0, 0x230060eb, 0x4b16612b,
    0x692ce017, 0x612c431c, 0x60046814, 0x03e468ec, 0x692cd4fc, 0x00640864, 0x68ec612c, 0x0f240624,
    0x68e8d004, 0x60e84330, 0xbd702001, 0x1d121d00, 0x29001f09, 0x2000d1e5, 0x0000bd70, 0x45670123,
    0x40023c00, 0xcdef89ab, 0x00005555, 0x40003000, 0x00000fff, 0x0000aaaa, 0x00000201, 0x00000000
    ],

    'pc_init' : 0x20000047,
    'pc_unInit': 0x20000075,
    'pc_program_page': 0x20000109,
    'pc_erase_sector': 0x200000bd,
    'pc_eraseAll' : 0x20000083,

    'static_base' : 0x20000171,
    'begin_stack' : 0x20000000 + 0x00000800,
    'begin_data' : 0x20001000,
    'page_buffers' : [0x20001000, 0x20002000],
    'min_program_length' : 1,
    'analyzer_supported' : True,
    'analyzer_address' : 0x20002000
  }

class STM32F439xG(CoreSightTarget):

    VENDOR = "STMicroelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x08000000, length=0x10000,  sector_size=0x4000,
                                                        page_size=0x1000, 
                                                        is_boot_memory=True,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08010000, length=0x10000,  sector_size=0x10000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08020000, length=0x60000,  sector_size=0x20000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x40000)
        )

    def __init__(self, session):
        super(STM32F439xG, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32F439x.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1_FZ, DBGMCU.APB1_FZ_VALUE)
        self.write32(DBGMCU.APB2_FZ, DBGMCU.APB2_FZ_VALUE)

class STM32F439xI(CoreSightTarget):

    VENDOR = "STMicroelectronics"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x08000000, length=0x10000,  sector_size=0x4000,
                                                        page_size=0x1000,
                                                        is_boot_memory=True,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08010000, length=0x10000,  sector_size=0x10000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08020000, length=0xe0000,  sector_size=0x20000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08100000, length=0x10000,  sector_size=0x4000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08110000, length=0x10000,  sector_size=0x10000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x08120000, length=0xe0000,  sector_size=0x20000,
                                                        page_size=0x1000,
                                                        erase_all_weight=CHIP_ERASE_WEIGHT,
                                                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x30000)
        )

    def __init__(self, session):
        super(STM32F439xI, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("STM32F439x.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.CR, DBGMCU.CR_VALUE)
        self.write32(DBGMCU.APB1_FZ, DBGMCU.APB1_FZ_VALUE)
        self.write32(DBGMCU.APB2_FZ, DBGMCU.APB2_FZ_VALUE)

