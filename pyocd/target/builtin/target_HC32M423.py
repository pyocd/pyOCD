# pyOCD debugger
# Copyright (c) 2021 Huada Semiconductor Corporation
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
    STPCTL = 0xE0042020
    STPCTL_VALUE = 0x3FFB

    TRACECTL = 0xE0042024
    TRACECTL_VALUE = 0x0


FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4770ba40, 0x4770ba40, 0x4770bac0, 0x4770bac0, 0xf000b510, 0x2000f833, 0xb510bd10, 0xf836f000,
    0xbd102000, 0xb876f000, 0xb898f000, 0xb836f000, 0x4603b5f0, 0xe00c2400, 0x0514f1a4, 0xd2022d03,
    0x1d1b1d12, 0xcb20e004, 0x42b56816, 0x1d12d104, 0xebb41c64, 0xd3ef0f91, 0x2300461d, 0x0103f001,
    0xf815e005, 0x5cd76b01, 0xd10242be, 0x42991c5b, 0xeb00d8f7, 0x44180084, 0x0000bdf0, 0xf2404849,
    0x60011123, 0x2110f243, 0x47706001, 0x20004945, 0x6008310c, 0x1e404943, 0x47706008, 0x4f41b5f8,
    0x23012600, 0x9600370c, 0x683b603b, 0x7398f443, 0xf8df603b, 0xf649c0f0, 0xf10c4540, 0x1d3c0c14,
    0x60036813, 0xe0049600, 0x1c5b9b00, 0x42ab9300, 0x6823d219, 0xd5f706db, 0xf8dce005, 0xf0433000,
    0xf8cc0310, 0x68233000, 0xd4f606db, 0x1f091d00, 0x29041d12, 0x603ed2e4, 0xe0069600, 0x1c409800,
    0x42a89000, 0x2001d301, 0x6820bdf8, 0xd5f505c0, 0xbdf82000, 0xb5304a23, 0x21012000, 0x6011320c,
    0xf4416811, 0x601171a8, 0x60004603, 0x1d114c1e, 0x1c40e004, 0xd30142a0, 0xbd302001, 0x05ed680d,
    0x4818d5f7, 0x680c3014, 0xd50406e4, 0xf0446804, 0x60040410, 0x6013e7f7, 0xbd302000, 0xb5304a11,
    0x23012100, 0x6013320c, 0xf4436813, 0x601373a0, 0x6001460b, 0x1d104c0c, 0x1c49e004, 0xd30142a1,
    0xbd302001, 0x05ed6805, 0x4906d5f7, 0x68043114, 0xd50406e4, 0xf044680c, 0x600c0410, 0x6013e7f7,
    0xbd302000, 0x40010400, 0x00061a80, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000031,
    'pc_unInit': 0x2000003b,
    'pc_program_page': 0x2000004d,
    'pc_erase_sector': 0x20000049,
    'pc_eraseAll': 0x20000045,

    'static_base' : 0x20000000 + 0x00000020 + 0x000001ac,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001200],   # Enable double buffering
    'min_program_length' : 0x200,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}


class HC32M423xA(CoreSightTarget):

    VENDOR = "HDSC"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x20000, page_size=0x200, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x1FFFE000, length=0x4000)
        )

    def __init__(self, session):
        super(HC32M423xA, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("HC32M423.svd")

    def post_connect_hook(self):
        self.write32(DBGMCU.STPCTL, DBGMCU.STPCTL_VALUE)
        self.write32(DBGMCU.TRACECTL, DBGMCU.TRACECTL_VALUE)
