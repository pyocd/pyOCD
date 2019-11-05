# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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

from ...flash.flash import Flash
from ...core.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile


class DBGMCU:
    STCTL = 0x40015004
    STCTL_VALUE = 0x9

FLASH_ALGO = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4807b5f8, 0x20009003, 0x466a43c0, 0x60112101, 0x20056050, 0xab032210, 0xf876f000, 0xbd80b004,
    0x00001234, 0x4602b5f8, 0x90034806, 0x43c02000, 0x2101466b, 0x60586019, 0xab032004, 0xf864f000,
    0xbd80b004, 0x00001234, 0x49064805, 0x49066001, 0x21016001, 0x89820209, 0x8182430a, 0x47702000,
    0x40000800, 0xffff0123, 0xffff3210, 0xb085b5f0, 0x90034613, 0x43c22000, 0x22039204, 0x1a8e400a,
    0xe003199d, 0xac045c2f, 0x1c405427, 0xd1f94282, 0x2a000888, 0x2500d00f, 0xc1214669, 0x46292002,
    0x46229c03, 0xf830f000, 0x21014668, 0x1932c022, 0xab04200f, 0x2100e005, 0xc203466a, 0x21012002,
    0xf0009a03, 0xb005f821, 0x0000bdf0, 0x88084906, 0x40024a06, 0x2001800a, 0x20006008, 0x390c6008,
    0x600a43c2, 0x46c04770, 0x4000080c, 0x0000feff, 0x2300b5b0, 0x5cc4e004, 0x42a55cd5, 0x1c5bd102,
    0xd3f8428b, 0xbdb018c0, 0x9301b5fc, 0x4c219100, 0xd00e280f, 0x25018821, 0x80214329, 0x26708821,
    0x074043b1, 0x18080e40, 0x02288020, 0x43018821, 0x9d088021, 0x23009f07, 0xe016461e, 0x990100b0,
    0x60105808, 0x1c404814, 0x6861d013, 0xd5fa05c9, 0xd0032d00, 0x42a86810, 0xe018d005, 0x200f6861,
    0x28004008, 0x1c76d106, 0x42be1d12, 0x4618d3e6, 0x201fe000, 0x29019900, 0x8821d107, 0x43912270,
    0x88218021, 0x43912201, 0xb0028021, 0x203fbdf0, 0x46c0e7f0, 0x4000080c, 0xfffcf2bf, 0x00000000
    ],

    'pc_init': 0x20000069,
    'pc_unInit': 0x200000ed,
    'pc_program_page': 0x2000008d,
    'pc_erase_sector': 0x20000045,
    'pc_eraseAll': 0x20000021,

    'static_base' : 0x20000000 + 0x00000020 + 0x0000019c,
    'begin_stack' : 0x20000400,
    'begin_data' : 0x20000000 + 0xA00,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20000A00, 0x20000C00],   # Enable double buffering
    'min_program_length' : 0x200,
  }


class HC32F120x6TA(CoreSightTarget):

    VENDOR = "HDSC"

    memoryMap = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, transport):
        super(HC32F120x6TA, self).__init__(transport, self.memoryMap)
        self._svd_location = SVDFile.from_builtin("HC32F120.svd")

    def create_init_sequence(self):
        seq = super(HC32F120x6TA, self).create_init_sequence()

        seq.insert_after('create_cores',
            ('setup_dbgmcu', self.setup_dbgmcu)
            )

        return seq

    def setup_dbgmcu(self):
        self.write32(DBGMCU.STCTL, DBGMCU.STCTL_VALUE)


class HC32F120x8TA(CoreSightTarget):

    VENDOR = "HDSC"

    memoryMap = MemoryMap(
        FlashRegion( start=0x00000000, length=0x10000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, transport):
        super(HC32F120x8TA, self).__init__(transport, self.memoryMap)
        self._svd_location = SVDFile.from_builtin("HC32F120.svd")

    def create_init_sequence(self):
        seq = super(HC32F120x8TA, self).create_init_sequence()

        seq.insert_after('create_cores',
            ('setup_dbgmcu', self.setup_dbgmcu)
            )

        return seq

    def setup_dbgmcu(self):
        self.write32(DBGMCU.STCTL, DBGMCU.STCTL_VALUE)


class HC32M120(CoreSightTarget):

    VENDOR = "HDSC"

    memoryMap = MemoryMap(
        FlashRegion( start=0x00000000, length=0x8000, sector_size=0x200,
                        is_boot_memory=True,
                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x1000)
        )

    def __init__(self, transport):
        super(HC32M120, self).__init__(transport, self.memoryMap)
        self._svd_location = SVDFile.from_builtin("HC32M120.svd")

    def create_init_sequence(self):
        seq = super(HC32M120, self).create_init_sequence()

        seq.insert_after('create_cores',
            ('setup_dbgmcu', self.setup_dbgmcu)
            )

        return seq

    def setup_dbgmcu(self):
        self.write32(DBGMCU.STCTL, DBGMCU.STCTL_VALUE)
