# pyOCD debugger
# Copyright (c) 2023 microcai
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

# pyOCD debugger
# Copyright (c) 2024 PyOCD Authors
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

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x4770ba40, 0x4770ba40, 0x4770bac0, 0x4770bac0, 0x211ab508, 0x90004348, 0xd0012800, 0xe7fa1e40,
    0x493bbd08, 0x22016188, 0xe00003d2, 0x69cb61ca, 0xd5fb041b, 0x0a404770, 0x47704770, 0xb5104770,
    0x48344a35, 0x48326010, 0x69813840, 0x01090909, 0x61811cc9, 0x24016b10, 0x43a00464, 0x200a6310,
    0xffd6f7ff, 0x43206b10, 0x200a6310, 0xffd0f7ff, 0x21036b10, 0x43880289, 0x184011a1, 0x6b106310,
    0xdafc2800, 0xf7ff2032, 0x6a50ffc3, 0x00800880, 0x62501c80, 0xf7ff2032, 0x2000ffbb, 0xbd106010,
    0xb672b500, 0x481e491d, 0x491e6141, 0xf7ff6141, 0x2000ffc6, 0x2000bd00, 0x48154770, 0x3840b510,
    0xf8acf000, 0x49154816, 0x49166141, 0x20006141, 0x01c0bd10, 0x480e0c01, 0x3840b510, 0xf895f000,
    0xbd102000, 0x1cc9b5f8, 0x4f09088c, 0x461500a4, 0x3f404606, 0x4632e008, 0x46382102, 0xf000682b,
    0x1f24f831, 0x1d361d2d, 0xd1f42c00, 0xbdf82000, 0x40020280, 0x3fac87e4, 0x40020000, 0x0000aaaa,
    0x40020180, 0x0000dddd, 0x04122201, 0x68012901, 0x4391d002, 0x47706001, 0xe7fb4311, 0x47706181,
    0x6181496c, 0xe7ef2100, 0xd0012900, 0xe0002100, 0x62014969, 0x29004770, 0x2100d001, 0x4967e000,
    0x47706241, 0x4604b510, 0x21004865, 0x46204002, 0xfff1f7ff, 0x612360e2, 0x064068a0, 0xbd10d5fc,
    0x4604b510, 0x2100485e, 0x46204002, 0xffdcf7ff, 0x07402001, 0x60e01810, 0x68a06123, 0xd5fc0640,
    0x2101bd10, 0x428a0409, 0x2102d201, 0x2102e7da, 0xb500e7e6, 0x4602460b, 0xd20f2980, 0x07c06890,
    0x2100d0fc, 0xf7ff4610, 0x0658ffc6, 0x0e402101, 0x18400789, 0x68906150, 0xd0fc07c0, 0xb500bd00,
    0x4602460b, 0xd20f2909, 0x07c06890, 0x2100d0fc, 0xf7ff4610, 0x0658ffa9, 0x0e402103, 0x18400749,
    0x68906150, 0xd0fc07c0, 0x2980bd00, 0xe7d0d200, 0xd2022989, 0xb2893980, 0x4770e7e1, 0x4602b500,
    0x07806890, 0x2100d5fc, 0xf7ff4610, 0x2001ff94, 0x615007c0, 0x07806890, 0xbd00d5fc, 0x42994b31,
    0x425bd305, 0x4b3018c9, 0x1d1b4019, 0x628118c9, 0x684162c2, 0x43114a2d, 0x68816041, 0xd5fc0549,
    0x47706b00, 0x4926b530, 0x400a9c03, 0x06496881, 0x6801d5fc, 0x02ad2501, 0x60014329, 0x628360c2,
    0x684162c4, 0x43114a21, 0x68816041, 0xd5fc0549, 0x43a96801, 0xbd306001, 0x491bb530, 0x400a9c03,
    0x06496881, 0x6801d5fc, 0x02ad2501, 0x60014329, 0x04eab291, 0x60c11889, 0x62c46283, 0x4a136841,
    0x60414311, 0x05496881, 0x6801d5fc, 0x600143a9, 0x6801bd30, 0x03122201, 0x60014311, 0x68014770,
    0x03122201, 0x60014391, 0x6b004770, 0x6c004770, 0x00004770, 0x00004041, 0x20150931, 0x20170230,
    0x0000fffc, 0x1ff00000, 0x1ffffffc, 0x04000400, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x200000a5,
    'pc_unInit': 0x200000bb,
    'pc_program_page': 0x200000e9,
    'pc_erase_sector': 0x200000d7,
    'pc_eraseAll': 0x200000bf,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000310,
    'begin_stack' : 0x20002000,
    'end_stack' : 0x20001720,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000320,
        0x20000b20
    ],
    'min_program_length' : 0x200,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x310,
    'rw_start': 0x314,
    'rw_size': 0x4,
    'zi_start': 0x318,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

class EG6832(CoreSightTarget):

    VENDOR = "EG6832"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0000_0000, length=0x10000,
                    blocksize=0x400,
                    is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x2000_0000,  length=0x1000)
        )

    def __init__(self, session):
        super(EG6832, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("EG32M0x.svd")
