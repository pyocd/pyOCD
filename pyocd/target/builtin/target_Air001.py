# pyOCD debugger
# Copyright (c) 2023 AirM2M
# Copyright (c) 2023 yekai
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

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x6842488d, 0x4b8d2107, 0x400a0349, 0x601a444b, 0x438a6842, 0x03c92101, 0x60411851, 0x4a886841,
    0x69120b49, 0x04d20349, 0x43110cd2, 0x68016041, 0xd5fc0549, 0x30404882, 0xb2ca6ac1, 0x600a4981,
    0x04126ac2, 0x610a0e12, 0x01d26ac2, 0x604a0dd2, 0xb2d26b02, 0x6b02608a, 0x0d520152, 0x6b4260ca,
    0x0bd203d2, 0x6b82614a, 0x0bd203d2, 0x6bc2618a, 0x61cab292, 0x0c006bc0, 0x47706208, 0x4c73b510,
    0x60a04871, 0x60a04872, 0xffbaf7ff, 0x60202000, 0x21016920, 0x61204308, 0x04c06a20, 0x486ed406,
    0x6001496c, 0x60412106, 0x6081496c, 0xbd102000, 0x68424861, 0x03492107, 0x4960438a, 0x68094449,
    0x6042430a, 0x035b2301, 0x495d1aca, 0x1ad2d018, 0x1ad2d011, 0x429ad00a, 0xd1036842, 0x03520b52,
    0xe0116909, 0x03520b52, 0xe00d6809, 0x68c96842, 0x03520b52, 0x6842e008, 0x0b526889, 0xe0030352,
    0x68496842, 0x03520b52, 0x0cc904c9, 0x6042430a, 0x05496801, 0x4770d5fc, 0xf7ffb500, 0x484bffc9,
    0x04826941, 0x61414311, 0xbd002000, 0x4a47b570, 0x23016910, 0x61104318, 0x24046950, 0x61504320,
    0x061d6950, 0x61504328, 0x06d920ff, 0xf3bf6008, 0x48438f4f, 0xe0004940, 0x69166008, 0xd4fb03f6,
    0x43a06950, 0x69506150, 0x615043a8, 0x07c06910, 0x2000d001, 0x6910bd70, 0x61104318, 0xbd702001,
    0x4932b530, 0x2301690a, 0x610a431a, 0x14cc694a, 0x614a4322, 0x061d694a, 0x614a432a, 0x600222ff,
    0x8f4ff3bf, 0x4a2c482e, 0x6010e000, 0x03db690b, 0x6948d4fb, 0x614843a0, 0x43a86948, 0x20006148,
    0x2001bd30, 0xb5f04770, 0x317f4d20, 0x692b09c9, 0x240101c9, 0x612b4323, 0xe0280626, 0x2401696b,
    0x616b4323, 0x4333696b, 0x2300616b, 0x5917009c, 0x2b1e5107, 0x696cd104, 0x04ff2701, 0x616c433c,
    0xb2db1c5b, 0xd3f12b20, 0x8f4ff3bf, 0x4c124b14, 0x6023e000, 0x03ff692f, 0x696bd4fb, 0x005b085b,
    0x696b616b, 0x616b43b3, 0x39803080, 0x29003280, 0x2000d1d4, 0x0000bdf0, 0x40021000, 0x00000004,
    0x1fff0f00, 0x40022100, 0x45670123, 0x40022000, 0xcdef89ab, 0x00005555, 0x40003000, 0x00000fff,
    0x0000aaaa, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000081,
    'pc_unInit': 0x2000011d,
    'pc_program_page': 0x200001cb,
    'pc_erase_sector': 0x20000185,
    'pc_eraseAll': 0x20000131,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000264,
    'begin_stack' : 0x20001000,
    'end_stack' : 0x20000370,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x80,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000270,
        0x200002f0
    ],
    'min_program_length' : 0x80,
}

class Air001(CoreSightTarget):

    VENDOR = "AirM2M"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x0800_0000, length=0x8000, 
                    page_size=0x80, sector_size=0x1000, 
                    is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x2000_0000,  length=0x1000)
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("AIR001.svd")
