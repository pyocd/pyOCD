# pyOCD debugger
# Copyright (c) 2026 Kai
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
from ...core.memory_map import FlashRegion, MemoryMap, RamRegion


class DBGMCU:
    APB = 0x4000580C
    APB_VALUE = 0x30000


FLASH_ALGO = {
    'load_address': 0x20000000,
    'instructions': [
        0xe7fdbe00,
        0xd3022820, 0x1d000940, 0x28104770, 0x0900d302, 0x47701cc0, 0x47700880, 0x6881487d, 0x04522201,
        0x60814311, 0x47702000, 0x4d7ab578, 0x487a4978, 0x60089500, 0x60084879, 0x220c68c8, 0x60c84310,
        0x240168c8, 0x60c84320, 0x040a4875, 0x4a756010, 0xe0044b75, 0x9800601a, 0x96001e46, 0x6888d309,
        0xd4f70740, 0xe0069500, 0x9800601a, 0x90001e40, 0x2001d201, 0x6888bd78, 0xd0f507c0, 0x43206888,
        0x20006088, 0xb578bd78, 0x06c9211f, 0x4d614a67, 0x95001841, 0xd3014291, 0xbd782000, 0x495e4a5c,
        0x495e6011, 0x68d16011, 0x4399230c, 0x68d160d1, 0x43192301, 0x495a60d1, 0x495a6001, 0xe0044c5a,
        0x98006021, 0x96001e46, 0x6890d309, 0xd4f70740, 0xe0069500, 0x98006021, 0x95001e45, 0x2001d201,
        0x6890bd78, 0xd0f507c0, 0x43186890, 0xe7d36090, 0x4b48b5f8, 0x231f9300, 0x06db0889, 0x00894c4b,
        0x4d4818c3, 0x4f424e48, 0xd20342a3, 0xca08e037, 0x1f09c008, 0xd1fa2900, 0x4b3fe033, 0x4b3f603b,
        0x68fb603b, 0x43232402, 0x681360fb, 0x4b396003, 0xe0049300, 0x9b006035, 0x94001e5c, 0x68bbd313,
        0xd4f7075b, 0x069b68bb, 0xd0040f5b, 0x213868b8, 0x60b84308, 0x4b2fe007, 0xe0069300, 0x9b006035,
        0x94001e5c, 0x2001d201, 0x68bbbdf8, 0xd5f5079b, 0x240268bb, 0x60bb4323, 0x1f091d00, 0x29001d12,
        0x2000d1cb, 0xb538bdf8, 0x49214c22, 0x6a089400, 0x05c04a25, 0x4826d405, 0x20066010, 0x48256050,
        0x6a086090, 0x28aab2c0, 0x4823d022, 0x48236048, 0x4b1c6048, 0x6013e004, 0x1e459800, 0xd3109500,
        0x03406888, 0x481ed5f7, 0x6a886288, 0x062d2501, 0x62884328, 0xe0069400, 0x98006013, 0x94001e44,
        0x2001d201, 0x6a88bd38, 0xd4f501c0, 0x60c84815, 0x22016888, 0x43100492, 0x48076088, 0x48076008,
        0x68886008, 0x43102238, 0x20006088, 0x0000bd38, 0x40020800, 0x0007a120, 0x96969696, 0x3c3c3c3c,
        0x0000a5a5, 0x0000aaaa, 0x40002400, 0x00020001, 0x00005555, 0x00000fff, 0xaaaabbbb, 0x44556677,
        0x00ff83aa, 0xa5a58000, 0x00000000
    ],
    'pc_init': 0x2000018b,
    'pc_unInit': 0x2000001d,
    'pc_program_page': 0x200000f5,
    'pc_erase_sector': 0x2000008b,
    'pc_eraseAll': 0x2000002d,
    'static_base': 0x20000000 + 0x00000004 + 0x00000248,
    'begin_stack': 0x20001650,
    'end_stack': 0x20000650,
    'begin_data': 0x20000000 + 0x1000,
    'page_size': 0x200,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000250, 0x20000450],
    'min_program_length': 0x200,
    'ro_start': 0x4,
    'ro_size': 0x248,
    'rw_start': 0x24c,
    'rw_size': 0x4,
    'zi_start': 0x250,
    'zi_size': 0x0,
    'flash_start': 0x8000000,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x200),
    ),
}

OPT_ALGO = {
    'load_address': 0x20000000,
    'instructions': [
        0xe7fdbe00,
        0x4828b518, 0x90004b28, 0x4c286a18, 0xd40505c0, 0x60204827, 0x60602006, 0x60a04826, 0x60584826,
        0x60584826, 0xe0064926, 0x98006021, 0x92001e42, 0x2001d201, 0x6898bd18, 0xd5f50340, 0xbd182000,
        0x68814819, 0x04922201, 0x60814311, 0x47702000, 0x47702000, 0x47702000, 0x4812b538, 0x79109000,
        0x04057893, 0x78140718, 0x7a110d00, 0x7a924305, 0x4b0d4325, 0x43080210, 0x62d8629d, 0x21016a98,
        0x43080609, 0x490e6298, 0xe0064c08, 0x98006021, 0x92001e42, 0x2001d201, 0x6a98bd38, 0xd4f501c0,
        0xbd382000, 0x0007a120, 0x40020800, 0x40002400, 0x00005555, 0x00000fff, 0xaaaabbbb, 0x44556677,
        0x0000aaaa, 0x00000000
    ],
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000045,
    'pc_program_page': 0x2000005d,
    'pc_erase_sector': 0x20000059,
    'pc_eraseAll': 0x20000055,
    'static_base': 0x20000000 + 0x00000004 + 0x000000c4,
    'begin_stack': 0x200010e8,
    'end_stack': 0x200000e8,
    'begin_data': 0x20000000 + 0x1000,
    'page_size': 0xc,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x200000d0, 0x200000dc],
    'min_program_length': 0xc,
    'ro_start': 0x4,
    'ro_size': 0xc4,
    'rw_start': 0xc8,
    'rw_size': 0x4,
    'zi_start': 0xcc,
    'zi_size': 0x0,
    'flash_start': 0x1fff0000,
    'flash_size': 0xc,
    'sector_sizes': (
        (0x0, 0xc),
    ),
}


class G32R430xB(CoreSightTarget):
    VENDOR = "Geehy"

    MEMORY_MAP = MemoryMap(
        FlashRegion(
            start=0x08000000,
            length=0x20000,
            sector_size=0x200,
            page_size=0x200,
            is_boot_memory=True,
            algo=FLASH_ALGO,
        ),
        FlashRegion(
            start=0x1FFF0000,
            length=0x10,
            sector_size=0x10,
            page_size=0x10,
            algo=OPT_ALGO,
        ),
        RamRegion(start=0x20000000, length=0x40000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def post_connect_hook(self):
        self.write32(DBGMCU.APB, DBGMCU.APB_VALUE)
