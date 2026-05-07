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

FLASH_ALGO = {
    'load_address': 0x20000000,
    'instructions': [
        0xe7fdbe00,
        0x69c8494d, 0xd1fc07c0, 0x4a4c484d, 0x68426002, 0x431a2301, 0x68426042, 0xd5fc0792, 0x60832300,
        0x07926882, 0x60c3d4fc, 0x62436103, 0x62c36283, 0x22016303, 0x60020412, 0x60024a42, 0x20084a42,
        0x48426210, 0x15506008, 0x69c86148, 0x431022e0, 0x200061c8, 0x48384770, 0x60416841, 0x60012100,
        0x47704608, 0x493a4834, 0x69416041, 0x00890889, 0x69416141, 0x43112202, 0x49326141, 0x60112200,
        0x07c969c1, 0x69c1d1fc, 0xd5fc06c9, 0x221069c1, 0x61c14311, 0x47702000, 0x69ca4927, 0xd1fc07d2,
        0x604a4a2b, 0x0892694a, 0x614a0092, 0x2301694a, 0x614a431a, 0x60024a23, 0x07c069c8, 0x69c8d1fc,
        0xd5fc06c0, 0x221069c8, 0x61c84310, 0x47702000, 0x4c19b530, 0x07db69e3, 0x4b1dd1fc, 0x69636063,
        0x009b089b, 0x69636163, 0x432b2503, 0x088b6163, 0x2510009b, 0x6811e01b, 0x69e16001, 0xd1fc07c9,
        0x060969e1, 0xd0050f49, 0x21e069e0, 0x61e04308, 0xbd302001, 0x06c969e1, 0x2100d5fc, 0x29641c49,
        0x69e1dbfc, 0x61e14329, 0x1d121d00, 0x2b001f1b, 0x2000d1e1, 0x0000bd30, 0x40020800, 0x000087e4,
        0x40020400, 0x0000a5a5, 0x40020500, 0x3399aa55, 0xabcd6789, 0x00000000,
    ],
    'pc_init': 0x20000005,
    'pc_unInit': 0x2000005b,
    'pc_program_page': 0x200000d5,
    'pc_erase_sector': 0x2000009d,
    'pc_eraseAll': 0x20000069,
    'static_base': 0x20000000 + 0x00000004 + 0x00000154,
    'begin_stack': 0x20001560,
    'end_stack': 0x20000560,
    'page_size': 0x200,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000160, 0x20000360],
    'min_program_length': 0x200,
    'ro_start': 0x4,
    'ro_size': 0x154,
    'rw_start': 0x158,
    'rw_size': 0x4,
    'zi_start': 0x15c,
    'zi_size': 0x0,
    'flash_start': 0x00000000,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x200),
    ),
}


class G32M3101x8(CoreSightTarget):
    """G32M3101 64 KB flash variant (e.g. G32M3101G8/K8/E8)."""

    VENDOR = "Geehy"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x00000000, length=0x10000, blocksize=0x200, page_size=0x200,
            is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(start=0x20000000, length=0x2000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
