# pyOCD debugger
# Copyright (c) 2021 NXP
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
    'load_address' : 0x10000200,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x47700a80, 0x48474948, 0x60084449, 0x22004847, 0x21016102, 0x61426141, 0x61816141, 0x20024943,
    0x70083940, 0x47704610, 0x47702000, 0x4c40b5f8, 0x444c2032, 0x25004621, 0xc461263f, 0x483c3114,
    0x44484f3c, 0x91003c0c, 0x696047b8, 0xd10d2800, 0xc4612034, 0x44484834, 0x60206800, 0x3c0c4834,
    0x99004448, 0x696047b8, 0xd0002800, 0xbdf82001, 0x4d2fb5f8, 0x20320a84, 0xc511444d, 0x310c4629,
    0x4e2c482b, 0x460f602c, 0x3d084448, 0x696847b0, 0xd10e2800, 0xc5112034, 0x602c4823, 0x68004448,
    0x48236068, 0x44484639, 0x47b03d08, 0x28006968, 0x2001d000, 0xb5f8bdf8, 0x00064614, 0xcc03d10e,
    0x18406862, 0x18896821, 0x68a11840, 0x68e11840, 0x69211840, 0x42401840, 0x3c086160, 0x0ab04d14,
    0x2132444d, 0x60296068, 0x462960a8, 0x4f113114, 0x91004628, 0x696847b8, 0xd1112800, 0x60ac2033,
    0x20ffc541, 0x60683001, 0x44484807, 0x60a86800, 0x3d084807, 0x99004448, 0x696847b8, 0xd0002800,
    0xbdf82001, 0x00002ee0, 0x00000004, 0x40048040, 0x00000008, 0x0f001ff1, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x10000225,
    'pc_unInit': 0x10000249,
    'pc_program_page': 0x100002d7,
    'pc_erase_sector': 0x10000291,
    'pc_eraseAll': 0x1000024d,

    'begin_data' : 0x10000380,
    'begin_stack' : 0x10000200,
    'static_base' : 0x10000358,

    # 'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x10001000, 0x10001100],   # Enable double buffering
    'min_program_length' : 0x100,
}

class LPC845(CoreSightTarget):

    VENDOR = "NXP"

    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0,           length=0x10000,       blocksize=0x400, page_size=0x100, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x10000000,  length=0x3fe0)
        )

    def __init__(self, session):
        super(LPC845, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("LPC845.xml")

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        super(LPC845, self).reset_and_halt(reset_type)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.write_memory(0x40048000, 0x2)
            sp = self.read_memory(0x0)
            pc = self.read_memory(0x4)
            self.write_core_register('sp', sp)
            self.write_core_register('pc', pc)
