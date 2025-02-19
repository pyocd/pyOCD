# Copyright (c) 2010 - 2023, Nordic Semiconductor ASA All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY, AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import logging
from ...core.memory_map import FlashRegion, RamRegion, MemoryMap
from ...debug.svd.loader import SVDFile
from ..family.target_nRF53 import NRF53
from ...flash.flash import Flash

LOG = logging.getLogger(__name__)

class Flash_NRF5340(Flash):
    def __init__(self, target, flash_algo):
        super(Flash_NRF5340, self).__init__(target, flash_algo)

    def prepare_target(self):
        self.target.other_core.reset_and_halt()


FLASH_ALGO_APP = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00,
    0xf8d24a02, 0x2b013400, 0x4770d1fb, 0x50039000, 0x47702000, 0x47702000, 0x2302b508, 0x20004906,
    0x3504f8c1, 0xffecf7ff, 0xf8c12301, 0xf7ff350c, 0xf8c1ffe7, 0xbd080504, 0x50039000, 0x2302b508,
    0xf8c14906, 0xf7ff3504, 0xf04fffdb, 0x600333ff, 0xf7ff2000, 0xf8c1ffd5, 0xbd080504, 0x50039000,
    0x2301b538, 0x4d0c4614, 0x0103f021, 0x3504f8c5, 0xffc6f7ff, 0x44214622, 0x428a1b00, 0x2000d105,
    0xffbef7ff, 0x0504f8c5, 0x4613bd38, 0x4b04f853, 0x461a5014, 0xbf00e7f1, 0x50039000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000015,
    'pc_unInit': 0x20000019,
    'pc_program_page': 0x20000065,
    'pc_erase_sector': 0x20000041,
    'pc_eraseAll': 0x2000001d,

    'static_base' : 0x20000000 + 0x00000004 + 0x000000a0,
    'begin_stack' : 0x20000300,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x1000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20002000],   # Enable double buffering
    'min_program_length' : 0x1000,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x100000),
        (0xff8000, 0x1000),
    )
}

FLASH_ALGO_NET = {
    'load_address' : 0x21000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00,
    0xf8d24a02, 0x2b013400, 0x4770d1fb, 0x41080000, 0x47702000, 0x47702000, 0x2302b508, 0x20004906,
    0x3504f8c1, 0xffecf7ff, 0xf8c12301, 0xf7ff350c, 0xf8c1ffe7, 0xbd080504, 0x41080000, 0x2302b508,
    0xf8c14906, 0xf7ff3504, 0xf04fffdb, 0x600333ff, 0xf7ff2000, 0xf8c1ffd5, 0xbd080504, 0x41080000,
    0x2301b538, 0x4d0c4614, 0x0103f021, 0x3504f8c5, 0xffc6f7ff, 0x44214622, 0x428a1b00, 0x2000d105,
    0xffbef7ff, 0x0504f8c5, 0x4613bd38, 0x4b04f853, 0x461a5014, 0xbf00e7f1, 0x41080000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x21000015,
    'pc_unInit': 0x21000019,
    'pc_program_page': 0x21000065,
    'pc_erase_sector': 0x21000041,
    'pc_eraseAll': 0x2100001d,

    'static_base' : 0x21000000 + 0x00000004 + 0x000000a0,
    'begin_stack' : 0x21000300,
    'begin_data' : 0x21000000 + 0x1000,
    'page_size' : 0x800,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x21001000, 0x21001800],   # Enable double buffering
    'min_program_length' : 0x800,

    # Flash information
    'flash_start': 0x1000000,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x1000000, 0x40000),
        (0x1ff8000, 0x1000),
    )
}


class NRF53XX(NRF53):
    MEMORY_MAP = MemoryMap(
        FlashRegion(
            start=0x0,
            length=0x200000,
            blocksize=0x1000,
            algo=FLASH_ALGO_APP,
            flash_class=Flash_NRF5340,
            core_index=0,
        ),
        FlashRegion(
            start=0x01000000,
            length=0x00040000,
            blocksize=0x800,
            algo=FLASH_ALGO_NET,
            flash_class=Flash_NRF5340,
            core_index=1,
        ),
        FlashRegion(
            start=0x00ff8000,
            length=0x1000,
            blocksize=4,
            is_erasable=False,
            algo=FLASH_ALGO_APP,
            flash_class=Flash_NRF5340,
            core_index=0,
        ),
        FlashRegion(
            start=0x01ff8000,
            length=0x1000,
            blocksize=4,
            is_erasable=False,
            algo=FLASH_ALGO_NET,
            flash_class=Flash_NRF5340,
            core_index=1,
        ),
        RamRegion(start=0x20000000, length=0x80000),
    )

    def __init__(self, session):
        super(NRF53XX, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("nrf5340_application.svd") # TODO
