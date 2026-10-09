# Copyright (c) 2025 StarSphere. All rights reserved.
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

from ...core.memory_map import FlashRegion, RamRegion, MemoryMap
from ...debug.svd.loader import SVDFile
from ..family.target_nRF54L import NRF54L

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
        0xe7fdbe00,
        0xf8d24a02, 0x07db3400, 0x4770d5fb, 0x5004e000, 0xf7ffb508, 0x2000fff5, 0x2000bd08, 0x00004770,
        0x49072001, 0xf8c1b508, 0xf7ff0500, 0xf8c1ffe9, 0x20000540, 0xffe4f7ff, 0x0500f8c1, 0xbf00bd08,
        0x5004e000, 0xf242b508, 0x49080301, 0x3500f8c1, 0xffd6f7ff, 0x33fff04f, 0x23016003, 0x608b2000,
        0xffcef7ff, 0x0500f8c1, 0xbf00bd08, 0x5004e000, 0xf242b538, 0x46140301, 0xf0214d0c, 0xf8c50103,
        0xf7ff3500, 0x4622ffbd, 0x1b004421, 0xeb02428a, 0xd1070300, 0x20002301, 0xf7ff60ab, 0xf8c5ffb1,
        0xbd380500, 0x4b04f852, 0xe7ef601c, 0x5004e000,
    ],

    # Relative function addresses
    'pc_init': 0x20000015,
    'pc_unInit': 0x2000001f,
    'pc_program_page': 0x20000075,
    'pc_erase_sector': 0x20000049,
    'pc_eraseAll': 0x20000025,

    'static_base' : 0x200000B8,
    'begin_stack' : 0x20003000,
    'page_size' : 0x1000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20000100,0x20001100],   # 4 KiB double buffers, 128-bit line aligned
    'min_program_length' : 0x4,

    # Relative region addresses and sizes
    'ro_start': 0xb4,
    'ro_size': 0x0,
    'rw_start': 0xb4,
    'rw_size': 0x0,
    'zi_start': 0xb4,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x1fd000,
    'sector_sizes': (
        (0x0, 0x1fd000),
        (0xffd000, 0x1000),
    )
}

class NRF54LM20A(NRF54L):
    MEMORY_MAP = MemoryMap(
        FlashRegion(
            start=0x0,
            length=0x1FD000,  # 2 MB Flash
            blocksize=0x1000,
            is_boot_memory=True,
            algo=FLASH_ALGO,
        ),
        # User Information Configuration Registers (UICR) as a flash region
        FlashRegion(
            start=0x00FFD000,
            length=0x1000,
            blocksize=0x4,
            is_testable=False,
            is_erasable=False,
            algo=FLASH_ALGO,
        ),
        RamRegion(start=0x20000000, length=0x80000),  # 512 KB RAM
    )

    def __init__(self, session):
        super(NRF54LM20A, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("nrf54lm20a.svd")

    def check_flash_security(self):
        """Override to relax ID check for nRF54LM20A."""
        import logging
        LOG = logging.getLogger(__name__)

        target_id = self.dp.read_dp(0x24)

        if target_id & 0xFFF != 0x289:
            LOG.error("This doesn't look like a Nordic Semiconductor device!")

        if target_id & 0xF0000 != 0x90000:
            LOG.error("This doesn't look like an nRF54LM20A device!")

        if not self.ap_is_enabled():
            if self.session.options.get('auto_unlock'):
                LOG.warning("%s APPROTECT enabled: will try to unlock via mass erase", self.part_number)
                self.mass_erase()
        else:
            LOG.warning("%s is not in a secure state", self.part_number)
