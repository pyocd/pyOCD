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
    0x68134a02, 0xd1fc2b01, 0x46c04770, 0x5004e400, 0x47702000, 0x47702000, 0x2501b570, 0x60254c05,
    0xffeef7ff, 0x601d4b04, 0xffeaf7ff, 0x60202000, 0x46c0bd70, 0x5004e500, 0x5004e540, 0xb5702301,
    0x00044d06, 0xf7ff602b, 0x2301ffdb, 0x6023425b, 0xffd6f7ff, 0x60282000, 0x46c0bd70, 0x5004e500,
    0x2301b5f8, 0x000f0014, 0x00064d0a, 0xf7ff602b, 0x0022ffc7, 0x00bf08bf, 0x1b3619e7, 0x42ba1993,
    0xf7ffd104, 0x2000ffbd, 0xbdf86028, 0x6019ca02, 0x46c0e7f4, 0x5004e500, 0x00000000, 0x00000000
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
    'page_size' : 0x4,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x200000b0,0x200000b4],   # Enable double buffering
    'min_program_length' : 0x4,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0xa0,
    'rw_start': 0xa4,
    'rw_size': 0x0,
    'zi_start': 0xa4,
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