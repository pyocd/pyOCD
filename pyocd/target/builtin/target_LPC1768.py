# pyOCD debugger
# Copyright (c) 2006-2015 Arm Limited
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

import logging
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap, DefaultFlashWeights)
from ...debug.svd.loader import SVDFile

LOG = logging.getLogger(__name__)

LARGE_PAGE_START_ADDR = 0x10000
SMALL_PAGE_SIZE = 0x1000
LARGE_PAGE_SIZE = 0x8000
LARGE_TO_SMALL_RATIO = LARGE_PAGE_SIZE / SMALL_PAGE_SIZE
LARGE_ERASE_SECTOR_WEIGHT = DefaultFlashWeights.ERASE_SECTOR_WEIGHT * LARGE_TO_SMALL_RATIO
LARGE_PROGRAM_PAGE_WEIGHT = DefaultFlashWeights.PROGRAM_PAGE_WEIGHT * LARGE_TO_SMALL_RATIO
WRITE_SIZE = 1024

FLASH_ALGO = { 'load_address' : 0x10000000,
               'instructions' : [
                                0xe00abe00, 0x062d780d, 0x24084068, 0xd3000040, 0x1e644058, 0x1c49d1fa, 0x2a001e52, 0x4770d1f2,
                                0x7803e005, 0x42931c40, 0x2001d001, 0x1e494770, 0x2000d2f7, 0x00004770, 0x28100b00, 0x210ed302,
                                0x00d0eb01, 0x486c4770, 0x7801b510, 0x0102f021, 0x22aa7001, 0x23557302, 0x78017303, 0x0101f021,
                                0x73027001, 0xf8d07303, 0xf0411120, 0xf8c00120, 0xf1a01120, 0xf8d00080, 0x064911a0, 0xf100d5fb,
                                0x24010080, 0x408cf880, 0x0113f04f, 0x73026041, 0x78017303, 0x0101f041, 0x73027001, 0xf1a07303,
                                0xf8d00080, 0x01491088, 0xf100d5fb, 0x2107006d, 0x1097f880, 0x0109f04f, 0x109bf880, 0xf0417cc1,
                                0x74c10102, 0x77c377c2, 0x4c2df800, 0xf64e494b, 0x44492060, 0xf04f6008, 0xbd100000, 0x47702000,
                                0x41f0e92d, 0x20324c46, 0x2500444c, 0xe884271d, 0xf10400a1, 0x4e430114, 0x46204688, 0x696047b0,
                                0x2034b960, 0x00a1e884, 0x4641483c, 0x68004448, 0x462060e0, 0x696047b0, 0xd0002800, 0xe8bd2001,
                                0xe92d81f0, 0xf7ff41f0, 0x4d35ff87, 0x444d4604, 0xe9c52032, 0xf1050400, 0x4e320114, 0x4628460f,
                                0x47b060ac, 0xb9686968, 0xe9c52034, 0x482b0400, 0x444860ac, 0x68004639, 0x462860e8, 0x696847b0,
                                0xd0dc2800, 0xe7da2001, 0x41f0e92d, 0x46140006, 0x4925d11d, 0x02fcf8d4, 0xd03a4288, 0x42884923,
                                0x4923d037, 0xd0344288, 0x4131ea4f, 0xd0304288, 0x0100e9d4, 0xe9d44408, 0x44111202, 0x69214408,
                                0x69614408, 0x69a14408, 0x42404408, 0x463061e0, 0xff42f7ff, 0x21324d12, 0x4f12444d, 0x1000e9c5,
                                0x0114f105, 0x468860a8, 0x47b84628, 0xb9806968, 0xe9c52033, 0xf44f0600, 0xe9c56080, 0x48074002,
                                0x44484641, 0x61286800, 0x47b84628, 0x28006968, 0x2001d095, 0x0000e793, 0x400fc080, 0x00000004,
                                0x00000008, 0x1fff1ff1, 0x4e697370, 0x12345678, 0x87654321, 0x00000000, 0x00000000
                                ],
               'pc_init' : 0x10000047,
               'pc_eraseAll' : 0x100000e1,
               'pc_erase_sector' : 0x10000123,
               'pc_program_page' : 0x10000169,
               'begin_data' : 0x2007c000,       # Analyzer uses a max of 120 B data (30 pages * 4 bytes / page)
               # Double buffering is not supported since there is not enough ram
               'page_buffers': [0x2007c000, 0x2007c400],
               'begin_stack' : 0x10001000,
               'static_base' : 0x10000214,
               'min_program_length' : 256,
               'analyzer_supported' : True,
               'analyzer_address' : 0x10002000  # Analyzer 0x10002000..0x10002600
              }

class LPC1768(CoreSightTarget):

    VENDOR = "NXP"
    
    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0,           length=0x10000,      is_boot_memory=True,
                                                                blocksize=0x1000,
                                                                page_size=0x400,
                                                                phrase_size=256,
                                                                algo=FLASH_ALGO),
        FlashRegion(    start=0x10000,     length=0x70000,      blocksize=0x8000,
                                                                page_size=0x400,
                                                                phrase_size=256,
                                                                algo=FLASH_ALGO,
                                                                erase_sector_weight=LARGE_ERASE_SECTOR_WEIGHT,
                                                                program_page_weight=LARGE_PROGRAM_PAGE_WEIGHT),
        RamRegion(      start=0x10000000,  length=0x8000),
        RamRegion(      start=0x2007C000,  length=0x8000)
        )

    def __init__(self, session):
        super(LPC1768, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("LPC176x5x_v0.2.svd")
        self._saved_vc = False
        self._reset_handler = 0
        self._had_reset_handler_bp = False

    def add_core(self, core):
        super(LPC1768, self).add_core(core)
        core.delegate = self
    
    def map_flash(self):
        self.write32(0x400FC040, 1)

    def set_reset_catch(self, core, reset_type=None):
        LOG.debug("LPC1768 set reset catch")

        # Clear reset vector catch and remember whether it was set.
        self._saved_vc = self.get_vector_catch()
        self.set_vector_catch(self._saved_vc & ~Target.VectorCatch.CORE_RESET)
        
        # Map flash to 0.
        self.map_flash()
        
        # Set breakpoint on user reset handler.
        self._reset_handler = self.read32(0x4)
        if self._reset_handler < 0x80000:
            self._had_reset_handler_bp = (self.get_breakpoint_type(self._reset_handler) is not None)
            self.set_breakpoint(self._reset_handler)

    def clear_reset_catch(self, core, reset_type=None):
        LOG.debug("LPC1768 clear reset catch")

        # Clear breakpoint if it wasn't previously set.
        if not self._had_reset_handler_bp:
            self.remove_breakpoint(self._reset_handler)
        
        # Restore vector catch.
        self.set_vector_catch(self._saved_vc)
