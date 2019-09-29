# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
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
from time import sleep

from .flash_algo_CY8C6xx5 import flash_algo as flash_algo_main
from .flash_algo_CY8C6xxA_WFLASH import flash_algo as flash_algo_work
from .flash_algo_CY8C6xxA_SFLASH import flash_algo as flash_algo_sflash
from .flash_algo_CY8C6xxA_SMIF_S25FL512S import flash_algo as flash_algo_smif
from .target_CY8C6xxA import CY8C6xxA
from ...core import exceptions
from ...core.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from ...core.target import Target
from ...coresight.cortex_m import CortexM
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)

ERASE_ALL_WEIGHT = 0.5 # Time it takes to perform a chip erase
ERASE_SECTOR_WEIGHT = 0.05 # Time it takes to erase a page
PROGRAM_PAGE_WEIGHT = 0.07 # Time it takes to program a page (Not including data transfer time)

class CY8C6xx5(CY8C6xxA):
    VENDOR = "Cypress"
    
    memoryMap = MemoryMap(
        RomRegion(start=0x00000000, length=0x20000),
        FlashRegion(start=0x10000000, length=0x80000,   blocksize=0x200,
                                                        is_boot_memory=True,
                                                        erased_byte_value=0,
                                                        algo=flash_algo_main,
                                                        erase_all_weight=ERASE_ALL_WEIGHT,
                                                        erase_sector_weight=ERASE_SECTOR_WEIGHT,
                                                        program_page_weight=PROGRAM_PAGE_WEIGHT),
        FlashRegion(start=0x14000000, length=0x8000,    blocksize=0x200,
                                                        is_boot_memory=False,
                                                        erased_byte_value=0,
                                                        algo=flash_algo_work,
                                                        erase_all_weight=ERASE_ALL_WEIGHT,
                                                        erase_sector_weight=ERASE_SECTOR_WEIGHT,
                                                        program_page_weight=PROGRAM_PAGE_WEIGHT),
        FlashRegion(start=0x16000000, length=0x8000,    blocksize=0x200,
                                                        is_boot_memory=False,
                                                        erased_byte_value=0,
                                                        is_testable=False,
                                                        algo=flash_algo_sflash,
                                                        erase_all_weight=ERASE_ALL_WEIGHT,
                                                        erase_sector_weight=ERASE_SECTOR_WEIGHT,
                                                        program_page_weight=PROGRAM_PAGE_WEIGHT),
        FlashRegion(start=0x18000000, length=0x4000000, blocksize=0x40000, page_size=0x1000,
                                                        is_boot_memory=False,
                                                        erased_byte_value=0xFF,
                                                        is_testable=False,
                                                        is_powered_on_boot=False,
                                                        algo=flash_algo_smif,
                                                        erase_all_weight=140,
                                                        erase_sector_weight=1,
                                                        program_page_weight=1),
        RamRegion(start=0x08000000, length=0x10000)
    )

    def __init__(self, link):
        super(CY8C6xx5, self).__init__(link, self.memoryMap)
