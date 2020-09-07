# pyOCD debugger
# Copyright (c) 2020 Cypress Semiconductor Corporation
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

from ...family.flash_psoc6 import Flash_PSoC64, PSoC6FlashParams
from ...family.target_psoc6 import PSoC64, CortexM_PSoC64_A2M
from ....core.memory_map import (FlashRegion, MemoryMap)

LOG = logging.getLogger(__name__)


class cy8c64xA(PSoC64):
    from .flash_algos.flash_algo_CY8C64xA import flash_algo as flash_algo_main
    from .flash_algos.flash_algo_CY8C6xxA_WFLASH import flash_algo as flash_algo_work
    from .flash_algos.flash_algo_CY8C6xxA_SMIF_S25FL512S import flash_algo as flash_algo_smif

    MEMORY_MAP = MemoryMap(
        PSoC6FlashParams.defaultRomRegion,
        PSoC6FlashParams.defaultRamRegion,

        FlashRegion(start=0x10000000, length=0x1E0000, blocksize=0x200,
                    is_boot_memory=True,
                    erased_byte_value=0,
                    algo=flash_algo_main,
                    erase_all_weight=PSoC6FlashParams.MFLASH_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.MFLASH_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.MFLASH_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),

        FlashRegion(start=0x14000000, length=0x8000, blocksize=0x200,
                    is_boot_memory=False,
                    erased_byte_value=0,
                    algo=flash_algo_work,
                    erase_all_weight=PSoC6FlashParams.MFLASH_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.MFLASH_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.MFLASH_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),

        FlashRegion(start=0x18000000, length=0x4000000, blocksize=0x40000, page_size=0x1000,
                    is_boot_memory=False,
                    is_testable=False,
                    erased_byte_value=0xFF,
                    is_powered_on_boot=False,
                    algo=flash_algo_smif,
                    erase_all_weight=PSoC6FlashParams.SMIF_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.SMIF_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.SMIF_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),
    )

    def __init__(self, session, ap_num):
        super(cy8c64xA, self).__init__(session, CortexM_PSoC64_A2M, self.MEMORY_MAP, ap_num)


class cy8c64xA_cm0(cy8c64xA):
    def __init__(self, session):
        super(cy8c64xA_cm0, self).__init__(session, 1)


class cy8c64xA_cm4(cy8c64xA):
    def __init__(self, session):
        super(cy8c64xA_cm4, self).__init__(session, 2)


class cy8c64xA_cm4_full_flash(cy8c64xA_cm4):
    from .flash_algos.flash_algo_CY8C64xA import flash_algo as flash_algo_main
    from .flash_algos.flash_algo_CY8C6xxA_WFLASH import flash_algo as flash_algo_work
    from .flash_algos.flash_algo_CY8C6xxA_SMIF_S25FL512S import flash_algo as flash_algo_smif

    MEMORY_MAP = MemoryMap(
        PSoC6FlashParams.defaultRomRegion,
        PSoC6FlashParams.defaultRamRegion,

        FlashRegion(start=0x10000000, length=0x200000, blocksize=0x200,
                    is_boot_memory=True,
                    erased_byte_value=0,
                    algo=flash_algo_main,
                    erase_all_weight=PSoC6FlashParams.MFLASH_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.MFLASH_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.MFLASH_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),

        FlashRegion(start=0x14000000, length=0x8000, blocksize=0x200,
                    is_boot_memory=False,
                    erased_byte_value=0,
                    algo=flash_algo_work,
                    erase_all_weight=PSoC6FlashParams.MFLASH_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.MFLASH_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.MFLASH_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),

        FlashRegion(start=0x18000000, length=0x4000000, blocksize=0x40000, page_size=0x1000,
                    is_boot_memory=False,
                    is_testable=False,
                    erased_byte_value=0xFF,
                    is_powered_on_boot=False,
                    algo=flash_algo_smif,
                    erase_all_weight=PSoC6FlashParams.SMIF_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.SMIF_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.SMIF_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),
    )


class cy8c64xA_cm0_full_flash(cy8c64xA_cm0):
    from .flash_algos.flash_algo_CY8C64xA import flash_algo as flash_algo_main
    from .flash_algos.flash_algo_CY8C6xxA_WFLASH import flash_algo as flash_algo_work
    from .flash_algos.flash_algo_CY8C6xxA_SMIF_S25FL512S import flash_algo as flash_algo_smif

    MEMORY_MAP = MemoryMap(
        PSoC6FlashParams.defaultRomRegion,
        PSoC6FlashParams.defaultRamRegion,

        FlashRegion(start=0x10000000, length=0x200000, blocksize=0x200,
                    is_boot_memory=True,
                    erased_byte_value=0,
                    algo=flash_algo_main,
                    erase_all_weight=PSoC6FlashParams.MFLASH_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.MFLASH_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.MFLASH_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),

        FlashRegion(start=0x14000000, length=0x8000, blocksize=0x200,
                    is_boot_memory=False,
                    erased_byte_value=0,
                    algo=flash_algo_work,
                    erase_all_weight=PSoC6FlashParams.MFLASH_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.MFLASH_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.MFLASH_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),

        FlashRegion(start=0x18000000, length=0x4000000, blocksize=0x40000, page_size=0x1000,
                    is_boot_memory=False,
                    is_testable=False,
                    erased_byte_value=0xFF,
                    is_powered_on_boot=False,
                    algo=flash_algo_smif,
                    erase_all_weight=PSoC6FlashParams.SMIF_ERASE_ALL_WEIGHT,
                    erase_sector_weight=PSoC6FlashParams.SMIF_ERASE_SECTOR_WEIGHT,
                    program_page_weight=PSoC6FlashParams.SMIF_PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_PSoC64),
    )
