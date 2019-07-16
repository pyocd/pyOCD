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

from .flash_algo_CY8C6xx7 import flash_algo as flash_algo_main
from .flash_algo_CY8C6xxx_WFLASH import flash_algo as flash_algo_work
from .flash_algo_CY8C6xxx_SFLASH import flash_algo as flash_algo_sflash
from .flash_algo_CY8C6xxx_SMIF_S25FL512S import flash_algo as flash_algo_smif
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
    
class CY8C6xx7(CoreSightTarget):
    VENDOR = "Cypress"
    
    memoryMap = MemoryMap(
        RomRegion(start=0x00000000, length=0x20000),
        FlashRegion(start=0x10000000, length=0x100000,  blocksize=0x200,
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
        super(CY8C6xx7, self).__init__(link, self.memoryMap)

    def create_init_sequence(self):
        seq = super(CY8C6xx7, self).create_init_sequence()
        seq.replace_task('create_cores', self.create_cy8c6xx7_core)
        return seq

    def create_cy8c6xx7_core(self):
        core0 = CortexM_CY8C6xx7(self.session, self.aps[1], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.SW_SYSRESETREQ
        core1 = CortexM_CY8C6xx7(self.session, self.aps[2], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.SW_SYSRESETREQ

        self.aps[1].core = core0
        self.aps[2].core = core1
        core0.init()
        core1.init()
        self.add_core(core0)
        self.add_core(core1)


class CortexM_CY8C6xx7(CortexM):
    def reset(self, reset_type=None):
        self.session.notify(Target.EVENT_PRE_RESET, self)

        self._run_token += 1
        
        if reset_type is Target.ResetType.HW:
            self.session.probe.reset()
            sleep(0.5)
            self._ap.dp.init()
            self._ap.dp.power_up_debug()
            self.fpb.enable()

        else:
            if reset_type is Target.ResetType.SW_VECTRESET:
                mask = CortexM.NVIC_AIRCR_VECTRESET
            else:
                mask = CortexM.NVIC_AIRCR_SYSRESETREQ

            try:
                self.write_memory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | mask)
                self.flush()
            except exceptions.TransferError:
                self.flush()

        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    dhcsr_reg = self.read32(CortexM.DHCSR)
                    if (dhcsr_reg & CortexM.S_RESET_ST) == 0:
                        break
                except exceptions.TransferError:
                    self.flush()
                    try:
                        self._ap.dp.init()
                        self._ap.dp.power_up_debug()
                    except exceptions.TransferError:
                        self.flush()
                    
                    sleep(0.01)

        self.session.notify(Target.EVENT_POST_RESET, self)

    def wait_halted(self):
        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    if not self.is_running():
                        break
                except exceptions.TransferError:
                    self.flush()
                    sleep(0.01)
            else:
                raise exceptions.TimeoutError("Timeout waiting for target halt")

    def reset_and_halt(self, reset_type=None):
        self.halt()
        self.reset(reset_type)
        sleep(0.5)
        self.halt()

        self.wait_halted()

        if self.core_number == 0:
            vtbase = self.read_memory(0x402102B0)  # VTBASE_CM0
        elif self.core_number == 1:
            vtbase = self.read_memory(0x402102C0)  # VTBASE_CM4
        else:
            raise exceptions.TargetError("Invalid CORE ID")

        vtbase &= 0xFFFFFF00
        if vtbase < 0x10000000 or vtbase > 0x18000000:
            LOG.info("Vector Table address invalid (0x%08X), will not halt at main()", vtbase)
            return

        entry = self.read_memory(vtbase + 4)
        if entry < 0x10000000 or entry > 0x18000000:
            LOG.info("Entry Point address invalid (0x%08X), will not halt at main()", entry)
            return
        
        self.set_breakpoint(entry)
        self.bp_manager.flush()
        self.reset(self.ResetType.SW_SYSRESETREQ)
        sleep(0.2)
        self.wait_halted()
        self.remove_breakpoint(entry)
        self.bp_manager.flush()
