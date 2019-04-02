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
from time import (time, sleep)

from ...core import exceptions
from ...core.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from ...core.target import Target
from ...coresight.cortex_m import CortexM
from ...flash.flash import Flash
from ...utility.notification import Notification
from ...utility.timeout import Timeout

flash_algo_main = {
    'load_address': 0x08000000,

    # Flash algorithm as a hex string
    'instructions': [
        0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
        0x68184b04, 0x011b23f0, 0x42434018, 0xb2c04158, 0x46c04770, 0x40210400, 0x2300b570, 0x19180004,
        0xd100428b, 0x7805bd70, 0x42ae5cd6, 0x3301d1fa, 0x0000e7f5, 0x2400b510, 0x18c04b0a, 0x69030140,
        0xd0052900, 0xd10a0fdb, 0xd8034294, 0xe7f63401, 0xe7f743db, 0x4b0422f0, 0x447b0612, 0x2000601a,
        0x46c0bd10, 0x02011800, 0x000001de, 0x4b092200, 0x014018c0, 0x2b006803, 0x428adb08, 0x3201d801,
        0x21f0e7f8, 0x06094a04, 0x6011447a, 0x0fc043d8, 0x46c04770, 0x02011800, 0x000001b0, 0x24a0b510,
        0x68030624, 0x60130f19, 0x42a10709, 0x4a02d1f9, 0x447a2000, 0xbd106013, 0x00000186, 0xb085b5f0,
        0x000e0007, 0xff9cf7ff, 0xd1322800, 0x4c1b2501, 0x002821fa, 0xf7ff0049, 0x2800ffc9, 0x4b18d127,
        0x447b003a, 0x23019302, 0x9201401a, 0x320c0022, 0x9a019203, 0xd11f2a00, 0x60e29a02, 0x0019002a,
        0x40913210, 0x00284a0f, 0x22fa6011, 0x005260a3, 0xf7ff2100, 0x2800ff8f, 0x21fad109, 0x00329b01,
        0x98020049, 0xd0002b00, 0xf7ff9803, 0xb005ffb7, 0x4c05bdf0, 0xe7cb2500, 0xe7df60e7, 0x40230020,
        0x0000013e, 0x40231008, 0x40230000, 0xb5004b0a, 0x781a447b, 0x701a2200, 0x21017859, 0x78997059,
        0x78da709a, 0xb083221c, 0xa90170da, 0x48036058, 0xffa4f7ff, 0x46c0bd0e, 0x000000d0, 0x1c000100,
        0xb5004b09, 0x781a447b, 0x701a2200, 0x21017859, 0x78997059, 0x78da709a, 0xb083220a, 0xa90170da,
        0xf7ff4802, 0xbd0eff8b, 0x0000009c, 0x0a000100, 0xf7ffb510, 0xbd10ffe5, 0xb5104b0c, 0x781a447b,
        0x701a2200, 0x2401785c, 0x789c705c, 0x78da709a, 0x70da2206, 0xb0823201, 0x605a32ff, 0x60d96098,
        0xa9014803, 0xff6af7ff, 0x46c0bd16, 0x00000064, 0x06000100, 0x47702000, 0x47702000, 0xf7ffb510,
        0xbd10ffd7, 0xf7ffb510, 0xbd10ffa1, 0xb5100013, 0x0019000a, 0xffd0f7ff, 0xb510bd10, 0xfefcf7ff,
        0x0000bd10, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x08000215,
    'pc_unInit': 0x08000219,
    'pc_program_page': 0x0800022d,
    'pc_erase_sector': 0x08000225,
    'pc_eraseAll': 0x0800021d,

    'static_base': 0x08000000 + 0x00000020 + 0x00000224,
    'begin_stack': 0x08008000,
    'begin_data': 0x08000000 + 0x1000,
    'page_size': 0x200,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x08001000, 0x08001200],  # Enable double buffering
    'min_program_length': 0x200,

    # Flash information
    'flash_start': 0x10000000,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

flash_algo_work = {
    'load_address': 0x08000000,

    # Flash algorithm as a hex string
    'instructions': [
        0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
        0x68184b04, 0x011b23f0, 0x42434018, 0xb2c04158, 0x46c04770, 0x40210400, 0x2300b570, 0x19180004,
        0xd100428b, 0x7805bd70, 0x42ae5cd6, 0x3301d1fa, 0x0000e7f5, 0x2400b510, 0x18c04b0a, 0x69030140,
        0xd0052900, 0xd10a0fdb, 0xd8034294, 0xe7f63401, 0xe7f743db, 0x4b0422f0, 0x447b0612, 0x2000601a,
        0x46c0bd10, 0x02011800, 0x000001e6, 0x4b092200, 0x014018c0, 0x2b006803, 0x428adb08, 0x3201d801,
        0x21f0e7f8, 0x06094a04, 0x6011447a, 0x0fc043d8, 0x46c04770, 0x02011800, 0x000001b8, 0x24a0b510,
        0x68030624, 0x60130f19, 0x42a10709, 0x4a02d1f9, 0x447a2000, 0xbd106013, 0x0000018e, 0xb085b5f0,
        0x000e0007, 0xff9cf7ff, 0xd1322800, 0x4c1b2501, 0x002821fa, 0xf7ff0049, 0x2800ffc9, 0x4b18d127,
        0x447b003a, 0x23019302, 0x9201401a, 0x320c0022, 0x9a019203, 0xd11f2a00, 0x60e29a02, 0x0019002a,
        0x40913210, 0x00284a0f, 0x22fa6011, 0x005260a3, 0xf7ff2100, 0x2800ff8f, 0x21fad109, 0x00329b01,
        0x98020049, 0xd0002b00, 0xf7ff9803, 0xb005ffb7, 0x4c05bdf0, 0xe7cb2500, 0xe7df60e7, 0x40230020,
        0x00000146, 0x40231008, 0x40230000, 0xb5004b0a, 0x781a447b, 0x701a2200, 0x21017859, 0x78997059,
        0x78da709a, 0xb083221c, 0xa90170da, 0x48036058, 0xffa4f7ff, 0x46c0bd0e, 0x000000d8, 0x1c000100,
        0xb5004b0a, 0x781a447b, 0x701a2200, 0x21017859, 0x78997059, 0x78da709a, 0xb0832214, 0xa90170da,
        0x48036058, 0xff8af7ff, 0x46c0bd0e, 0x000000a4, 0x14000100, 0xb51020a0, 0xf7ff0540, 0xbd10ffe1,
        0xb5104b0c, 0x781a447b, 0x701a2200, 0x2401785c, 0x789c705c, 0x78da709a, 0x70da2206, 0xb0823201,
        0x605a32ff, 0x60d96098, 0xa9014803, 0xff66f7ff, 0x46c0bd16, 0x00000064, 0x06000100, 0x47702000,
        0x47702000, 0xf7ffb510, 0xbd10ffd5, 0xf7ffb510, 0xbd10ff9d, 0xb5100013, 0x0019000a, 0xffd0f7ff,
        0xb510bd10, 0xfef8f7ff, 0x0000bd10, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x0800021d,
    'pc_unInit': 0x08000221,
    'pc_program_page': 0x08000235,
    'pc_erase_sector': 0x0800022d,
    'pc_eraseAll': 0x08000225,

    'static_base': 0x08000000 + 0x00000020 + 0x0000022c,
    'begin_stack': 0x08008000,
    'begin_data': 0x08000000 + 0x1000,
    'page_size': 0x200,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x08001000, 0x08001200],  # Enable double buffering
    'min_program_length': 0x200,

    # Flash information
    'flash_start': 0x14000000,
    'flash_size': 0x8000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

flash_algo_sflash = {
    'load_address': 0x08000000,

    # Flash algorithm as a hex string
    'instructions': [
        0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
        0x68184b04, 0x011b23f0, 0x42434018, 0xb2c04158, 0x46c04770, 0x40210400, 0x2300b570, 0x19180004,
        0xd100428b, 0x7805bd70, 0x42ae5cd6, 0x3301d1fa, 0x0000e7f5, 0x2400b510, 0x18c04b0a, 0x69030140,
        0xd0052900, 0xd10a0fdb, 0xd8034294, 0xe7f63401, 0xe7f743db, 0x4b0422f0, 0x447b0612, 0x2000601a,
        0x46c0bd10, 0x02011800, 0x00000176, 0x4b092200, 0x014018c0, 0x2b006803, 0x428adb08, 0x3201d801,
        0x21f0e7f8, 0x06094a04, 0x6011447a, 0x0fc043d8, 0x46c04770, 0x02011800, 0x00000148, 0x24a0b510,
        0x68030624, 0x60130f19, 0x42a10709, 0x4a02d1f9, 0x447a2000, 0xbd106013, 0x0000011e, 0xb085b5f0,
        0x000e0007, 0xff9cf7ff, 0xd1322800, 0x4c1b2501, 0x002821fa, 0xf7ff0049, 0x2800ffc9, 0x4b18d127,
        0x447b003a, 0x23019302, 0x9201401a, 0x320c0022, 0x9a019203, 0xd11f2a00, 0x60e29a02, 0x0019002a,
        0x40913210, 0x00284a0f, 0x22fa6011, 0x005260a3, 0xf7ff2100, 0x2800ff8f, 0x21fad109, 0x00329b01,
        0x98020049, 0xd0002b00, 0xf7ff9803, 0xb005ffb7, 0x4c05bdf0, 0xe7cb2500, 0xe7df60e7, 0x40230020,
        0x000000d6, 0x40231008, 0x40230000, 0x47702000, 0xb5104b0c, 0x781a447b, 0x701a2200, 0x2401785c,
        0x789c705c, 0x78da709a, 0x70da2205, 0xb0823202, 0x605a32ff, 0x60d96098, 0xa9014803, 0xff9ef7ff,
        0x46c0bd16, 0x00000064, 0x05000100, 0x47702000, 0x47702000, 0xf7ffb510, 0xbd10ffd9, 0x47702000,
        0xb5100013, 0x0019000a, 0xffd2f7ff, 0xb510bd10, 0xff32f7ff, 0x2000bd10, 0x00004770, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x080001ad,
    'pc_unInit': 0x080001b1,
    'pc_program_page': 0x080001c1,
    'pc_erase_sector': 0x080001bd,
    'pc_eraseAll': 0x080001b5,

    'static_base': 0x08000000 + 0x00000020 + 0x000001bc,
    'begin_stack': 0x08008000,
    'begin_data': 0x08000000 + 0x1000,
    'page_size': 0x200,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x08001000, 0x08001200],  # Enable double buffering
    'min_program_length': 0x200,

    # Flash information
    'flash_start': 0x16000000,
    'flash_size': 0x8000,
    'sector_sizes': (
        (0x0, 0x200),
    )
}

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
        RamRegion(start=0x08000000, length=0x10000)
    )

    def __init__(self, link):
        super(CY8C6xx7, self).__init__(link, self.memoryMap)

    def create_init_sequence(self):
        seq = super(CY8C6xx7, self).create_init_sequence()
        seq.replace_task('create_cores', self.create_cy8c6xx7_core)
        return seq

    def create_cy8c6xx7_core(self):
        core0 = CortexM_CY8C6xx7(self, self.aps[1], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.SW_SYSRESETREQ
        core1 = CortexM_CY8C6xx7(self, self.aps[2], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.SW_SYSRESETREQ

        self.aps[1].core = core0
        self.aps[2].core = core1
        core0.init()
        core1.init()
        self.add_core(core0)
        self.add_core(core1)


class CortexM_CY8C6xx7(CortexM):
    def reset(self, reset_type=None):
        self.notify(Notification(event=Target.EVENT_PRE_RESET, source=self))

        self._run_token += 1

        if reset_type is Target.ResetType.HW:
            self.session.probe.reset()
            sleep(0.5)
            self._ap.dp.init()
            self._ap.dp.power_up_debug()
            # This is ugly, but FPB gets disabled after HW Reset so breakpoints stop working
            self.bp_manager._fpb.enable()

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
                    self._ap.dp.init()
                    self._ap.dp.power_up_debug()
                    sleep(0.01)

        self.notify(Notification(event=Target.EVENT_POST_RESET, source=self))

    def wait_halted(self):
        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    if not self.is_running():
                        return
                except exceptions.TransferError:
                    self.flush()
                    sleep(0.01)
            else:
                raise Exception("Timeout waiting for target halt")

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
            raise Exception("Invalid CORE ID")

        vtbase &= 0xFFFFFF00
        if vtbase < 0x10000000 or vtbase > 0x18000000:
            logging.info("Vector Table address invalid (0x%08X), will not halt at main()", vtbase)
            return

        entry = self.read_memory(vtbase + 4)
        if entry < 0x10000000 or entry > 0x18000000:
            logging.info("Entry Point address invalid (0x%08X), will not halt at main()", entry)
            return

        self.set_breakpoint(entry)
        self.reset(self.ResetType.SW_SYSRESETREQ)
        sleep(0.2)
        self.wait_halted()
        self.remove_breakpoint(entry)
