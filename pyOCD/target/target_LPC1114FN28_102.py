"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from ..flash.flash import Flash
from ..core.coresight_target import CoreSightTarget
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)

WRITE_SIZE = 256

flash_algo = {
    'load_address' : 0x10000000,
    'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4c0fb5f8, 0x25002032, 0x2607444c, 0x490d60a6, 0x60206065, 0x4f0c4449, 0x91004620, 0x696047b8,
    0xd10b2800, 0x203460a6, 0x60206065, 0x60e04807, 0x99004620, 0x696047b8, 0xd0002800, 0xbdf82001,
    0x00000004, 0x00000018, 0x1fff1ff1, 0x00002ee0, 0x4d0fb5f8, 0x444d0b04, 0x490e606c, 0x60ac2032,
    0x60284449, 0x460f4e0c, 0x47b04628, 0x28006968, 0x606cd10b, 0x60ac2034, 0x48086028, 0x463960e8,
    0x47b04628, 0x28006968, 0x2001d000, 0x0000bdf8, 0x00000004, 0x00000018, 0x1fff1ff1, 0x00002ee0,
    0x47700b00, 0x21004807, 0x22016301, 0x63416342, 0x6b416342, 0xd0fc07c9, 0x49036382, 0x60082002,
    0x47702000, 0x40048040, 0x40048000, 0x4614b5f8, 0xd10e0005, 0x68206861, 0x184068e2, 0x188968a1,
    0x69211840, 0x69611840, 0x69a11840, 0x42401840, 0x4e1061e0, 0x444e0b28, 0x60702132, 0x490e6031,
    0x444960b0, 0x46304f0d, 0x47b89100, 0x28006970, 0x6075d10e, 0x60b42033, 0x20ff6030, 0x60f03001,
    0x61304807, 0x99004630, 0x697047b8, 0xd0002800, 0xbdf82001, 0x00000004, 0x00000018, 0x1fff1ff1,
    0x00002ee0, 0x47702000, 0x00000000,
    ],

    'pc_eraseAll' : 0x10000021,
    'pc_init' : 0x100000C5,
    #'pc_UnInit' : 0x10000165,
    'pc_program_page' : 0x100000ED,
    'pc_erase_sector' : 0x10000071,

    'static_base' : 0x10000000 + 0x00000020 + 0x00000148,
    'begin_data' : 0x10000000 + 0x00000A00,
    # Double buffering is not supported since there is not enough ram
    'begin_stack' : 0x10000800,
    'page_size' : 0x00001000,
    'min_program_length' : 1024,
    'analyzer_supported' : False,
};

class Flash_lpc11xx_32(Flash):
    def __init__(self, target):
        super(Flash_lpc11xx_32, self).__init__(target, flash_algo)

    # Override programPage and break the operation into 4 1KB writes
    # since there isn't enough ram to do a 4K sector write directly
    def programPage(self, flashPtr, bytes):
        pages = (len(bytes) + WRITE_SIZE - 1) // WRITE_SIZE
        for i in range(0, pages):
            data = bytes[i * WRITE_SIZE : (i + 1) * WRITE_SIZE]
            Flash.programPage(self, flashPtr + i * WRITE_SIZE, data)

class LPC11XX_32(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x8000,       blocksize=0x1000, isBootMemory=True),
        RamRegion(      start=0x10000000,  length=0x1000)
        )

    def __init__(self, link):
        super(LPC11XX_32, self).__init__(link, self.memoryMap)

    def resetStopOnReset(self, software_reset=None, map_to_user=True):
        super(LPC11XX_32, self).resetStopOnReset(software_reset)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.writeMemory(0x40048000, 0x2, 32)
            sp = self.readMemory(0x0)
            pc = self.readMemory(0x4)
            self.writeCoreRegisterRaw('sp', sp)
            self.writeCoreRegisterRaw('pc', pc)
