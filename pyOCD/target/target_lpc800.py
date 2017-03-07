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
from ..core.coresight_target import (SVDFile, CoreSightTarget)
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)

flash_algo = { 'load_address' : 0x10000000,
               'instructions' : [
                                 0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
                                 0x47700a80, 0x484e494f, 0x60084449, 0x2100484e, 0x22016301, 0x63416342, 0x6b416342, 0xd0fc07c9,
                                 0x49496382, 0x39402002, 0x20007008, 0x20004770, 0xb5f84770, 0x20324c45, 0x2500444c, 0x4622260f,
                                 0x4621c261, 0x4f423114, 0x91004620, 0x696047b8, 0xd10c2800, 0x46212034, 0x483ac161, 0x68004448,
                                 0x462060e0, 0x47b89900, 0x28006960, 0x2001d000, 0xb5f8bdf8, 0x0a844d35, 0x2032444d, 0x4629606c,
                                 0x311460ac, 0x4e326028, 0x4628460f, 0x696847b0, 0xd10d2800, 0x2034606c, 0x602860ac, 0x46394829,
                                 0x68004448, 0x462860e8, 0x696847b0, 0xd0002800, 0xbdf82001, 0x4614b5f8, 0xd11e0006, 0x0180200b,
                                 0x6bc11820, 0x42814823, 0x4823d038, 0xd0354281, 0x42814822, 0x4822d032, 0xd02f4281, 0x68206861,
                                 0x184068e2, 0x188968a1, 0x69211840, 0x69611840, 0x69a11840, 0x42401840, 0x4d1461e0, 0x444d0ab0,
                                 0x60682132, 0x60a86029, 0x31144629, 0x46284f10, 0x47b89100, 0x28006968, 0x606ed110, 0x60ac2033,
                                 0x20016028, 0x60e80280, 0x44484806, 0x61286800, 0x99004628, 0x696847b8, 0xd0002800, 0xbdf82001,
                                 0x00002ee0, 0x00000004, 0x40048040, 0x00000008, 0x1fff1ff1, 0x4e697370, 0x12345678, 0x87654321,
                                 0x43218765
                                ],
               'pc_init' : 0x10000024,
               'pc_eraseAll' : 0x10000052,
               'pc_erase_sector' : 0x10000092,
               'pc_program_page' : 0x100000d4,
               'begin_data' : 0x10000400,       # Analyzer uses a max of 128 B data (32 pages * 4 bytes / page)
               # Double buffering is not supported since there is not enough ram
               'begin_stack' : 0x10001000,
               'static_base' : 0x10000300,
               'min_program_length' : 64,
               'analyzer_supported' : True,
               'analyzer_address' : 0x10000800  # Analyzer 0x10000800..0x10000e00
              };

class Flash_lpc800(Flash):

    def __init__(self, target):
        super(Flash_lpc800, self).__init__(target, flash_algo)

class LPC800(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x4000,       blocksize=0x400, isBootMemory=True),
        RamRegion(      start=0x10000000,  length=0x1000)
        )

    def __init__(self, link):
        super(LPC800, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile(vendor="NXP", filename="LPC800_v0.3.svd", is_local=False)

    def resetStopOnReset(self, software_reset=None, map_to_user=True):
        super(LPC800, self).resetStopOnReset(software_reset)

        # Remap to use flash and set SP and SP accordingly
        if map_to_user:
            self.writeMemory(0x40048000, 0x2, 32)
            sp = self.readMemory(0x0)
            pc = self.readMemory(0x4)
            self.writeCoreRegisterRaw('sp', sp)
            self.writeCoreRegisterRaw('pc', pc)
