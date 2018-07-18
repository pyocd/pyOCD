"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013,2018 ARM Limited

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
from ..core.memory_map import (FlashRegion, RamRegion, DeviceRegion, MemoryMap)
import logging

flash_algo = { 'load_address' : 0x20000000,
               'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x68884972, 0x7f80f010, 0x2001d001, 0x200c4770, 0x20006048, 0x496de7fa, 0xf0106888, 0xd0017f80,
    0x47702001, 0xb1486a48, 0x62482000, 0xb1286a48, 0x62482002, 0xb1086a48, 0xe7f22001, 0xf0206888,
    0xf0404070, 0x60885000, 0xe7ea2000, 0x4c5fb510, 0xffe1f7ff, 0x2001b108, 0x68a0bd10, 0x407ff420,
    0x402af440, 0x68a060a0, 0x0002f040, 0xbf0060a0, 0xf01068a0, 0xd1fb7f80, 0xf02068a0, 0x60a04070,
    0xf0106a60, 0xd0010f02, 0xe7e52001, 0xe7e32000, 0x4605b570, 0xf7ff4c4d, 0xb108ffbe, 0xbd702001,
    0xf42068a0, 0xf440407f, 0x60a040aa, 0x68a06025, 0x0004f040, 0xbf0060a0, 0xf01068a0, 0xd1fb7f80,
    0xf02068a0, 0x60a04070, 0xf0106a60, 0xd0010f02, 0xe7e42001, 0xe7e22000, 0x47f0e92d, 0x468a4606,
    0x4c3a4690, 0x46474655, 0x0f03f018, 0x2001d002, 0x87f0e8bd, 0xf7ff4647, 0xb108ff8e, 0xe7f72002,
    0xf02068a0, 0x60a06000, 0xf04068a0, 0x60a00010, 0x6026e00d, 0x6320cf01, 0xf04068a0, 0x60a00001,
    0x68a0bf00, 0x7f80f010, 0x1d36d1fb, 0x2d041f2d, 0xf016d302, 0xd1ec0f1f, 0x2d04bf00, 0x68a0d318,
    0x6000f020, 0x68a060a0, 0x0010f040, 0xe00d60a0, 0xcf016026, 0x68a06320, 0x0001f040, 0xbf0060a0,
    0xf01068a0, 0xd1fb7f80, 0x1f2d1d36, 0xd2ef2d04, 0x68a2b1fd, 0x6200f022, 0x68a260a2, 0x0210f042,
    0xf04f60a2, 0x21ff30ff, 0x683ae005, 0x0201ea62, 0x02094010, 0x2d001e6d, 0x6026d1f7, 0x68a26320,
    0x0201f042, 0xbf0060a2, 0xf01268a2, 0xd1fb7f80, 0x68a0bf00, 0x4070f020, 0x6a6060a0, 0x0f02f010,
    0x2003d001, 0x2000e794, 0x0000e792, 0x400f0000, 0x00000000, 0x11111111, 0x22222222, 0x33333333,
    0x44444444, 0x00000000, 0x00000000, 0x00000000,
                                ],
               'pc_init' : 0x20000021,
               'pc_eraseAll' : 0x2000006D,
               'pc_erase_sector' : 0x200000B1,
               'pc_program_page' : 0x200000F9,
               'begin_data' : 0x20003000,       # Analyzer uses a max of 512 B data (128 pages * 4 bytes / page)
               'page_buffers' : [0x20003000, 0x20003800],   # Enable double buffering
               'begin_stack' : 0x20001000,
               'static_base' : 0x20000230,
               'min_program_length' : 4,
               'analyzer_supported' : True,
               'analyzer_address' : 0x20004000  # Analyzer 0x20004000..0x20004600
              };

class Flash_max32600(Flash):

    def __init__(self, target):
        super(Flash_max32600mbed, self).__init__(target, flash_algo)

class MAX32600(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x40000,      blocksize=0x800, isBootMemory=True),
        RamRegion(      start=0x20000000,  length=0x8000),
        DeviceRegion(   start=0x40000000,  length=0x100000),
        DeviceRegion(   start=0xe0000000,  length=0x100000)
        )

    def __init__(self, link):
        super(MAX32600, self).__init__(link, self.memoryMap)

    def dsb(self):
        logging.info("Triggering Destructive Security Bypass...")

        self.link.vendor(1)

        # Reconnect debugger
        self.link.init()

    def fge(self):
        logging.info("Triggering Factory Global Erase...")

        self.link.vendor(2)

        # Reconnect debugger
        self.link.init()
