"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

import time
from ..flash.flash import Flash
from ..core.coresight_target import CoreSightTarget
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)

flash_algo = { 
    'load_address' : 0x20000000,
    'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x43f8e92d, 0xf44f2206, 0xf44f7144, 0xf0007080, 0xbb20f959, 0x7480f44f, 0xf44f00a5, 0xf44f52fa, 
    0xf04f760c, 0xf04f0c01, 0xf04f0800, 0x270f2340, 0x629c2005, 0x631e62dd, 0x0100f8c3, 0xc034f8c3, 
    0x50faf44f, 0x10a0f8d3, 0x0f01f011, 0xb158d00a, 0x70a0f8c3, 0x0200f8d3, 0x46409000, 0x2001b130, 
    0x83f8e8bd, 0xd1ed1e40, 0xe7f74660, 0xf0109800, 0xd1010f02, 0xd1db1e52, 0xe8bd2000, 0xe92d83f8, 
    0x461543f8, 0x4606460c, 0xffbaf7ff, 0xd17a2800, 0x2c40f04f, 0x7780f44f, 0xf8cc2135, 0x00b87028, 
    0x002cf8cc, 0x720cf44f, 0x2030f8cc, 0x1100f8cc, 0xf8cc2201, 0xf44f2034, 0xf8dc51fa, 0xf01330a0, 
    0xd00a0f01, 0x210fb159, 0x10a0f8cc, 0x1200f8dc, 0x21009100, 0xd1562900, 0x1e49e003, 0x4611d1ed, 
    0x9900e7f8, 0x8290f8df, 0x0f02f011, 0x0101f1a4, 0x6101ea48, 0xf44fd00b, 0xf8cc7381, 0xf8cc3028, 
    0xf8cc002c, 0xba301030, 0x0032f040, 0xf8cce008, 0xf8cc7028, 0xf8cc002c, 0xba301030, 0x0002f040, 
    0x0100f8cc, 0xf0242000, 0x2c000103, 0xf020d907, 0x4e920303, 0x503358eb, 0x42841d00, 0x42a1d8f7, 
    0xf021d006, 0xf1010003, 0x58282140, 0x0200f8c1, 0xd2082ce0, 0xeba02008, 0xeb001054, 0x00800040, 
    0x1e40bf00, 0xf8ccd1fc, 0xf44f2034, 0xf8dc50fa, 0xf01110a0, 0xd0090f02, 0xf000b128, 0x2800f8be, 
    0xe8bdbf08, 0x200183f8, 0x83f8e8bd, 0xd1ee1e40, 0x497be7f9, 0xf8c12000, 0x2a030154, 0xf04fd103, 
    0x20012140, 0x20006508, 0x20004770, 0xe92d4770, 0xf7ff45f8, 0x2800ff25, 0x2060bf08, 0xbf00d12f, 
    0xd1fc1e40, 0xf44f22c7, 0xf44f7144, 0xf0007080, 0xbb20f879, 0xf44f2200, 0x00a57480, 0x760cf44f, 
    0x0c01f04f, 0xf04f4692, 0x270f2340, 0x7810f242, 0x629c2005, 0x631e62dd, 0x0100f8c3, 0xc034f8c3, 
    0x50faf44f, 0x10a0f8d3, 0x0f01f011, 0xb158d00a, 0x70a0f8c3, 0x0200f8d3, 0x46509000, 0x2001b130, 
    0x85f8e8bd, 0xd1ed1e40, 0xe7f74660, 0xf0109800, 0xbf180f01, 0x60e0f642, 0xbf00d005, 0xd1fc1e40, 
    0x45421c52, 0x2000dbd4, 0x85f8e8bd, 0x4604b510, 0xfed6f7ff, 0xbf082800, 0xd1102160, 0x1e49bf00, 
    0xba20d1fc, 0x0220f040, 0xf44f4946, 0xf0007080, 0xb920f829, 0xf841f000, 0xbf082800, 0x2001bd10, 
    0xb570bd10, 0x1e0c4615, 0xdd194606, 0x7080f5a4, 0x462a2800, 0xf44fdd05, 0x46307180, 0xfeeff7ff, 
    0x4621e003, 0xf7ff4630, 0x2800feea, 0xbd70bf18, 0x7480f5a4, 0x7580f505, 0x7680f506, 0xdce52c00, 
    0xbd702000, 0x2340f04f, 0x15186298, 0x631962d8, 0x2100f8c3, 0x63582001, 0x50faf44f, 0x10a0f8d3, 
    0x0f02f011, 0xb130d005, 0xf8c3200f, 0x200000a0, 0x1e404770, 0x2001d1f2, 0xe92d4770, 0xf44f01f8, 
    0x00a57480, 0x52faf44f, 0x760cf44f, 0x0c01f04f, 0x0800f04f, 0x2340f04f, 0x2005270f, 0x62dd629c, 
    0xf8c3631e, 0xf8c30100, 0xf44fc034, 0xf8d350fa, 0xf01110a0, 0xd00b0f01, 0xf8c3b160, 0xf8d370a0, 
    0x90000200, 0xb1384640, 0x01f8e8bd, 0x47702001, 0xd1ec1e40, 0xe7f64660, 0xf0109800, 0xbf180f01, 
    0xd0042000, 0x28641c40, 0x1e52dbfc, 0xe8bdd1d5, 0x200001f8, 0x00004770, 0x00030330, 0x40004200, 
    0x4004a000, 0x00030310, 0x00000000, 
    ],
    
    'pc_init' : 0x200001B3,
    'pc_unInit': 0x200001CB,
    'pc_program_page': 0x200002A3,
    'pc_erase_sector': 0x2000026D,
    'pc_eraseAll' : 0x200001CF,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000388,
    'begin_stack' : 0x20000000 + 0x00000800,            
    'begin_data' : 0x20000000 + 0x00000A00,
    'page_size' : 0x00000200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000  # ITCM, Analyzer 0x00000000..0x000000600
};

class Flash_tz10xx(Flash):
    def __init__(self, target):
        super(Flash_tz10xx, self).__init__(target, flash_algo)

class TZ10xx(CoreSightTarget):

    has_fpu = True
    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x00100000,   blocksize=0x1000, isBootMemory=True),   #On package NOR Flash
        RamRegion(      start=0x10000000,  length=0x00040000),                                          #Code region
        RamRegion(      start=0x20000000,  length=0x00008000)                                           #Data region
        )

    def __init__(self, link):
        super(TZ10xx, self).__init__(link, self.memoryMap)

    def add_core(self, core):
        super(TZ10xx, self).add_core(core)
        if self.link.get_unique_id()[0:4] == "7010":
            # Board dependent routine of Cerevo BlueNinja.
            self.__power_hold()

    def reset(self, software_reset=True):
        super(TZ10xx, self).reset(True)

    # Board dependent routine of Cerevo BlueNinja.
    # (Tell me a better place to write...)
    def __power_hold(self):
       # Hold the `Power Enable Pin' of BlueNinja.
       self.writeMemory(0x4004B400, 0x00000008) #GPIO3 Output
       self.writeMemory(0x4004B020, 0x00000008) #GPIO3 Hi
       self.readMemory(0x4004B000)

