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
import logging

flash_algo = { 'load_address' : 0x20000000,
               'instructions' : [
                                0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
                                0x47702000, 0x47702000, 0x4c26b570, 0x60602002, 0x60e02001, 0x68284d24, 0xd00207c0, 0x60602000,
                                0xf000bd70, 0xe7f6f82c, 0x4c1eb570, 0x60612102, 0x4288491e, 0x2001d302, 0xe0006160, 0x4d1a60a0,
                                0xf81df000, 0x07c06828, 0x2000d0fa, 0xbd706060, 0x4605b5f8, 0x4813088e, 0x46142101, 0x4f126041,
                                0xc501cc01, 0x07c06838, 0x1e76d006, 0x480dd1f8, 0x60412100, 0xbdf84608, 0xf801f000, 0x480ce7f2,
                                0x06006840, 0xd00b0e00, 0x6849490a, 0xd0072900, 0x4a0a4909, 0xd00007c3, 0x1d09600a, 0xd1f90840,
                                0x00004770, 0x4001e500, 0x4001e400, 0x10001000, 0x40010400, 0x40010500, 0x40010600, 0x6e524635,
                                0x00000000, ],
               'pc_init'          : 0x20000021,
               'pc_eraseAll'      : 0x20000029,
               'pc_erase_sector'  : 0x20000049,
               'pc_program_page'  : 0x20000071,
               'begin_data'       : 0x20002000, # Analyzer uses a max of 0.5 KB data (128 pages * 4 bytes / page)
               'page_buffers'    : [0x20002000, 0x20003000],   # Enable double buffering
               'begin_stack'      : 0x20001000,
               'static_base'      : 0x20000170,
               'min_program_length' : 4,
               'analyzer_supported' : True,
               'analyzer_address' : 0x20004000  # Analyzer 0x20004000..0x20004600
              }

class Flash_nrf52840(Flash):

    def __init__(self, target):
        super(Flash_nrf52840, self).__init__(target, flash_algo)

class NRF52840(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(    start=0x0,         length=0x100000,     blocksize=0x1000, isBootMemory=True),
        # User Information Configation Registers (UICR) as a flash region
        FlashRegion(    start=0x10001000,  length=0x100,        blocksize=0x100, isTestable=False),
        RamRegion(      start=0x20000000,  length=0x40000)
        )

    def __init__(self, link):
        super(NRF52840, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile(vendor="Nordic", filename="nrf52.svd", is_local=False)

    def resetn(self):
        """
        reset a core. After a call to this function, the core
        is running
        """
        self.reset()
