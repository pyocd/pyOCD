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

from flash import Flash
import logging

NVMC_READY      = 0x4001E400
NVMC_CONFIG     = 0x4001E504
NVMC_ERASEPAGE  = 0x4001E508

flash_algo = { 'load_address' : 0x20000000,
               'instructions' : [
                                0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
                                0x47702000, 0x47702000, 0x4c26b570, 0x60602002, 0x60e02001, 0x68284d24, 0xd00207c0L, 0x60602000, 
                                0xf000bd70L, 0xe7f6f82cL, 0x4c1eb570, 0x60612102, 0x4288491e, 0x2001d302, 0xe0006160L, 0x4d1a60a0, 
                                0xf81df000L, 0x7c06828, 0x2000d0fa, 0xbd706060L, 0x4605b5f8, 0x4813088e, 0x46142101, 0x4f126041, 
                                0xc501cc01L, 0x7c06838, 0x1e76d006, 0x480dd1f8, 0x60412100, 0xbdf84608L, 0xf801f000L, 0x480ce7f2, 
                                0x6006840, 0xd00b0e00L, 0x6849490a, 0xd0072900L, 0x4a0a4909, 0xd00007c3L, 0x1d09600a, 0xd1f90840L, 
                                0x4770, 0x4001e500, 0x4001e400, 0x10001000, 0x40010400, 0x40010500, 0x40010600, 0x6e524635, 
                                0x0],
               'pc_init'          : 0x20000021,
               'pc_eraseAll'      : 0x20000029,
               'pc_program_page'  : 0x20000071,
               'begin_data'       : 0x20000200,
               'begin_stack'      : 0x20001000,
               'static_base'      : 0x20000170,
               'page_size'        : 1024
              };
              
class Flash_nrf51822(Flash):
    
    def __init__(self, target):
        super(Flash_nrf51822, self).__init__(target, flash_algo)

    def erasePage(self, flashPtr):
        """
        Erase one page
        """

        logging.info("Flash_nrf51822: Erase page: 0x%X", flashPtr)
        self.target.writeMemory(NVMC_CONFIG, 2)
        while self.target.readMemory(NVMC_READY) == 0:
            pass
        self.target.writeMemory(NVMC_ERASEPAGE, flashPtr)

        while self.target.readMemory(NVMC_READY) == 0:
            pass
