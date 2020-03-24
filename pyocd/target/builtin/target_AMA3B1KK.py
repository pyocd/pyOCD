# pyOCD debugger
# Copyright (c) 2019 SparkFun Electronics
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

from ...flash.flash import Flash
from ...core.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...coresight.cortex_m import CortexM
from ...debug.svd.loader import SVDFile

flash_algo = {
    'load_address' : 0x10000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x2040f04f, 0x61812147, 0x61412100, 0x46086181, 0x20004770, 0xe92d4770, 0x4e3341f0, 0x4f332500,
    0x444e2406, 0x68734622, 0x46382100, 0x43054798, 0x2c401c64, 0x6832dbf6, 0x46382101, 0x43284790,
    0x81f0e8bd, 0x0cc1b510, 0x2101d000, 0x444a4a26, 0xf3c06853, 0x48253245, 0x28004798, 0x2001d000,
    0xe92dbd10, 0x460747f0, 0x07884616, 0x2001d000, 0x0491eb00, 0x8070f8df, 0x0006ea47, 0xa06cf8df,
    0x44c80780, 0x2000d025, 0xf5b4e01f, 0xd2017f00, 0xe00100a5, 0x6500f44f, 0x20004915, 0xe0044449,
    0x2b01f816, 0x2b01f801, 0x42a81c40, 0x4910d3f8, 0xc008f8d8, 0xf02708ab, 0x44490203, 0x47e04650,
    0xd1042800, 0x0495eba4, 0x2c00442f, 0xe8bdd1dd, 0xf8d887f0, 0x46235008, 0x4631463a, 0x46ac4650,
    0x47f0e8bd, 0x00004760, 0x00000004, 0x12344321, 0x00000024, 0x00000000, 0x0800004d, 0x08000051,
    0x08000055, 0x08000059, 0x0800005d, 0x08000061, 0x08000065, 0x08000069, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x10000021,
    'pc_unInit': 0x10000033,
    'pc_program_page': 0x10000083,
    'pc_erase_sector': 0x10000065,
    'pc_eraseAll': 0x10000037,

    'static_base' : 0x10000000 + 0x00000020 + 0x000000f4,
    'begin_stack' : 0x10000400,
    'begin_data' : 0x10000000 + 0x1000,
    'page_size' : 0x2000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x10001000, 0x10003000],   # Enable double buffering
    'min_program_length' : 0x2000,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x100000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}

class Apollo3(CortexM):
    def __init__(self, session, ap, memoryMap, core_num, acquire_timeout):
        self._acquire_timeout = acquire_timeout
        super(Apollo3, self).__init__(session, ap, memoryMap, core_num)
    # def reset_and_halt(self, reset_type=None):
    #     #ignore reset type
    #     #write_memory(self, addr, data, transfer_size=32):
    #     #read_memory(self, addr, transfer_size=32, now=True)
    #     print("ENTERING CUSTOM RESET SEQUENCE")

    #     v = self.read_memory(0xE000EDF0)
    #     print("0xE000EDF0 = " + str(v))
    #     v &= 0x3F
    #     v |= 0xA05F0003
    #     self.write_memory(0xE000EDF0, v)
    #     print("Wrote "+ str(v) + " to 0xE000EDF0")

    #     jdecpid = self.read_memory(0xF0000FE0)
    #     print("JDEC PID " + str(jdecpid))

    #     if((jdecpid & 0xf0) == 0xc0):
    #         print("Ambiq Apollo3")
    #         bootldr = self.read_memory(0x400401A0)
    #         if ((bootldr & 0x0C000000) == 0x04000000):
    #             print("Secure Part.")
    #             secure = True
        
    #     if(secure):
    #         scratch0 = self.read_memory(0x400401B0)
    #         print("scratch0 = "+ str(scratch0))
    #         self.write_memory(0x400401B0, (scratch0 | 0x1))
    #         print("wrote " + str(scratch0 | 0x1) + " to scratch0")
    #     else:
    #         print("I havent wrtten non secure yet")
        
    #     #mask = CortexM.NVIC_AIRCR_SYSRESETREQ        
    #     #self.write_memory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | mask)
    #     self.write_memory(0xe000ed0c, 0x05fa0004)
    #     print("reset")
    #     # Without a flush a transfer error can occur
    #     self.flush()
    #     print("flush")

    def set_reset_catch(self, reset_type=None):
        """! @brief Prepare to halt core on reset."""
        #LOG.debug("set reset catch, core %d", self.core_number)

        self._reset_catch_delegate_result = self.call_delegate('set_reset_catch', core=self, reset_type=reset_type)
        
        # Default behaviour if the delegate didn't handle it.
        if not self._reset_catch_delegate_result:
            # Halt the target.
            self.halt()

        jdecpid = self.read_memory(0xF0000FE0)
        print("JDEC PID " + str(jdecpid))

        if((jdecpid & 0xf0) == 0xc0):
            print("Ambiq Apollo3")
            bootldr = self.read_memory(0x400401A0)
            if ((bootldr & 0x0C000000) == 0x04000000):
                print("Secure Part.")
                secure = True
        
        if(secure):
            scratch0 = self.read_memory(0x400401B0)
            print("scratch0 = "+ str(scratch0))
            self.write_memory(0x400401B0, (scratch0 | 0x1))
            print("wrote " + str(scratch0 | 0x1) + " to scratch0")
        else:
            print("I havent wrtten non secure yet")
class AMA3B1KK(CoreSightTarget):
    
    VENDOR = "Ambiq Micro"
    CortexM_Core = Apollo3

    memoryMap = MemoryMap(
        FlashRegion(start=0x00000000, length=0x10000000, sector_size=0x2000,
                        page_size=0x200,
                        is_boot_memory=True,
                        algo=flash_algo),
        RamRegion(  start=0x10000000,  length=0x60000)
        )

    def __init__(self, link):
        self.DEFAULT_ACQUIRE_TIMEOUT = 25.0
        print("HELLO __init___ THEJERJEIDKDFJ")
        #CortexM_Core = CortexM_Core
        super(AMA3B1KK, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile.from_builtin("ama3b1kk.svd")
        #seq.wrap_task('create_cores', self.setup_CC3220SF_core)

    def create_init_sequence(self):
        seq = super(AMA3B1KK, self).create_init_sequence()
        seq.replace_task('create_cores', self.create_ap3_core)
        return seq

    def create_ap3_core(self):
        print(self.aps)
        core = self.CortexM_Core(self.session, self.aps[0], self.memory_map, 0, self.DEFAULT_ACQUIRE_TIMEOUT)
        core.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[0].core = core
        core.init()
        self.add_core(core)

    # def create_psoc_core(self):
    #     core = self.CoretxM_Core(self.session, self.aps[self.AP_NUM], self.memory_map, 0, self.DEFAULT_ACQUIRE_TIMEOUT)
    #     core.default_reset_type = self.ResetType.SW_SYSRESETREQ
    #     self.aps[self.AP_NUM].core = core
    #     core.init()
    #     self.add_core(core)

    def resetn(self):
        """
        reset a core. After a call to this function, the core
        is running
        """
        print("HELLO reset sequence")
        self.reset()

    #def will_reset(self, core, reset_type):


