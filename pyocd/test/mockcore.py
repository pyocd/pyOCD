"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2017 ARM Limited

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

from pyocd.debug.cache import MemoryCache
from pyocd.debug.context import DebugContext
from pyocd.coresight.cortex_m import (
    CORE_REGISTER,
    register_name_to_index,
    is_cfbp_subregister,
    is_psr_subregister,
    sysm_to_psr_mask
)
from pyocd.core import memory_map
from pyocd.utility import conversion
from pyocd.utility import mask
import pytest
import logging

class MockCore(object):
    def __init__(self):
        self.run_token = 1
        self.flash_region = memory_map.FlashRegion(start=0, length=1*1024, blocksize=1024, name='flash')
        self.ram_region = memory_map.RamRegion(start=0x20000000, length=1*1024, name='ram')
        self.ram2_region = memory_map.RamRegion(start=0x20000400, length=1*1024, name='ram2', is_cacheable=False)
        self.memory_map = memory_map.MemoryMap(
            self.flash_region,
            self.ram_region,
            self.ram2_region
            )
        self.ram = bytearray(1024)
        self.ram2 = bytearray(1024)
        self.flash = bytearray([0xff]) * 1024
        self.regions = [(self.flash_region, self.flash),
                        (self.ram_region, self.ram),
                        (self.ram2_region, self.ram2)]
        self.has_fpu = True
        self.clear_all_regs()
    
    def clear_all_regs(self):
        self.regs = {i:0 for i in range(0, 19)} # r0-15, xpsr, msp, psp
        self.regs[CORE_REGISTER['cfbp']] = 0

    def is_running(self):
        return False

    def read_core_registers_raw(self, reg_list):
        reg_list = [register_name_to_index(reg) for reg in reg_list]
        results = []
        for r in reg_list:
            if is_cfbp_subregister(r):
                v = self.regs[CORE_REGISTER['cfbp']]
                v = (v >> ((-r - 1) * 8)) & 0xff
            elif is_psr_subregister(r):
                v = self.regs[CORE_REGISTER['xpsr']]
                v &= sysm_to_psr_mask(r)
            else:
                if r not in self.regs:
                    self.regs[r] = 0
                v = self.regs[r]
            results.append(v)
#         logging.info("mockcore[%x]:read(%s)=%s", id(self), reg_list, results)
        return results

    def write_core_registers_raw(self, reg, data):
        reg = [register_name_to_index(r) for r in reg]
#         logging.info("mockcore[%x]:write(%s, %s)", id(self), reg, data)
        for r, v in zip(reg, data):
            if is_cfbp_subregister(r):
                shift = (-r - 1) * 8
                mask = 0xffffffff ^ (0xff << shift)
                data = (self.regs[CORE_REGISTER['cfbp']] & mask) | ((v & 0xff) << shift)
                self.regs[CORE_REGISTER['cfbp']] = data
            elif is_psr_subregister(r):
                mask = sysm_to_psr_mask(r)
                data = (self.regs[CORE_REGISTER['xpsr']] & (0xffffffff ^ mask)) | (v & mask)
                self.regs[CORE_REGISTER['xpsr']] = data
            else:
                self.regs[r] = v

    def read_memory(self, addr, transfer_size=32, now=True):
        if transfer_size == 8:
            return 0x12
        elif transfer_size == 16:
            return 0x1234
        elif transfer_size == 32:
            return 0x12345678

    def read_memory_block8(self, addr, size):
        for r, m in self.regions:
            if r.contains_range(addr, length=size):
                addr -= r.start
                return list(m[addr:addr+size])
        return [0x55] * size

    def read_memory_block32(self, addr, size):
        return conversion.byte_list_to_u32le_list(self.read_memory_block8(addr, size*4))

    def write_memory(self, addr, value, transfer_size=32):
        return True

    def write_memory_block8(self, addr, value):
        for r, m in self.regions:
            if r.contains_range(addr, length=len(value)):
                addr -= r.start
                m[addr:addr+len(value)] = value
                return True
        return False

    def write_memory_block32(self, addr, data):
        return self.write_memory_block8(addr, conversion.u32le_list_to_byte_list(data))


