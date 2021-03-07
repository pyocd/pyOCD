# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

import pytest
import logging

from pyocd.debug.cache import MemoryCache
from pyocd.debug.context import DebugContext
from pyocd.coresight.component import CoreSightCoreComponent
from pyocd.core.core_registers import CoreRegistersIndex
from pyocd.core.memory_interface import MemoryInterface
from pyocd.coresight.cortex_m_core_registers import (
    CortexMCoreRegisterInfo,
    CoreRegisterGroups,
    index_for_reg,
)
from pyocd.core import memory_map
from pyocd.utility import conversion
from pyocd.utility import mask

CFBP_INDEX = index_for_reg('cfbp')
XPSR_INDEX = index_for_reg('xpsr')

class MockCore(CoreSightCoreComponent, MemoryInterface):
    def __init__(self, has_fpu=True):
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
        self.has_fpu = has_fpu
        self.core_registers = CoreRegistersIndex()
        self.core_registers.add_group(CoreRegisterGroups.M_PROFILE_COMMON
                + CoreRegisterGroups.V7M_v8M_ML_ONLY
                + CoreRegisterGroups.V8M_SEC_ONLY)
        if has_fpu:
            self.core_registers.add_group(CoreRegisterGroups.VFP_V5)
        self.clear_all_regs()
    
    def clear_all_regs(self):
        self.regs = {i:0 for i in self.core_registers.by_index.keys()} # r0-15, xpsr, msp, psp
        self.regs[CFBP_INDEX] = 0

    def is_running(self):
        return False

    def read_core_registers_raw(self, reg_list):
        reg_list = [CortexMCoreRegisterInfo.register_name_to_index(reg) for reg in reg_list]
        results = []
        for r in reg_list:
            if CortexMCoreRegisterInfo.get(r).is_cfbp_subregister:
                v = self.regs[CFBP_INDEX]
                v = (v >> ((-r - 1) * 8)) & 0xff
            elif CortexMCoreRegisterInfo.get(r).is_psr_subregister:
                v = self.regs[XPSR_INDEX]
                v &= CortexMCoreRegisterInfo.get(r).psr_mask
            else:
                if r not in self.regs:
                    self.regs[r] = 0
                v = self.regs[r]
            results.append(v)
#         logging.info("mockcore[%x]:read(%s)=%s", id(self), reg_list, results)
        return results

    def write_core_registers_raw(self, reg, data):
        reg = [CortexMCoreRegisterInfo.register_name_to_index(r) for r in reg]
#         logging.info("mockcore[%x]:write(%s, %s)", id(self), reg, data)
        for r, v in zip(reg, data):
            if CortexMCoreRegisterInfo.get(r).is_cfbp_subregister:
                shift = (-r - 1) * 8
                mask = 0xffffffff ^ (0xff << shift)
                data = (self.regs[CFBP_INDEX] & mask) | ((v & 0xff) << shift)
                self.regs[CFBP_INDEX] = data
            elif CortexMCoreRegisterInfo.get(r).is_psr_subregister:
                mask = CortexMCoreRegisterInfo.get(r).psr_mask
                data = (self.regs[XPSR_INDEX] & (0xffffffff ^ mask)) | (v & mask)
                self.regs[XPSR_INDEX] = data
            else:
                self.regs[r] = v

    def check_reg_list(self, reg_list):
        # Copied from CortexM.
        for reg in reg_list:
            if reg not in self.core_registers.by_index:
                # Invalid register, try to give useful error. An invalid name will already
                # have raised a KeyError above.
                info = CortexMCoreRegisterInfo.get(reg)
                if info.is_fpu_register and (not self.has_fpu):
                    raise KeyError("attempt to read FPU register %s without FPU", info.name)
                else:
                    raise KeyError("register %s not available in this CPU", info.name)

    def read_memory(self, addr, transfer_size=32, now=True):
        assert now is True
        bytes_data = self.read_memory_block8(addr, transfer_size // 8)
        return conversion.byte_list_to_nbit_le_list(bytes_data, transfer_size)[0]

    def read_memory_block8(self, addr, size):
        for r, m in self.regions:
            if r.contains_range(addr, length=size):
                addr -= r.start
                return list(m[addr:addr+size])
        return [0x55] * size

    def read_memory_block32(self, addr, size):
        return conversion.byte_list_to_u32le_list(self.read_memory_block8(addr, size*4))

    def write_memory(self, addr, value, transfer_size=32):
        bytes_data = conversion.nbit_le_list_to_byte_list([value], transfer_size)
        return self.write_memory_block8(addr, bytes_data)

    def write_memory_block8(self, addr, value):
        for r, m in self.regions:
            if r.contains_range(addr, length=len(value)):
                addr -= r.start
                m[addr:addr+len(value)] = value
                return True
        return False

    def write_memory_block32(self, addr, data):
        return self.write_memory_block8(addr, conversion.u32le_list_to_byte_list(data))


