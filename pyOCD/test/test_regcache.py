"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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

from pyOCD.debug.cache import RegisterCache
from pyOCD.debug.context import DebugContext
from pyOCD.coresight.cortex_m import (CORE_REGISTER, register_name_to_index)
from pyOCD.core import memory_map
from pyOCD.utility import conversion
from pyOCD.utility import mask
import pytest
import logging

@pytest.fixture(scope='function')
def regcache(mockcore):
    return RegisterCache(DebugContext(mockcore))

# Copy of the register list without CFBP.
CORE_REGS_NO_CFBP = CORE_REGISTER.copy()
CORE_REGS_NO_CFBP.pop('cfbp')

def get_expected_reg_value(r):
    i = register_name_to_index(r)
    if i < 0:
        i += 100
    return i + 1

def get_expected_cfbp():
    return ((get_expected_reg_value('control') << 24) |
            (get_expected_reg_value('faultmask') << 16) |
            (get_expected_reg_value('basepri') << 8) |
            get_expected_reg_value('primask'))

class TestRegisterCache:
    def set_core_regs(self, mockcore, modifier=0):
        for r in CORE_REGS_NO_CFBP:
            mockcore.writeCoreRegistersRaw([r], [get_expected_reg_value(r) + modifier])
            assert mockcore.readCoreRegistersRaw([r]) == [get_expected_reg_value(r) + modifier]
        
    def test_r_1(self, mockcore, regcache):
        assert regcache.readCoreRegistersRaw(['r0']) == [0] # cache initial value of 0
        mockcore.writeCoreRegistersRaw(['r0'], [1234]) # modify reg behind the cache's back
        assert mockcore.readCoreRegistersRaw(['r0']) == [1234] # verify modified reg
        assert regcache.readCoreRegistersRaw(['r0']) == [0] # should return cached 0 value
        regcache.invalidate() # explicitly invalidate cache
        assert mockcore.readCoreRegistersRaw(['r0']) == [1234] # verify modified reg
        assert regcache.readCoreRegistersRaw(['r0']) == [1234] # now should return updated 1234 value
        
    def test_run_token(self, mockcore, regcache):
        assert regcache.readCoreRegistersRaw(['r0']) == [0] # cache initial value of 0
        mockcore.writeCoreRegistersRaw(['r0'], [1234]) # modify reg behind the cache's back
        assert mockcore.readCoreRegistersRaw(['r0']) == [1234] # verify modified reg
        assert regcache.readCoreRegistersRaw(['r0']) == [0] # should return cached 0 value
        mockcore.run_token += 1 # bump run token to cause cache to invalidate
        assert regcache.readCoreRegistersRaw(['r0']) == [1234] # now should return updated 1234 value

    def test_reading_from_core(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        for r in CORE_REGS_NO_CFBP:
            assert regcache.readCoreRegistersRaw([r]) == [get_expected_reg_value(r)]

    def test_read_cached(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        # cache all regs
        regcache.readCoreRegistersRaw(CORE_REGS_NO_CFBP.values())
        # modify regs in mock core
        self.set_core_regs(mockcore, 7)
        # cache should return original unmodified values
        for r in CORE_REGS_NO_CFBP:
            assert regcache.readCoreRegistersRaw([r]) == [get_expected_reg_value(r)]

    def test_read_cfbp(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert regcache.readCoreRegistersRaw(['cfbp', 'control', 'faultmask']) == [
            get_expected_cfbp(), get_expected_reg_value('control'), get_expected_reg_value('faultmask')
            ]

    def test_read_cached_cfbp(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        # cache it
        regcache.readCoreRegistersRaw(['cfbp'])
        # modify behind the cache's back
        mockcore.writeCoreRegistersRaw(['control', 'primask'], [0x55, 0xaa])
        # cache should return original value
        assert regcache.readCoreRegistersRaw(['cfbp']) == [get_expected_cfbp()]
    
    def test_write_1(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert mockcore.readCoreRegistersRaw(['r0']) == [get_expected_reg_value('r0')]
        assert regcache.readCoreRegistersRaw(['r0']) == [get_expected_reg_value('r0')]
        regcache.writeCoreRegistersRaw(['r0'], [1234])
        assert mockcore.readCoreRegistersRaw(['r0']) == [1234]
        assert regcache.readCoreRegistersRaw(['r0']) == [1234]
    
    def test_write_regs(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        for r in CORE_REGS_NO_CFBP:
            regcache.writeCoreRegistersRaw([r], [get_expected_reg_value(r) + 7])
        for r in CORE_REGS_NO_CFBP:
            assert mockcore.readCoreRegistersRaw([r]) == [get_expected_reg_value(r) + 7]
     
    def test_write_cfbp(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert mockcore.readCoreRegistersRaw(['cfbp']) == [get_expected_cfbp()]
        regcache.writeCoreRegistersRaw(['control', 'primask'], [3, 19])
        assert mockcore.readCoreRegistersRaw(['control', 'primask', 'cfbp']) == [
            3, 19,
            ((3 << 24) | (get_expected_reg_value('faultmask') << 16) |
            (get_expected_reg_value('basepri') << 8) | 19)
            ]
   
    def test_invalid_reg_r(self, regcache):
        with pytest.raises(ValueError):
            regcache.readCoreRegistersRaw([132423])

    def test_invalid_reg_w(self, regcache):
        with pytest.raises(ValueError):
            regcache.writeCoreRegistersRaw([132423], [1234])
    
    def test_invalid_fpu_reg_r(self, mockcore, regcache):
        mockcore.has_fpu = False
        with pytest.raises(ValueError):
            regcache.readCoreRegistersRaw(['s1'])
    
    def test_invalid_fpu_reg_w(self, mockcore, regcache):
        mockcore.has_fpu = False
        with pytest.raises(ValueError):
            regcache.writeCoreRegistersRaw(['s1'], [1.234])

            



