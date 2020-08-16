# pyOCD debugger
# Copyright (c) 2016-2019 Arm Limited
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

from pyocd.cache.register import RegisterCache
from pyocd.debug.context import DebugContext
from pyocd.coresight.cortex_m import CortexM
from pyocd.coresight.cortex_m_core_registers import CortexMCoreRegisterInfo
from pyocd.core import memory_map
from pyocd.utility import conversion
from pyocd.utility import mask

@pytest.fixture(scope='function')
def regcache(mockcore):
    return RegisterCache(DebugContext(mockcore), mockcore)

@pytest.fixture(scope='function')
def regcache_no_fpu(mockcore_no_fpu):
    return RegisterCache(DebugContext(mockcore_no_fpu), mockcore_no_fpu)

COMPOSITES = [
    'cfbp',
    'xpsr',
    'iapsr',
    'eapsr',
    'iepsr',
    ]

# Appropriate modifiers for masked registers - others modified by adding 7
REG_MODIFIER = {
    'apsr': 0x30010000,
    'epsr': 0x01000C00,
}

# Return list of reg names from the core, excluding composite regs.
def core_regs_composite_regs(core):
    return list(r for r in core.core_registers.by_name.keys() if r not in COMPOSITES)

def get_modifier(r):
    return REG_MODIFIER.get(r, 7)

def get_expected_reg_value(r):
    i = CortexMCoreRegisterInfo.register_name_to_index(r)
    if CortexMCoreRegisterInfo.get(i).is_psr_subregister:
        return 0x55555555 & CortexMCoreRegisterInfo.get(i).psr_mask
    if i < 0:
        i += 100
    return i + 1

def get_expected_cfbp():
    return ((get_expected_reg_value('control') << 24) |
            (get_expected_reg_value('faultmask') << 16) |
            (get_expected_reg_value('basepri') << 8) |
            get_expected_reg_value('primask'))

def get_expected_xpsr():
    return (get_expected_reg_value('apsr') |
            get_expected_reg_value('ipsr') |
            get_expected_reg_value('epsr'))

class TestRegisterCache:
    def set_core_regs(self, mockcore, modify=False):
        for r in core_regs_composite_regs(mockcore):
            if modify:
                modifier = get_modifier(r)
            else:
                modifier = 0
            mockcore.write_core_registers_raw([r], [get_expected_reg_value(r) + modifier])
            assert mockcore.read_core_registers_raw([r]) == [get_expected_reg_value(r) + modifier]
        
    def test_r_1(self, mockcore, regcache):
        assert regcache.read_core_registers_raw(['r0']) == [0] # cache initial value of 0
        mockcore.write_core_registers_raw(['r0'], [1234]) # modify reg behind the cache's back
        assert mockcore.read_core_registers_raw(['r0']) == [1234] # verify modified reg
        assert regcache.read_core_registers_raw(['r0']) == [0] # should return cached 0 value
        regcache.invalidate() # explicitly invalidate cache
        assert mockcore.read_core_registers_raw(['r0']) == [1234] # verify modified reg
        assert regcache.read_core_registers_raw(['r0']) == [1234] # now should return updated 1234 value
        
    def test_run_token(self, mockcore, regcache):
        assert regcache.read_core_registers_raw(['r0']) == [0] # cache initial value of 0
        mockcore.write_core_registers_raw(['r0'], [1234]) # modify reg behind the cache's back
        assert mockcore.read_core_registers_raw(['r0']) == [1234] # verify modified reg
        assert regcache.read_core_registers_raw(['r0']) == [0] # should return cached 0 value
        mockcore.run_token += 1 # bump run token to cause cache to invalidate
        assert regcache.read_core_registers_raw(['r0']) == [1234] # now should return updated 1234 value

    def test_reading_from_core(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        for r in core_regs_composite_regs(mockcore):
            assert regcache.read_core_registers_raw([r]) == [get_expected_reg_value(r)]

    def test_read_cached(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        # cache all regs
        regcache.read_core_registers_raw(core_regs_composite_regs(mockcore))
        # modify regs in mock core
        self.set_core_regs(mockcore, True)
        # cache should return original unmodified values
        for r in core_regs_composite_regs(mockcore):
            assert regcache.read_core_registers_raw([r]) == [get_expected_reg_value(r)]

    def test_read_cfbp(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert regcache.read_core_registers_raw(['cfbp', 'control', 'faultmask']) == [
            get_expected_cfbp(), get_expected_reg_value('control'), get_expected_reg_value('faultmask')
            ]

    def test_read_xpsr(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert regcache.read_core_registers_raw(['xpsr', 'ipsr', 'apsr', 'eapsr']) == [
            get_expected_xpsr(), get_expected_reg_value('ipsr'),
            get_expected_reg_value('apsr'), get_expected_reg_value('eapsr')
            ]

    def test_read_cached_cfbp(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        # cache it
        regcache.read_core_registers_raw(['cfbp'])
        # modify behind the cache's back
        mockcore.write_core_registers_raw(['control', 'primask'], [0x55, 0xaa])
        # cache should return original value
        assert regcache.read_core_registers_raw(['cfbp']) == [get_expected_cfbp()]
    
    def test_read_cached_xpsr(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        # cache it
        regcache.read_core_registers_raw(['xpsr'])
        # modify behind the cache's back
        mockcore.write_core_registers_raw(['ipsr', 'apsr'], [0x22, 0x10000000])
        # cache should return original value
        assert regcache.read_core_registers_raw(['xpsr']) == [get_expected_xpsr()]

    def test_write_1(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert mockcore.read_core_registers_raw(['r0']) == [get_expected_reg_value('r0')]
        assert regcache.read_core_registers_raw(['r0']) == [get_expected_reg_value('r0')]
        regcache.write_core_registers_raw(['r0'], [1234])
        assert mockcore.read_core_registers_raw(['r0']) == [1234]
        assert regcache.read_core_registers_raw(['r0']) == [1234]
    
    def test_write_regs(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        for r in core_regs_composite_regs(mockcore):
            regcache.write_core_registers_raw([r], [get_expected_reg_value(r) + get_modifier(r)])
        for r in core_regs_composite_regs(mockcore):
            assert mockcore.read_core_registers_raw([r]) == [get_expected_reg_value(r) + get_modifier(r)]
     
    def test_write_cfbp(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert mockcore.read_core_registers_raw(['cfbp']) == [get_expected_cfbp()]
        regcache.write_core_registers_raw(['control', 'primask'], [3, 19])
        assert mockcore.read_core_registers_raw(['control', 'primask', 'cfbp']) == [
            3, 19,
            ((3 << 24) | (get_expected_reg_value('faultmask') << 16) |
            (get_expected_reg_value('basepri') << 8) | 19)
            ]
   
    def test_write_xpsr(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert mockcore.read_core_registers_raw(['xpsr']) == [get_expected_xpsr()]
        regcache.write_core_registers_raw(['iapsr'], [0x10000022])
        assert mockcore.read_core_registers_raw(['ipsr', 'apsr', 'iapsr', 'xpsr']) == [
            0x22, 0x10000000, 0x10000022,
            0x10000022 | get_expected_reg_value('epsr')
            ]

    def test_write_full_xpsr(self, mockcore, regcache):
        self.set_core_regs(mockcore)
        assert mockcore.read_core_registers_raw(['xpsr']) == [get_expected_xpsr()]
        regcache.write_core_registers_raw(['xpsr'], [0xffffffff])
        assert mockcore.read_core_registers_raw(['ipsr', 'apsr', 'epsr', 'xpsr']) == [
            CortexM.IPSR_MASK, CortexM.APSR_MASK, CortexM.EPSR_MASK,
            0xffffffff
            ]

    def test_invalid_reg_r(self, regcache):
        with pytest.raises(KeyError):
            regcache.read_core_registers_raw([132423])

    def test_invalid_reg_w(self, regcache):
        with pytest.raises(KeyError):
            regcache.write_core_registers_raw([132423], [1234])
    
    def test_invalid_fpu_reg_r(self, regcache_no_fpu):
        with pytest.raises(KeyError):
            regcache_no_fpu.read_core_registers_raw(['s1'])
    
    def test_invalid_fpu_reg_w(self, regcache_no_fpu):
        with pytest.raises(KeyError):
            regcache_no_fpu.write_core_registers_raw(['s1'], [1.234])

            



