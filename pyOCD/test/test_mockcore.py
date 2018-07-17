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

from pyOCD.core import memory_map
from pyOCD.coresight.cortex_m import CORE_REGISTER
from pyOCD.utility import conversion
from pyOCD.utility import mask
import pytest
import logging
from .mockcore import MockCore

# @pytest.fixture(scope='function')
# def mockcore():
#     return MockCore()

# Basic tests of MockCore memory simulation.
class TestMockCoreMem:
    def test_read8_flash(self, mockcore):
        assert mockcore.readBlockMemoryUnaligned8(0, 4) == [0xff, 0xff, 0xff, 0xff]

    def test_read8_ram(self, mockcore):
        assert mockcore.readBlockMemoryUnaligned8(0x20000000, 4) == [0, 0, 0, 0]

    def test_read32_flash(self, mockcore):
        assert mockcore.readBlockMemoryAligned32(0, 1) == [0xffffffff]

    def test_read32_ram(self, mockcore):
        assert mockcore.readBlockMemoryAligned32(0x20000000, 1) == [0x00000000]

    def test_write8_flash(self, mockcore):
        mockcore.writeBlockMemoryUnaligned8(0x100, [0xaa, 0xbb, 0xcc, 0xdd])
        assert mockcore.readBlockMemoryUnaligned8(0xfe, 8) == [0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xff, 0xff]

    def test_write32_flash(self, mockcore):
        mockcore.writeBlockMemoryAligned32(0x100, [0xaabbccdd])
        assert mockcore.readBlockMemoryAligned32(0xfc, 3) == [0xffffffff, 0xaabbccdd, 0xffffffff]

    def test_write8_ram(self, mockcore):
        mockcore.writeBlockMemoryUnaligned8(0x20000100, [0xaa, 0xbb, 0xcc, 0xdd])
        assert mockcore.readBlockMemoryUnaligned8(0x200000fe, 8) == [0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00]

    def test_write32_ram(self, mockcore):
        mockcore.writeBlockMemoryAligned32(0x20000100, [0xaabbccdd])
        assert mockcore.readBlockMemoryAligned32(0x200000fc, 3) == [0x00000000, 0xaabbccdd, 0x00000000]

# Basic tests of MockCore register simulation.
class TestMockCoreReg:
    def test_rw_r0_r15(self, mockcore):
        for r in range(0, 16):
            mockcore.writeCoreRegistersRaw([r], [1+r])
        for r in range(0, 16):
            assert mockcore.readCoreRegistersRaw([r]) == [1+r]
    
    def test_rw_cfbp(self, mockcore):
        mockcore.writeCoreRegistersRaw([CORE_REGISTER['cfbp']], [0x01020304])
        assert mockcore.readCoreRegistersRaw([CORE_REGISTER['control'], CORE_REGISTER['faultmask'], CORE_REGISTER['basepri'], CORE_REGISTER['primask']]) == [0x01, 0x02, 0x03, 0x04]

    def test_w_control(self, mockcore):
        mockcore.writeCoreRegistersRaw([CORE_REGISTER['control']], [0xaa])
        assert mockcore.readCoreRegistersRaw([CORE_REGISTER['cfbp']]) == [0xaa000000]

    def test_w_faultmask(self, mockcore):
        mockcore.writeCoreRegistersRaw([CORE_REGISTER['faultmask']], [0xaa])
        mockcore.readCoreRegistersRaw([CORE_REGISTER['cfbp']]) == [0x00aa0000]

    def test_w_basepri(self, mockcore):
        mockcore.writeCoreRegistersRaw([CORE_REGISTER['basepri']], [0xaa])
        mockcore.readCoreRegistersRaw([CORE_REGISTER['cfbp']]) == [0x0000aa00]

    def test_w_primask(self, mockcore):
        mockcore.writeCoreRegistersRaw([CORE_REGISTER['primask']], [0xaa])
        mockcore.readCoreRegistersRaw([CORE_REGISTER['cfbp']]) == [0x000000aa]

