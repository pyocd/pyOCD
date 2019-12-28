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

from .mockcore import MockCore

from pyocd.core import memory_map
from pyocd.coresight.cortex_m_core_registers import index_for_reg
from pyocd.utility import conversion
from pyocd.utility import mask

# @pytest.fixture(scope='function')
# def mockcore():
#     return MockCore()

# Basic tests of MockCore memory simulation.
class TestMockCoreMem:
    def test_read8_flash(self, mockcore):
        assert mockcore.read_memory_block8(0, 4) == [0xff, 0xff, 0xff, 0xff]

    def test_read8_ram(self, mockcore):
        assert mockcore.read_memory_block8(0x20000000, 4) == [0, 0, 0, 0]

    def test_read32_flash(self, mockcore):
        assert mockcore.read_memory_block32(0, 1) == [0xffffffff]

    def test_read32_ram(self, mockcore):
        assert mockcore.read_memory_block32(0x20000000, 1) == [0x00000000]

    def test_write8_flash(self, mockcore):
        mockcore.write_memory_block8(0x100, [0xaa, 0xbb, 0xcc, 0xdd])
        assert mockcore.read_memory_block8(0xfe, 8) == [0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xff, 0xff]

    def test_write32_flash(self, mockcore):
        mockcore.write_memory_block32(0x100, [0xaabbccdd])
        assert mockcore.read_memory_block32(0xfc, 3) == [0xffffffff, 0xaabbccdd, 0xffffffff]

    def test_write8_ram(self, mockcore):
        mockcore.write_memory_block8(0x20000100, [0xaa, 0xbb, 0xcc, 0xdd])
        assert mockcore.read_memory_block8(0x200000fe, 8) == [0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00]

    def test_write32_ram(self, mockcore):
        mockcore.write_memory_block32(0x20000100, [0xaabbccdd])
        assert mockcore.read_memory_block32(0x200000fc, 3) == [0x00000000, 0xaabbccdd, 0x00000000]

# Basic tests of MockCore register simulation.
class TestMockCoreReg:
    def test_rw_r0_r15(self, mockcore):
        for r in range(0, 16):
            mockcore.write_core_registers_raw([r], [1+r])
        for r in range(0, 16):
            assert mockcore.read_core_registers_raw([r]) == [1+r]
    
    def test_rw_cfbp(self, mockcore):
        mockcore.write_core_registers_raw([index_for_reg('cfbp')], [0x01020304])
        assert mockcore.read_core_registers_raw([
                index_for_reg('control'),
                index_for_reg('faultmask'),
                index_for_reg('basepri'),
                index_for_reg('primask')]) == [0x01, 0x02, 0x03, 0x04]

    def test_w_control(self, mockcore):
        mockcore.write_core_registers_raw([index_for_reg('control')], [0xaa])
        assert mockcore.read_core_registers_raw([index_for_reg('cfbp')]) == [0xaa000000]

    def test_w_faultmask(self, mockcore):
        mockcore.write_core_registers_raw([index_for_reg('faultmask')], [0xaa])
        mockcore.read_core_registers_raw([index_for_reg('cfbp')]) == [0x00aa0000]

    def test_w_basepri(self, mockcore):
        mockcore.write_core_registers_raw([index_for_reg('basepri')], [0xaa])
        mockcore.read_core_registers_raw([index_for_reg('cfbp')]) == [0x0000aa00]

    def test_w_primask(self, mockcore):
        mockcore.write_core_registers_raw([index_for_reg('primask')], [0xaa])
        mockcore.read_core_registers_raw([index_for_reg('cfbp')]) == [0x000000aa]

