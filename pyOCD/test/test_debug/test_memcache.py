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

from pyOCD.debug.cache import MemoryCache
from pyOCD.debug.context import DebugContext
from pyOCD.core import memory_map
from pyOCD.utility import conversion
from pyOCD.utility import mask
import pytest
import logging

@pytest.fixture(scope='module', autouse=True)
def debuglog():
    logging.basicConfig(level=logging.DEBUG)

class MockCore(object):
    def __init__(self):
        self.run_token = 1
        self.flash_region = memory_map.FlashRegion(start=0, length=1*1024, blocksize=1024, name='flash')
        self.ram_region = memory_map.RamRegion(start=0x20000000, length=1*1024, name='ram')
        self.ram2_region = memory_map.RamRegion(start=0x20000400, length=1*1024, name='ram2', isCacheable=False)
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

    def isRunning(self):
        return False

    def readMemory(self, addr, transfer_size=32, now=True):
        if transfer_size == 8:
            return 0x12
        elif transfer_size == 16:
            return 0x1234
        elif transfer_size == 32:
            return 0x12345678

    def readBlockMemoryUnaligned8(self, addr, size):
        for r, m in self.regions:
            if r.containsRange(addr, length=size):
                addr -= r.start
                return list(m[addr:addr+size])
        return [0x55] * size

    def readBlockMemoryAligned32(self, addr, size):
        return conversion.byteListToU32leList(self.readBlockMemoryUnaligned8(addr, size*4))

    def writeMemory(self, addr, value, transfer_size=32):
        return True

    def writeBlockMemoryUnaligned8(self, addr, value):
        for r, m in self.regions:
            if r.containsRange(addr, length=len(value)):
                addr -= r.start
                m[addr:addr+len(value)] = value
                return True
        return False

    def writeBlockMemoryAligned32(self, addr, data):
        return self.writeBlockMemoryUnaligned8(addr, conversion.u32leListToByteList(data))

@pytest.fixture(scope='function')
def mockcore():
    return MockCore()

@pytest.fixture(scope='function')
def memcache(mockcore):
    return MemoryCache(DebugContext(mockcore))

# Basic tests of MockCore memory simulation.
class TestMockCore:
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

class TestMemoryCache:
    def test_1(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, [0x10, 0x12, 0x14, 0x16])
        assert memcache.readBlockMemoryUnaligned8(0, 4) == [0x10, 0x12, 0x14, 0x16]

    def test_2(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, [0x10, 0x12, 0x14, 0x16])
        assert memcache.readBlockMemoryUnaligned8(0, 4) == [0x10, 0x12, 0x14, 0x16]
        assert memcache.readBlockMemoryUnaligned8(2, 4) == [0x14, 0x16, 0xff, 0xff]

    def test_3(self, mockcore, memcache):
        memcache.writeBlockMemoryAligned32(0, [0x10121416])
        assert memcache.readBlockMemoryAligned32(0, 1) == [0x10121416]
        assert memcache.readBlockMemoryUnaligned8(2, 4) == [0x12, 0x10, 0xff, 0xff]

    def test_4(self, mockcore, memcache):
        mockcore.writeBlockMemoryUnaligned8(0, [1, 2, 3, 4])
        assert memcache.readBlockMemoryUnaligned8(0, 8) == [1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff]
        assert memcache.readBlockMemoryUnaligned8(4, 4) == [0xff] * 4
        mockcore.writeBlockMemoryUnaligned8(10, [50, 51])
        assert memcache.readBlockMemoryUnaligned8(6, 6) == [0xff, 0xff, 0xff, 0xff, 50, 51]

    def test_5(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, [1, 2])
        memcache.writeBlockMemoryUnaligned8(4, [3, 4])
        assert memcache.readBlockMemoryUnaligned8(0, 8) == [1, 2, 0xff, 0xff, 3, 4, 0xff, 0xff]

    def test_6_middle_cached(self, mockcore, memcache):
        mockcore.writeBlockMemoryUnaligned8(0, [50, 51, 52, 53, 54, 55, 56, 57])
        memcache.writeBlockMemoryUnaligned8(4, [3, 4])
        assert memcache.readBlockMemoryUnaligned8(0, 8) == [50, 51, 52, 53, 3, 4, 56, 57]

    def test_7_odd_cached(self, mockcore, memcache):
        mockcore.writeBlockMemoryUnaligned8(0, [50, 51, 52, 53, 54, 55, 56, 57])
        memcache.writeBlockMemoryUnaligned8(1, [1])
        memcache.writeBlockMemoryUnaligned8(3, [2])
        memcache.writeBlockMemoryUnaligned8(5, [3])
        memcache.writeBlockMemoryUnaligned8(7, [4])
        assert memcache.readBlockMemoryUnaligned8(0, 8) == [50, 1, 52, 2, 54, 3, 56, 4]

    def test_8_no_overlap(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, [1, 2, 3, 4])
        assert memcache.readBlockMemoryUnaligned8(8, 4) == [0xff] * 4

    def test_9_begin_overlap(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(4, range(8))
        assert memcache.readBlockMemoryUnaligned8(0, 8) == [0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3]

    def test_10_end_overlap(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, range(8))
        assert memcache.readBlockMemoryUnaligned8(4, 8) == [4, 5, 6, 7, 0xff, 0xff, 0xff, 0xff]

    def test_11_full_overlap(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, range(8))
        assert memcache.readBlockMemoryUnaligned8(0, 8) == range(8)

    def test_12_begin(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(8, [1, 2, 3, 4])
        assert memcache.readBlockMemoryUnaligned8(7, 1) == [0xff]
        assert memcache.readBlockMemoryUnaligned8(8, 1) == [1]

    def test_13_end(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0, [1, 2, 3, 4])
        assert memcache.readBlockMemoryUnaligned8(3, 1) == [4]
        assert memcache.readBlockMemoryUnaligned8(4, 1) == [0xff]

    def test_14_write_begin_ragged_cached(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(4, [1, 2, 3, 4])
        mockcore.writeBlockMemoryUnaligned8(8, [90, 91, 92, 93])
        memcache.writeBlockMemoryUnaligned8(6, [55, 56, 57, 58])
        assert memcache.readBlockMemoryUnaligned8(4, 8) == [1, 2, 55, 56, 57, 58, 92, 93]

    def test_15_write_end_ragged_cached(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(4, [1, 2, 3, 4])
        mockcore.writeBlockMemoryUnaligned8(0, [90, 91, 92, 93])
        memcache.writeBlockMemoryUnaligned8(2, [55, 56, 57, 58])
        assert memcache.readBlockMemoryUnaligned8(0, 8) == [90, 91, 55, 56, 57, 58, 3, 4]

    def test_16_no_mem_region(self, mockcore, memcache):
        assert memcache.readBlockMemoryUnaligned8(0x30000000, 4) == [0x55] * 4
        # Make sure we didn't cache anything.
        assert memcache._cache.search(0x30000000, 0x30000004) == set()

    def test_17_noncacheable_region_read(self, mockcore, memcache):
        mockcore.writeBlockMemoryUnaligned8(0x20000410, [90, 91, 92, 93])
        assert memcache.readBlockMemoryUnaligned8(0x20000410, 4) == [90, 91, 92, 93]
        # Make sure we didn't cache anything.
        assert memcache._cache.search(0x20000410, 0x20000414) == set()

    def test_18_noncacheable_region_write(self, mockcore, memcache):
        memcache.writeBlockMemoryUnaligned8(0x20000410, [1, 2, 3, 4])
        mockcore.writeBlockMemoryUnaligned8(0x20000410, [90, 91, 92, 93])
        assert memcache.readBlockMemoryUnaligned8(0x20000410, 4) == [90, 91, 92, 93]
        # Make sure we didn't cache anything.
        assert memcache._cache.search(0x20000410, 0x20000414) == set()

    def test_19_write_into_cached(self, mockcore, memcache):
        mockcore.writeBlockMemoryUnaligned8(4, [1, 2, 3, 4, 5, 6, 7, 8])
        assert memcache.readBlockMemoryUnaligned8(4, 8) == [1, 2, 3, 4, 5, 6, 7, 8]
        memcache.writeBlockMemoryUnaligned8(6, [128, 129, 130, 131])
        assert memcache.readBlockMemoryUnaligned8(4, 8) == [1, 2, 128, 129, 130, 131, 7, 8]
        assert len(list(memcache._cache.search(4, 12))[0].data) == 8

    def test_20_empty_read(self, memcache):
        assert memcache.readBlockMemoryUnaligned8(128, 0) == []

    def test_21_empty_write(self, memcache):
        memcache.writeBlockMemoryUnaligned8(128, [])

# TODO test read32/16/8 with and without callbacks

