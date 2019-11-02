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

from pyocd.cache.memory import MemoryCache
from pyocd.debug.context import DebugContext
from pyocd.core import memory_map
from pyocd.utility import conversion
from pyocd.utility import mask

@pytest.fixture(scope='function')
def memcache(mockcore):
    return MemoryCache(DebugContext(mockcore), mockcore)

class TestMemoryCache:
    def test_1(self, mockcore, memcache):
        memcache.write_memory_block8(0, [0x10, 0x12, 0x14, 0x16])
        assert memcache.read_memory_block8(0, 4) == [0x10, 0x12, 0x14, 0x16]

    def test_2(self, mockcore, memcache):
        memcache.write_memory_block8(0, [0x10, 0x12, 0x14, 0x16])
        assert memcache.read_memory_block8(0, 4) == [0x10, 0x12, 0x14, 0x16]
        assert memcache.read_memory_block8(2, 4) == [0x14, 0x16, 0xff, 0xff]

    def test_3(self, mockcore, memcache):
        memcache.write_memory_block32(0, [0x10121416])
        assert memcache.read_memory_block32(0, 1) == [0x10121416]
        assert memcache.read_memory_block8(2, 4) == [0x12, 0x10, 0xff, 0xff]

    def test_4(self, mockcore, memcache):
        mockcore.write_memory_block8(0, [1, 2, 3, 4])
        assert memcache.read_memory_block8(0, 8) == [1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff]
        assert memcache.read_memory_block8(4, 4) == [0xff] * 4
        mockcore.write_memory_block8(10, [50, 51])
        assert memcache.read_memory_block8(6, 6) == [0xff, 0xff, 0xff, 0xff, 50, 51]

    def test_5(self, mockcore, memcache):
        memcache.write_memory_block8(0, [1, 2])
        memcache.write_memory_block8(4, [3, 4])
        assert memcache.read_memory_block8(0, 8) == [1, 2, 0xff, 0xff, 3, 4, 0xff, 0xff]

    def test_6_middle_cached(self, mockcore, memcache):
        mockcore.write_memory_block8(0, [50, 51, 52, 53, 54, 55, 56, 57])
        memcache.write_memory_block8(4, [3, 4])
        assert memcache.read_memory_block8(0, 8) == [50, 51, 52, 53, 3, 4, 56, 57]

    def test_7_odd_cached(self, mockcore, memcache):
        mockcore.write_memory_block8(0, [50, 51, 52, 53, 54, 55, 56, 57])
        memcache.write_memory_block8(1, [1])
        memcache.write_memory_block8(3, [2])
        memcache.write_memory_block8(5, [3])
        memcache.write_memory_block8(7, [4])
        assert memcache.read_memory_block8(0, 8) == [50, 1, 52, 2, 54, 3, 56, 4]

    def test_8_no_overlap(self, mockcore, memcache):
        memcache.write_memory_block8(0, [1, 2, 3, 4])
        assert memcache.read_memory_block8(8, 4) == [0xff] * 4

    def test_9_begin_overlap(self, mockcore, memcache):
        memcache.write_memory_block8(4, range(8))
        assert memcache.read_memory_block8(0, 8) == [0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3]

    def test_10_end_overlap(self, mockcore, memcache):
        memcache.write_memory_block8(0, range(8))
        assert memcache.read_memory_block8(4, 8) == [4, 5, 6, 7, 0xff, 0xff, 0xff, 0xff]

    def test_11_full_overlap(self, mockcore, memcache):
        memcache.write_memory_block8(0, range(8))
        assert memcache.read_memory_block8(0, 8) == list(range(8))

    def test_12_begin(self, mockcore, memcache):
        memcache.write_memory_block8(8, [1, 2, 3, 4])
        assert memcache.read_memory_block8(7, 1) == [0xff]
        assert memcache.read_memory_block8(8, 1) == [1]

    def test_13_end(self, mockcore, memcache):
        memcache.write_memory_block8(0, [1, 2, 3, 4])
        assert memcache.read_memory_block8(3, 1) == [4]
        assert memcache.read_memory_block8(4, 1) == [0xff]

    def test_14_write_begin_ragged_cached(self, mockcore, memcache):
        memcache.write_memory_block8(4, [1, 2, 3, 4])
        mockcore.write_memory_block8(8, [90, 91, 92, 93])
        memcache.write_memory_block8(6, [55, 56, 57, 58])
        assert memcache.read_memory_block8(4, 8) == [1, 2, 55, 56, 57, 58, 92, 93]

    def test_15_write_end_ragged_cached(self, mockcore, memcache):
        memcache.write_memory_block8(4, [1, 2, 3, 4])
        mockcore.write_memory_block8(0, [90, 91, 92, 93])
        memcache.write_memory_block8(2, [55, 56, 57, 58])
        assert memcache.read_memory_block8(0, 8) == [90, 91, 55, 56, 57, 58, 3, 4]

    def test_16_no_mem_region(self, mockcore, memcache):
        assert memcache.read_memory_block8(0x30000000, 4) == [0x55] * 4
        # Make sure we didn't cache anything.
        assert memcache._cache.overlap(0x30000000, 0x30000004) == set()

    def test_17_noncacheable_region_read(self, mockcore, memcache):
        mockcore.write_memory_block8(0x20000410, [90, 91, 92, 93])
        assert memcache.read_memory_block8(0x20000410, 4) == [90, 91, 92, 93]
        # Make sure we didn't cache anything.
        assert memcache._cache.overlap(0x20000410, 0x20000414) == set()

    def test_18_noncacheable_region_write(self, mockcore, memcache):
        memcache.write_memory_block8(0x20000410, [1, 2, 3, 4])
        mockcore.write_memory_block8(0x20000410, [90, 91, 92, 93])
        assert memcache.read_memory_block8(0x20000410, 4) == [90, 91, 92, 93]
        # Make sure we didn't cache anything.
        assert memcache._cache.overlap(0x20000410, 0x20000414) == set()

    def test_19_write_into_cached(self, mockcore, memcache):
        mockcore.write_memory_block8(4, [1, 2, 3, 4, 5, 6, 7, 8])
        assert memcache.read_memory_block8(4, 8) == [1, 2, 3, 4, 5, 6, 7, 8]
        memcache.write_memory_block8(6, [128, 129, 130, 131])
        assert memcache.read_memory_block8(4, 8) == [1, 2, 128, 129, 130, 131, 7, 8]
        assert len(list(memcache._cache.overlap(4, 12))[0].data) == 8

    def test_20_empty_read(self, memcache):
        assert memcache.read_memory_block8(128, 0) == []

    def test_21_empty_write(self, memcache):
        memcache.write_memory_block8(128, [])
    
    # This test reproduces a bug where writes followed by reads will start
    # accumulating and returning extra data.
    def test_22_multi_write_read_size(self, memcache):
        test_size = 128
        for i in range(100):
            data = [x for x in range(test_size)]
            memcache.write_memory_block8(0, data)
            block = memcache.read_memory_block8(0, test_size)
            assert data == block

    # Variant of test 22.
    def test_23_multi_write_1_read_size(self, memcache):
        test_size = 128
        data = [x for x in range(test_size)]
        for i in range(10):
            memcache.write_memory_block8(0, data)
        block = memcache.read_memory_block8(0, test_size)
        assert data == block

    # Variant of test 22.
    def test_24_1_write_multi_read_size(self, memcache):
        test_size = 128
        data = [x for x in range(test_size)]
        memcache.write_memory_block8(0, data)
        for i in range(10):
            block = memcache.read_memory_block8(0, test_size)
            assert data == block

    # Variant of test 22.
    def test_25_multi_write_subrange_1_read_size(self, memcache):
        test_size = 128
        data = [x for x in range(test_size)]
        memcache.write_memory_block8(0, data)
        for i in range(10):
            memcache.write_memory_block8(64, data[64:96])
        block = memcache.read_memory_block8(0, test_size)
        assert data == block
    
    def test_26_read_subrange(self, memcache):
        data = list((n % 256) for n in range(320))
        memcache.write_memory_block8(0x20000000, data)
        block = memcache.read_memory_block8(0x2000007e, 4)
        assert block == data[0x7e:0x82]

     

# TODO test read32/16/8 with and without callbacks

