"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

from mock import patch
from pyOCD.target.pack.pack_target import (get_supported_targets, _align_up,
                                           _bytes_to_words,
                                           _get_sector_size, get_memory_map,
                                           _split_on_blocksize,
                                           _get_cache_device_errors,
                                           FlashInfo)
MOCK_DEV_1 = {
    "memory": {
        "IROM1": {
            "start": "0x1000",
            "size": "0x2000"
        },
        "IROM2": {
            "start": "0x4000",
            "size": "0x1000"
        },
        "IRAM1": {
            "start": "0x10000",
            "size": "0x10"
        }
    }
}
DEV_1_SECTOR_SIZES = (
    (0x0000, 0x040),
    (0x0100, 0x100),
    (0x3000, 0x200)
)
DEV_1_FLASH_INFO = FlashInfo(
    start=0x1000,
    size=0x4000,
    sector_sizes=DEV_1_SECTOR_SIZES
)

MOCK_DEV_INVALID_ROM = {
    "memory": {
        "IROM1": {
            "start": "abcd",
        }
    }
}

MOCK_DEV_NO_MEM = {}

MOCK_INDEX = {
    "version": "0.1.0",
    "mock_dev_1": MOCK_DEV_1,
    "mock_device_invalid_rom": MOCK_DEV_INVALID_ROM,
    "mock_device_no_mem": MOCK_DEV_NO_MEM,
}


class MockCache:

    def __init__(self, a, b):
        self.index = MOCK_INDEX

    def get_flash_algorthim_binary(self, all=False):
        pass


@patch("pyOCD.target.pack.pack_target.Cache", wraps=MockCache)
def test_get_supported_targets(MockCacheClass):
    assert sorted(get_supported_targets()) == sorted(["mock_dev_1"])


def test_get_memory_map():
    expected_info = (
        {   # IROM1 blocksize 0x40
            "type": "flash",
            "start": 0x1000,
            "length": 0x100,
            "blocksize": 0x40
        },
        {   # IROM1 blocksize 0x100
            "type": "flash",
            "start": 0x1100,
            "length": 0x1F00,
            "blocksize": 0x100
        },
        {   # IROM2
            "type": "flash",
            "start": 0x4000,
            "length": 0x1000,
            "blocksize": 0x200
        },
        {   # IRAM1
            "type": "ram",
            "start": 0x10000,
            "length": 0x10
        }
    )
    sector_sizes = (
        (0x0000, 0x040),
        (0x0100, 0x100),
        (0x3000, 0x200)
    )
    flash_info = FlashInfo(
        start=0x1000,
        size=0x4000,
        sector_sizes=sector_sizes
    )

    memmap = get_memory_map(MOCK_DEV_1, flash_info)
    regions = [region for region in memmap]
    assert len(regions) == len(expected_info)
    for info, region in zip(expected_info, regions):
        for attr, value in info.items():
            assert hasattr(region, attr)
            assert getattr(region, attr) == value


def test_split_on_blocksize():
    result_regions_1 = (
        (0x0000, 0x1000),
        (0x1000, 0x0100),
        (0x1100, 0x2F00),
        (0x4000, 0x2000)
    )
    result_regions_2 = (
        (0x1100, 0x2F00),
    )
    addr_size_result = (
        # Fully encompass flash
        (0x0000, 0x6000, result_regions_1),
        # Completely inside flash with the same sector size
        (0x1100, 0x2F00, result_regions_2),
    )
    for addr, size, result in addr_size_result:
        assert (list(result) ==
                list(_split_on_blocksize(addr, size, DEV_1_FLASH_INFO)))


def test_get_sector_size():
    start = 1000
    size = 100
    sector_sizes = (
        (10, 10),
        (20, 17),
        (37, 7),
    )
    block_info = FlashInfo(start, size, sector_sizes)
    addr_and_results = [
        (999, None),
        (1000, None),
        (1009, None),
        (1010, 10),
        (1019, 10),
        (1020, 17),
        (1036, 17),
        (1037, 7),
        (1099, 7),
        (1100, None),
        (1101, None),
    ]
    for addr, results in addr_and_results:
        assert results == _get_sector_size(block_info, addr)

    block_info_empty = FlashInfo(start, size, ())
    assert _get_sector_size(block_info_empty, 1010) is None


def test_bytes_to_words():
    args_and_results = [
        ((b"",), []),
        ((b"a",), [0x61]),
        ((b"abc",), [0x636261]),
        ((b"abcd",), [0x64636261]),
        ((b"abcde",), [0x64636261, 0x65]),
        ((bytearray(b"abcde"),), [0x64636261, 0x65]),
    ]
    for args, result in args_and_results:
        assert list(result) == list(_bytes_to_words(*args))


def test_align_up():
    args_and_results = [
        ((0, 1024), 0),
        ((1, 1024), 1024),
        ((0, 3), 0),
        ((100, 3), 102),
    ]
    for args, result in args_and_results:
        assert result == _align_up(*args)


def test_get_cache_device_errors():
    assert _get_cache_device_errors(MOCK_DEV_1) is None
    assert (sorted(_get_cache_device_errors(MOCK_DEV_INVALID_ROM)) ==
            sorted(["Device region 'IROM1' key 'start' has invalid value 'abcd'",
                    "Device region 'IROM1' missing key 'size'"]))
    assert (sorted(_get_cache_device_errors(MOCK_DEV_NO_MEM)) ==
            sorted(["Device does not have a memory layout"]))
