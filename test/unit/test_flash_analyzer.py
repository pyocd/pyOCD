# pyOCD debugger
# Copyright (c) 2026 Andrew Jessop
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
from binascii import crc32
from struct import pack
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.core.memory_map import FlashRegion
from pyocd.flash.flash import Flash
from pyocd.target.builtin.target_STM32F103RC import FLASH_ALGO


def make_builder(address, readable=True, pages=1):
    # Real Flash and FlashBuilder; only target RAM, flash, and code execution are simulated.
    contents = [0x55] * (0x800 * pages)
    ram = {}
    reads = []

    def read_bytes(addr, size):
        assert readable
        reads.append((addr, size))
        offset = addr - address
        assert 0 <= offset <= len(contents) - size
        return contents[offset:offset + size]

    def write_words(addr, words):
        # A probe cannot send words larger than 32 bits to the target.
        pack('<' + 'I' * len(words), *words)
        ram[addr] = list(words)

    def run_analyzer(entry, buffer, count, **kwargs):
        # Emulate the existing analyzer's uint16_t size/address command layout.
        commands = ram[buffer]
        checksums = []
        for command in commands[:count]:
            size = 1 << (command & 0xffff)
            addr = (command >> 16) * size
            checksums.append(crc32(bytes(read_bytes(addr, size))))
        ram[buffer] = checksums

    target = SimpleNamespace(
        session=SimpleNamespace(options={'flash.timeout.analyzer': 30}, notify=Mock()),
        read_memory_block8=Mock(side_effect=read_bytes),
        write_memory_block32=Mock(side_effect=write_words),
        read_memory_block32=lambda addr, count: ram[addr][:count],
    )
    flash = Flash(target, FLASH_ALGO)
    flash.region = FlashRegion(start=address, length=len(contents), blocksize=0x800,
                               access='rx' if readable else 'x', algo=FLASH_ALGO)
    flash.init = Mock()
    flash._call_function_and_wait = Mock(side_effect=run_analyzer)
    return flash.get_flash_builder(), contents, reads


@pytest.mark.parametrize('address', [0, 0x07fff800, 0x08000000, 0x08004000])
@pytest.mark.parametrize('changed_offset', [None, 0, 1000])
@pytest.mark.parametrize('fast_verify', [False, True])
def test_smart_flash_analyzer_address_range(address, changed_offset, fast_verify):
    builder, original, reads = make_builder(address)
    data = list(original)
    if changed_offset is not None:
        data[changed_offset] ^= 1
    builder.add_data(address, data)
    builder._prepare_sectors_and_pages(keep_unwritten=False, smart_flash=True)
    builder._finalize_smart_flash(lambda progress: None, fast_verify=fast_verify)

    assert builder.page_list[0].same is (changed_offset is None)
    if address >= 0x08000000:
        builder.flash._call_function_and_wait.assert_not_called()
        assert builder.perf.analyze_type == builder.FLASH_ANALYSIS_PARTIAL_PAGE_READ
    else:
        builder.flash._call_function_and_wait.assert_called_once()
        assert builder.perf.analyze_type == builder.FLASH_ANALYSIS_CRC32
    assert reads


def test_unencodable_unreadable_flash_is_programmed_without_reading():
    builder, data, reads = make_builder(0x08004000, readable=False)
    builder.add_data(0x08004000, data)
    builder._prepare_sectors_and_pages(keep_unwritten=False, smart_flash=True)
    builder._finalize_smart_flash(lambda progress: None, fast_verify=True)

    assert builder.page_list[0].same is False
    builder.flash._call_function_and_wait.assert_not_called()
    builder.flash.target.read_memory_block8.assert_not_called()
    assert not reads


@pytest.mark.parametrize('changed_offset', [None, 0, 0x800 + 1000])
@pytest.mark.parametrize('fast_verify', [False, True])
def test_erase_and_program_across_analyzer_address_limit(changed_offset, fast_verify):
    address = 0x07fff800
    builder, contents, reads = make_builder(address, pages=2)
    expected = list(contents)
    if changed_offset is not None:
        expected[changed_offset] ^= 1

    def erase_sector(addr):
        offset = addr - address
        contents[offset:offset + 0x800] = [0xff] * 0x800

    def program_page(addr, data):
        offset = addr - address
        contents[offset:offset + len(data)] = data

    builder.flash.uninit = Mock()
    builder.flash.cleanup = Mock()
    builder.flash.erase_sector = Mock(side_effect=erase_sector)
    builder.flash.program_page = Mock(side_effect=program_page)
    builder.enable_double_buffer(False)
    builder.add_data(address, expected)
    builder.erase(chip_erase='sector', fast_verify=fast_verify)
    builder.program(fast_verify=fast_verify)

    assert contents == expected
    expected_writes = int(changed_offset is not None)
    assert builder.flash.erase_sector.call_count == expected_writes
    assert builder.flash.program_page.call_count == expected_writes
    assert builder.perf.program_page_count == expected_writes
    builder.flash._call_function_and_wait.assert_not_called()
