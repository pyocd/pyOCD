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
import copy

from pyocd.core.memory_map import (
    MemoryType,
    check_range,
    MemoryRange,
    MemoryRegion,
    MemoryMap,
    FlashRegion,
    RomRegion,
    RamRegion,
    DeviceRegion,
    DefaultFlashWeights
    )

@pytest.fixture(scope='function')
def flash():
    return FlashRegion(start=0, length=1*1024, blocksize=0x100, name='flash', is_boot_memory=True)

@pytest.fixture(scope='function')
def rom():
    return RomRegion(start=0x1c000000, length=16*1024, name='rom')

@pytest.fixture(scope='function')
def ram1():
    return RamRegion(start=0x20000000, length=1*1024, name='ram', is_default=False)

@pytest.fixture(scope='function')
def ram2():
    return RamRegion(start=0x20000400, length=1*1024, name='ram2', is_cacheable=False)

@pytest.fixture(scope='function')
def ram_alias():
    return RamRegion(start=0x30000400, length=1*1024, name='ram2_alias', alias='ram2', is_cacheable=False)

@pytest.fixture(scope='function')
def memmap(flash, rom, ram1, ram2):
    return MemoryMap(flash, rom, ram1, ram2)

@pytest.fixture(scope='function')
def memmap2(flash, rom, ram1, ram2, ram_alias):
    return MemoryMap(flash, rom, ram1, ram2, ram_alias)

class TestCheckRange:
    def test_1(self):
        assert check_range(0, end=0x1ff) == (0, 0x1ff)

    def test_2(self):
        assert check_range(0, length=0x200) == (0, 0x1ff)

    def test_3(self):
        with pytest.raises(AssertionError):
            check_range(None, end=100)

    def test_4(self):
        with pytest.raises(AssertionError):
            check_range(0x100, end=None)

    def test_5(self):
        with pytest.raises(AssertionError):
            check_range(0x100, length=None)

class TestRange:
    def test_empty_range_1(self):
        range = MemoryRange(start=0x1000, length=0)
        assert range.start == 0x1000
        assert range.end == 0xfff
        assert range.length == 0
    
    def test_empty_range_2(self):
        range = MemoryRange(start=0x1000, end=0xfff)
        assert range.start == 0x1000
        assert range.end == 0xfff
        assert range.length == 0
    
    def test_eq(self):
        assert MemoryRange(0, length=1000) == MemoryRange(0, length=1000)
    
    def test_lt(self):
        assert MemoryRange(0, length=1000) < MemoryRange(1000, length=1000)
    
    def test_gt(self):
        assert MemoryRange(1000, length=1000) > MemoryRange(0, length=1000)
    
    def test_sort(self, ram1, ram2, flash, rom):
        regionList = [ram2, rom, flash, ram1]
        sortedRegionList = sorted(regionList)
        assert sortedRegionList == [flash, rom, ram1, ram2]
    
    def test_inplace_sort(self, ram1, ram2, flash, rom):
        regionList = [ram2, rom, flash, ram1]
        regionList.sort()
        assert regionList == [flash, rom, ram1, ram2]

class TestHash:
    def test_range_neq(self):
        a = MemoryRange(0, 0x1000)
        b = MemoryRange(10, 20)
        assert hash(a) != hash(b)

    def test_range_eq(self):
        a = MemoryRange(0, 0x1000)
        b = MemoryRange(0, 0x1000)
        assert hash(a) == hash(b)

    def test_range_w_region_neq(self, ram1, rom):
        a = MemoryRange(0, 0x1000, region=ram1)
        b = MemoryRange(0x5000, length=200, region=rom)
        assert hash(a) != hash(b)
        
        a = MemoryRange(0, 0x1000, region=ram1)
        b = MemoryRange(0, 0x1000, region=rom)
        assert hash(a) != hash(b)

    def test_range_eq(self, ram1, rom):
        a = MemoryRange(0, 0x1000, region=ram1)
        b = MemoryRange(0, 0x1000, region=ram1)
        assert hash(a) == hash(b)

# MemoryRegion test cases.
class TestMemoryRegion:
    def test_empty_region_1(self):
        with pytest.raises(AssertionError):
            rgn = MemoryRegion(start=0x1000, length=0)
    
    def test_empty_region_2(self):
        with pytest.raises(AssertionError):
            rgn = MemoryRegion(start=0x1000, end=0xfff)
    
    def test_default_name(self):
        rgn = RamRegion(start=0x1000, end=0x1fff)
        assert rgn.name == 'ram'

        rgn = RomRegion(start=0x1000, end=0x1fff)
        assert rgn.name == 'rom'

        rgn = FlashRegion(start=0x1000, end=0x1fff, blocksize=256)
        assert rgn.name == 'flash'

        rgn = DeviceRegion(start=0x1000, end=0x1fff)
        assert rgn.name == 'device'
    
    def test_block_sector_size(self):
        rgn = FlashRegion(start=0x1000, end=0x1fff, blocksize=256)
        assert rgn.blocksize == 256
        assert rgn.sector_size == 256

        rgn = FlashRegion(start=0x1000, end=0x1fff, sector_size=256)
        assert rgn.blocksize == 256
        assert rgn.sector_size == 256
    
    def test_flash_attrs(self, flash):
        assert flash.type == MemoryType.FLASH
        assert flash.start == 0
        assert flash.end == 0x3ff
        assert flash.length == 0x400
        assert flash.blocksize == 0x100
        assert flash.page_size == 0x100
        assert flash.phrase_size == 0x100
        assert flash.erase_all_weight == DefaultFlashWeights.ERASE_ALL_WEIGHT
        assert flash.erase_sector_weight == DefaultFlashWeights.ERASE_SECTOR_WEIGHT
        assert flash.program_page_weight == DefaultFlashWeights.PROGRAM_PAGE_WEIGHT
        assert flash.name == 'flash'
        assert flash.is_flash
        assert not flash.is_ram
        assert not flash.is_rom
        assert flash.is_boot_memory
        assert flash.is_cacheable
        assert flash.is_powered_on_boot
        assert flash.is_readable
        assert not flash.is_writable
        assert flash.is_executable

    def test_custom_flash_attrs(self):
        flash = FlashRegion(start=0x01000000, length=4*1024, blocksize=0x800, name='myflash',
                            is_boot_memory=False, page_size=256, phrase_size=4,
                            erase_all_weight=1.2, erase_sector_weight=0.1, program_page_weight=0.25)
        assert flash.type == MemoryType.FLASH
        assert flash.start == 0x01000000
        assert flash.end == 0x01000fff
        assert flash.length == 0x1000
        assert flash.blocksize == 0x800
        assert flash.page_size == 256
        assert flash.phrase_size == 4
        assert flash.erase_all_weight == 1.2
        assert flash.erase_sector_weight == 0.1
        assert flash.program_page_weight == 0.25
        assert flash.name == 'myflash'
        assert flash.is_flash
        assert not flash.is_ram
        assert not flash.is_rom
        assert not flash.is_boot_memory
        assert flash.is_cacheable
        assert flash.is_powered_on_boot
        assert flash.is_readable
        assert not flash.is_writable
        assert flash.is_executable

    def test_rom_attrs(self, rom):
        assert rom.type == MemoryType.ROM
        assert rom.start == 0x1c000000
        assert rom.end == 0x1c003fff
        assert rom.length == 0x4000
        with pytest.raises(AttributeError):
            rom.blocksize
        assert rom.name == 'rom'
        assert not rom.is_flash
        assert not rom.is_ram
        assert rom.is_rom
        assert not rom.is_boot_memory
        assert rom.is_cacheable
        assert rom.is_powered_on_boot
        assert rom.is_readable
        assert not rom.is_writable
        assert rom.is_executable

    def test_ram1_attrs(self, ram1):
        assert ram1.type == MemoryType.RAM
        assert ram1.start == 0x20000000
        assert ram1.end == 0x200003ff
        assert ram1.length == 0x400
        with pytest.raises(AttributeError):
            ram1.blocksize
        assert ram1.name == 'ram'
        assert not ram1.is_flash
        assert ram1.is_ram
        assert not ram1.is_rom
        assert not ram1.is_boot_memory
        assert ram1.is_cacheable
        assert ram1.is_powered_on_boot
        assert ram1.is_readable
        assert ram1.is_writable
        assert ram1.is_executable

    def test_ram2_attrs(self, ram2):
        assert ram2.type == MemoryType.RAM
        assert ram2.start == 0x20000400
        assert ram2.end == 0x200007ff
        assert ram2.length == 0x400
        with pytest.raises(AttributeError):
            ram2.blocksize
        assert ram2.name == 'ram2'
        assert not ram2.is_flash
        assert ram2.is_ram
        assert not ram2.is_rom
        assert not ram2.is_boot_memory
        assert not ram2.is_cacheable
        assert ram2.is_powered_on_boot
        assert ram2.is_readable
        assert ram2.is_writable
        assert ram2.is_executable

    def test_flash_range(self, flash):
        assert flash.contains_address(0)
        assert flash.contains_address(0x3ff)
        assert not flash.contains_address(0x400)
        assert flash.contains_range(0, length=0x400)
        assert flash.contains_range(0, end=0x3ff)
        assert flash.contains_range(0x100, length=0x100)
        assert not flash.contains_range(0x300, end=0x720)
        assert flash.intersects_range(0, length=0x100)
        assert flash.intersects_range(0x300, end=0x720)

    def test_intersects(self, ram1):
        assert not ram1.intersects_range(0, length=10)
        assert not ram1.intersects_range(0xf0000000, end=0xffffffff)
        assert ram1.intersects_range(0x100000, end=0x20000010)
        assert ram1.intersects_range(0x20000010, end=0x30000000)
        assert ram1.intersects_range(0x20000040, length=0x1000)
        assert ram1.intersects_range(0x20000020, end=0x20000030)
        assert ram1.intersects_range(0x20000020, length=0x10)
        assert ram1.intersects_range(0x1fff0000, end=0x20001000)
        assert ram1.intersects_range(0x1ffff000, length=0x40000)
    
    def test_copy_ram(self, ram1):
        ramcpy = copy.copy(ram1)
        assert ramcpy.type == ram1.type
        assert ramcpy.start == ram1.start
        assert ramcpy.end == ram1.end
        assert ramcpy.length == ram1.length
        assert ramcpy.name == ram1.name
        assert ramcpy == ram1
    
    def test_copy_flash(self, flash):
        flashcpy = copy.copy(flash)
        assert flashcpy == flash
    
    def test_eq(self, flash, ram1):
        assert flash != ram1
        
        a = RamRegion(name='a', start=0x1000, length=0x2000)
        b = RamRegion(name='a', start=0x1000, length=0x2000)
        assert a == b


# MemoryMap test cases.
class TestMemoryMap:
    def test_empty_map(self):
        memmap = MemoryMap()
        assert memmap.region_count == 0
        assert memmap.regions == []
        assert memmap.get_boot_memory() is None
        assert memmap.get_region_for_address(0x1000) is None
        assert not memmap.is_valid_address(0x2000)
        assert memmap.get_contained_regions(0, end=0xffffffff) == []
        assert memmap.get_intersecting_regions(0, end=0xffffffff) == []

    def test_regions(self, memmap):
        rgns = memmap.regions
        # Count
        assert len(rgns) == 4
        assert memmap.region_count == 4
        # Sorted order
        assert rgns[0].start < rgns[1].start and rgns[1].start < rgns[2].start and rgns[2].start < rgns[3].start

    def test_boot_mem(self, memmap):
        bootmem = memmap.get_boot_memory()
        assert bootmem is not None
        assert bootmem.name == 'flash'
        assert bootmem.start == 0
        assert bootmem.end == 0x3ff
        assert bootmem.is_boot_memory == True

    def test_rgn_for_addr(self, memmap):
        assert memmap.get_region_for_address(0).name == 'flash'
        assert memmap.get_region_for_address(0x20000000).name == 'ram'
        assert memmap.get_region_for_address(0x20000500).name == 'ram2'

    def test_valid(self, memmap):
        assert memmap.is_valid_address(0)
        assert memmap.is_valid_address(0x200)
        assert memmap.is_valid_address(0x3ff)
        assert not memmap.is_valid_address(0x400)
        assert not memmap.is_valid_address(0x1bffffff)
        assert memmap.is_valid_address(0x1c000000)
        assert not memmap.is_valid_address(0x1fffffff)
        assert memmap.is_valid_address(0x20000000)
        assert memmap.is_valid_address(0x20000001)
        assert memmap.is_valid_address(0x200003ff)
        assert memmap.is_valid_address(0x20000400)
        assert memmap.is_valid_address(0x200007ff)
        assert not memmap.is_valid_address(0x20000800)

    def test_contained_1(self, memmap):
        rgns = memmap.get_contained_regions(0, 0x100)
        assert len(rgns) == 0

    def test_contained_2(self, memmap):
        rgns = memmap.get_contained_regions(0x20000000, 0x20000600)
        assert len(rgns) == 1

    def test_intersect_1(self, memmap):
        rgns = memmap.get_intersecting_regions(0, 0x100)
        assert len(rgns) == 1

    def test_intersect_2(self, memmap):
        rgns = memmap.get_intersecting_regions(0x20000200, end=0x20000700)
        assert len(rgns) == 2

    def test_x(self):
        ramrgn = RamRegion(name='core0 ram', start=0x1fffa000, length=0x18000)
        assert ramrgn.contains_range(0x1fffc9f8, end=0x1fffc9fc)
        assert ramrgn.intersects_range(0x1fffc9f8, end=0x1fffc9fc)
        dualMap = MemoryMap(
            FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, is_boot_memory=True),
            RomRegion(name='core1 imem alias', start=0x1d200000, length=0x40000),
            ramrgn,
            RomRegion(name='core1 imem', start=0x2d200000, length=0x40000),
            RamRegion(name='core1 dmem', start=0x2d300000, length=0x8000),
            RamRegion(name='usb ram', start=0x40100000, length=0x800)
            )
        rgns = dualMap.get_intersecting_regions(0x1fffc9f8, end=0x1fffc9fc)
        assert len(rgns) > 0
    
    def test_get_type_iter(self, memmap, flash, rom, ram1, ram2):
        assert list(memmap.iter_matching_regions(type=MemoryType.FLASH)) == [flash]
        assert list(memmap.iter_matching_regions(type=MemoryType.ROM)) == [rom]
        assert list(memmap.iter_matching_regions(type=MemoryType.RAM)) == [ram1, ram2]
    
    def test_match_iter(self, memmap, flash, ram1, ram2, ram_alias):
        assert list(memmap.iter_matching_regions(blocksize=0x100)) == [flash]
        assert list(memmap.iter_matching_regions(start=0x20000000)) == [ram1]
    
    def test_first_match(self, memmap, flash, ram2):
        assert memmap.get_first_matching_region(blocksize=0x100) == flash
        assert memmap.get_first_matching_region(length=1024, is_cacheable=False) == ram2
    
    def test_alias(self, memmap2, ram2, ram_alias):
        assert ram_alias.alias is ram2
    
    def test_get_default(self, memmap, flash, ram2):
        assert memmap.get_default_region_of_type(MemoryType.FLASH) == flash
        assert memmap.get_default_region_of_type(MemoryType.RAM) == ram2

    def test_index_by_num(self, memmap, flash, ram2):
        assert memmap[0] == flash
        assert memmap[3] == ram2

    def test_index_by_name(self, memmap, rom, ram2):
        assert memmap['rom'] == rom
        assert memmap['ram2'] == ram2
    
    def test_clone(self, memmap):
        mapcpy = memmap.clone()
        assert id(mapcpy) != id(memmap)
        assert id(mapcpy.get_first_matching_region(type=MemoryType.RAM)) != \
            id(memmap.get_first_matching_region(type=MemoryType.RAM))
        assert mapcpy == memmap
        


