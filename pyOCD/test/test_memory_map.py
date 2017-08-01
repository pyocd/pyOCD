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

from pyOCD.core.memory_map import (check_range, MemoryMap, FlashRegion, RomRegion, RamRegion)
import pytest
import logging

@pytest.fixture(scope='function')
def flash():
    return FlashRegion(start=0, length=1*1024, blocksize=0x100, name='flash', isBootMemory=True)

@pytest.fixture(scope='function')
def rom():
    return RomRegion(start=0x1c000000, length=16*1024, name='rom')

@pytest.fixture(scope='function')
def ram1():
    return RamRegion(start=0x20000000, length=1*1024, name='ram')

@pytest.fixture(scope='function')
def ram2():
    return RamRegion(start=0x20000400, length=1*1024, name='ram2', isCacheable=False)

@pytest.fixture(scope='function')
def memmap(flash, rom, ram1, ram2):
    return MemoryMap(flash, rom, ram1, ram2)

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

# MemoryRegion test cases.
class TestMemoryRegion:
    def test_flash_attrs(self, flash):
        assert flash.start == 0
        assert flash.end == 0x3ff
        assert flash.length == 0x400
        assert flash.blocksize == 0x100
        assert flash.name == 'flash'
        assert flash.isFlash
        assert not flash.isRam
        assert not flash.isRom
        assert flash.isBootMemory
        assert flash.isCacheable
        assert flash.isPoweredOnBoot

    def test_rom_attrs(self, rom):
        assert rom.start == 0x1c000000
        assert rom.end == 0x1c003fff
        assert rom.length == 0x4000
        assert rom.blocksize == 0
        assert rom.name == 'rom'
        assert not rom.isFlash
        assert not rom.isRam
        assert rom.isRom
        assert not rom.isBootMemory
        assert rom.isCacheable
        assert rom.isPoweredOnBoot

    def test_ram1_attrs(self, ram1):
        assert ram1.start == 0x20000000
        assert ram1.end == 0x200003ff
        assert ram1.length == 0x400
        assert ram1.blocksize == 0
        assert ram1.name == 'ram'
        assert not ram1.isFlash
        assert ram1.isRam
        assert not ram1.isRom
        assert not ram1.isBootMemory
        assert ram1.isCacheable
        assert ram1.isPoweredOnBoot

    def test_ram2_attrs(self, ram2):
        assert ram2.start == 0x20000400
        assert ram2.end == 0x200007ff
        assert ram2.length == 0x400
        assert ram2.blocksize == 0
        assert ram2.name == 'ram2'
        assert not ram2.isFlash
        assert ram2.isRam
        assert not ram2.isRom
        assert not ram2.isBootMemory
        assert not ram2.isCacheable
        assert ram2.isPoweredOnBoot

    def test_flash_range(self, flash):
        assert flash.containsAddress(0)
        assert flash.containsAddress(0x3ff)
        assert not flash.containsAddress(0x400)
        assert flash.containsRange(0, length=0x400)
        assert flash.containsRange(0, end=0x3ff)
        assert flash.containsRange(0x100, length=0x100)
        assert not flash.containsRange(0x300, end=0x720)
        assert flash.intersectsRange(0, length=0x100)
        assert flash.intersectsRange(0x300, end=0x720)

    def test_intersects(self, ram1):
        assert not ram1.intersectsRange(0, length=10)
        assert not ram1.intersectsRange(0xf0000000, end=0xffffffff)
        assert ram1.intersectsRange(0x100000, end=0x20000010)
        assert ram1.intersectsRange(0x20000010, end=0x30000000)
        assert ram1.intersectsRange(0x20000040, length=0x1000)
        assert ram1.intersectsRange(0x20000020, end=0x20000030)
        assert ram1.intersectsRange(0x20000020, length=0x10)
        assert ram1.intersectsRange(0x1fff0000, end=0x20001000)
        assert ram1.intersectsRange(0x1ffff000, length=0x40000)


# MemoryMap test cases.
class TestMemoryMap:
    def test_empty_map(self):
        memmap = MemoryMap()
        assert memmap.regionCount == 0
        assert memmap.regions == []
        assert memmap.getBootMemory() is None
        assert memmap.getRegionForAddress(0x1000) is None
        assert not memmap.isValidAddress(0x2000)
        assert memmap.getContainedRegions(0, end=0xffffffff) == []
        assert memmap.getIntersectingRegions(0, end=0xffffffff) == []

    def test_regions(self, memmap):
        rgns = memmap.regions
        # Count
        assert len(rgns) == 4
        assert memmap.regionCount == 4
        # Sorted order
        assert rgns[0].start < rgns[1].start and rgns[1].start < rgns[2].start and rgns[2].start < rgns[3].start

    def test_boot_mem(self, memmap):
        bootmem = memmap.getBootMemory()
        assert bootmem is not None
        assert bootmem.name == 'flash'
        assert bootmem.start == 0
        assert bootmem.end == 0x3ff
        assert bootmem.isBootMemory == True

    def test_rgn_for_addr(self, memmap):
        assert memmap.getRegionForAddress(0).name == 'flash'
        assert memmap.getRegionForAddress(0x20000000).name == 'ram'
        assert memmap.getRegionForAddress(0x20000500).name == 'ram2'

    def test_valid(self, memmap):
        assert memmap.isValidAddress(0)
        assert memmap.isValidAddress(0x200)
        assert memmap.isValidAddress(0x3ff)
        assert not memmap.isValidAddress(0x400)
        assert not memmap.isValidAddress(0x1bffffff)
        assert memmap.isValidAddress(0x1c000000)
        assert not memmap.isValidAddress(0x1fffffff)
        assert memmap.isValidAddress(0x20000000)
        assert memmap.isValidAddress(0x20000001)
        assert memmap.isValidAddress(0x200003ff)
        assert memmap.isValidAddress(0x20000400)
        assert memmap.isValidAddress(0x200007ff)
        assert not memmap.isValidAddress(0x20000800)

    def test_contained_1(self, memmap):
        rgns = memmap.getContainedRegions(0, 0x100)
        assert len(rgns) == 0

    def test_contained_2(self, memmap):
        rgns = memmap.getContainedRegions(0x20000000, 0x20000600)
        assert len(rgns) == 1

    def test_intersect_1(self, memmap):
        rgns = memmap.getIntersectingRegions(0, 0x100)
        assert len(rgns) == 1

    def test_intersect_2(self, memmap):
        rgns = memmap.getIntersectingRegions(0x20000200, end=0x20000700)
        assert len(rgns) == 2

    def test_x(self):
        ramrgn = RamRegion(name='core0 ram', start=0x1fffa000, length=0x18000)
        assert ramrgn.containsRange(0x1fffc9f8, end=0x1fffc9fc)
        assert ramrgn.intersectsRange(0x1fffc9f8, end=0x1fffc9fc)
        dualMap = MemoryMap(
            FlashRegion(name='flash', start=0, length=0x80000, blocksize=0x800, isBootMemory=True),
            RomRegion(name='core1 imem alias', start=0x1d200000, length=0x40000),
            ramrgn,
            RomRegion(name='core1 imem', start=0x2d200000, length=0x40000),
            RamRegion(name='core1 dmem', start=0x2d300000, length=0x8000),
            RamRegion(name='usb ram', start=0x40100000, length=0x800)
            )
        rgns = dualMap.getIntersectingRegions(0x1fffc9f8, end=0x1fffc9fc)
        assert len(rgns) > 0
    
    def test_get_type_iter(self, memmap, flash, rom, ram1, ram2):
        assert list(memmap.getRegionsOfType('flash')) == [flash]
        assert list(memmap.getRegionsOfType('rom')) == [rom]
        assert list(memmap.getRegionsOfType('ram')) == [ram1, ram2]



