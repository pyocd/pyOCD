"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2017 ARM Limited

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

from xml.etree import ElementTree

__all__ = ['MemoryRange', 'MemoryRegion', 'MemoryMap', 'RamRegion', 'RomRegion',
            'FlashRegion', 'DeviceRegion', 'AliasRegion']

MAP_XML_HEADER = b"""<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
"""

def check_range(start, end=None, length=None, range=None):
    assert (start is not None) and ((isinstance(start, MemoryRange) or range is not None) or
        ((end is not None) ^ (length is not None)))
    if isinstance(start, MemoryRange):
        range = start
    if range is not None:
        start = range.start
        end = range.end
    elif end is None:
        end = start + length - 1
    return start, end

## @brief A range of memory within a region.
class MemoryRangeBase(object):
    def __init__(self, start=0, end=0, length=0, region=None):
        self._start = start
        if length != 0:
            self._end = self._start + length - 1
        else:
            self._end = end
        self._region = region

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    @property
    def length(self):
        return self._end - self._start + 1

    @property
    def region(self):
        return self._region

    def contains_address(self, address):
        return (address >= self.start) and (address <= self.end)

    ##
    # @return Whether the given range is fully contained by the region.
    def contains_range(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return self.contains_address(start) and self.contains_address(end)

    ##
    # @return Whether the region is fully within the bounds of the given range.
    def contained_by_range(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return start <= self.start and end >= self.end

    ##
    # @return Whether the region and the given range intersect at any point.
    def intersects_range(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return (start <= self.start and end >= self.start) or (start <= self.end and end >= self.end) \
            or (start >= self.start and end <= self.end)

## @brief A range of memory within a region.
class MemoryRange(MemoryRangeBase):
    def __init__(self, start=0, end=0, length=0, region=None):
        super(MemoryRange, self).__init__(start=start, end=end, length=length)
        self._region = region

    @property
    def region(self):
        return self._region

    def __repr__(self):
        return "<%s@0x%x start=0x%x end=0x%x length=0x%x region=%s>" % (self.__class__.__name__,
            id(self), self.start, self.end, self.length, self.region)

## @brief One contiguous range of memory.
class MemoryRegion(MemoryRangeBase):
    def __init__(self, type='ram', start=0, end=0, length=0, blocksize=0, name='', is_boot_memory=False,
                is_powered_on_boot=True, is_cacheable=True, invalidate_cache_on_run=True, is_testable=True):
        super(MemoryRegion, self).__init__(start=start, end=end, length=length)
        self._type = type
        self._blocksize = blocksize
        if not name:
            self._name = self._type
        else:
            self._name = name
        self._is_boot_mem = is_boot_memory
        self._is_powered_on_boot = is_powered_on_boot
        self._is_cacheable = is_cacheable
        self._invalidate_cache_on_run = invalidate_cache_on_run
        self._is_testable = is_testable

    @property
    def type(self):
        return self._type

    @property
    def blocksize(self):
        return self._blocksize

    @property
    def name(self):
        return self._name

    @property
    def is_flash(self):
        return self._type == 'flash'

    @property
    def is_ram(self):
        return self._type == 'ram'

    @property
    def is_rom(self):
        return self._type == 'rom'

    @property
    def is_device(self):
        return self._type == 'device'

    @property
    def is_alias(self):
        return self._type == 'alias'

    @property
    def is_boot_memory(self):
        return self._is_boot_mem

    @property
    def is_powered_on_boot(self):
        return self._is_powered_on_boot

    @property
    def is_cacheable(self):
        return self._is_cacheable

    @property
    def invalidate_cache_on_run(self):
        return self._invalidate_cache_on_run
    
    @property
    def is_testable(self):
        return self._is_testable

    def __repr__(self):
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x blocksize=0x%x>" % (self.__class__.__name__, id(self), self.name, self.type, self.start, self.end, self.length, self.blocksize)

## @brief Contiguous region of RAM.
class RamRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, name='', is_boot_memory=False,
                is_powered_on_boot=True, is_cacheable=True, invalidate_cache_on_run=True, is_testable=True):
        super(RamRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name,
            is_boot_memory=is_boot_memory, is_powered_on_boot=is_powered_on_boot, is_cacheable=is_cacheable,
            invalidate_cache_on_run=invalidate_cache_on_run, is_testable=is_testable)

## @brief Contiguous region of ROM.
class RomRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, name='', is_boot_memory=False,
                is_powered_on_boot=True, is_cacheable=True, invalidate_cache_on_run=False, is_testable=True):
        super(RomRegion, self).__init__(type='rom', start=start, end=end, length=length, name=name,
            is_boot_memory=is_boot_memory, is_powered_on_boot=is_powered_on_boot, is_cacheable=is_cacheable,
            invalidate_cache_on_run=invalidate_cache_on_run, is_testable=is_testable)

## @brief Contiguous region of flash memory.
class FlashRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', is_boot_memory=False,
                is_powered_on_boot=True, is_cacheable=True, invalidate_cache_on_run=True, is_testable=True):
        super(FlashRegion, self).__init__(type='flash', start=start, end=end, length=length,
            blocksize=blocksize, name=name, is_boot_memory=is_boot_memory, is_powered_on_boot=is_powered_on_boot,
            is_cacheable=is_cacheable, invalidate_cache_on_run=invalidate_cache_on_run, is_testable=is_testable)

## @brief Device or peripheral memory.
class DeviceRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, name='', is_powered_on_boot=True):
        super(DeviceRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name,
            is_boot_memory=False, is_powered_on_boot=is_powered_on_boot, is_cacheable=False,
            invalidate_cache_on_run=True, is_testable=False)

## @brief Alias of another region.
class AliasRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', aliasOf=None, is_boot_memory=False,
                is_powered_on_boot=True, is_cacheable=True, invalidate_cache_on_run=True):
        super(AliasRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name,
            is_boot_memory=is_boot_memory, is_powered_on_boot=is_powered_on_boot, is_cacheable=is_cacheable,
            invalidate_cache_on_run=invalidate_cache_on_run, is_testable=False)
        self._alias_reference = aliasOf

    @property
    def aliased_region(self):
        return self._alias_reference

## @brief Memory map consisting of memory regions.
class MemoryMap(object):
    def __init__(self, *moreRegions):
        self._regions = []
        if len(moreRegions):
            if type(moreRegions[0]) is list:
                self._regions = moreRegions[0]
            else:
                self._regions.extend(moreRegions)
        self._regions.sort(key=lambda x:x.start)

    @property
    def regions(self):
        return self._regions

    @property
    def region_count(self):
        return len(self._regions)

    def add_region(self, newRegion):
        self._regions.append(newRegion)
        self._regions.sort(key=lambda x:x.start)

    def get_boot_memory(self):
        for r in self._regions:
            if r.is_boot_memory:
                return r
        return None

    def get_region_for_address(self, address):
        for r in self._regions:
            if r.contains_address(address):
                return r
        return None

    def get_region_by_name(self, name):
        for r in self._regions:
            if r.name == name:
                return r
        return None

    def is_valid_address(self, address):
        return self.get_region_for_address(address) is not None

    def get_contained_regions(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return [r for r in self._regions if r.contained_by_range(start, end)]

    def get_intersecting_regions(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return [r for r in self._regions if r.intersects_range(start, end)]
    
    def get_regions_of_type(self, type):
        for r in self._regions:
            if r.type == type:
                yield r

    ## @brief Generate GDB memory map XML.
    def get_xml(self):
        root = ElementTree.Element('memory-map')
        for r in self._regions:
            mem = ElementTree.SubElement(root, 'memory', type=r.type, start=hex(r.start).rstrip("L"), length=hex(r.length).rstrip("L"))
            if r.is_flash:
                prop = ElementTree.SubElement(mem, 'property', name='blocksize')
                prop.text = hex(r.blocksize).rstrip("L")
        return MAP_XML_HEADER + ElementTree.tostring(root)

    ## @brief Enable iteration over the memory map.
    def __iter__(self):
        return iter(self._regions)

    def __repr__(self):
        return "<MemoryMap@0x%08x regions=%s>" % (id(self), repr(self._regions))




