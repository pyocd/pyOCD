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

    def containsAddress(self, address):
        return (address >= self.start) and (address <= self.end)

    ##
    # @return Whether the given range is fully contained by the region.
    def containsRange(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return self.containsAddress(start) and self.containsAddress(end)

    ##
    # @return Whether the region is fully within the bounds of the given range.
    def containedByRange(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return start <= self.start and end >= self.end

    ##
    # @return Whether the region and the given range intersect at any point.
    def intersectsRange(self, start, end=None, length=None, range=None):
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
    def __init__(self, type='ram', start=0, end=0, length=0, blocksize=0, name='', isBootMemory=False,
                isPoweredOnBoot=True, isCacheable=True, invalidateCacheOnRun=True, isTestable=True):
        super(MemoryRegion, self).__init__(start=start, end=end, length=length)
        self._type = type
        self._blocksize = blocksize
        if not name:
            self._name = self._type
        else:
            self._name = name
        self._is_boot_mem = isBootMemory
        self._isPoweredOnBoot = isPoweredOnBoot
        self._isCacheable = isCacheable
        self._invalidateCacheOnRun = invalidateCacheOnRun
        self._isTestable = isTestable

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
    def isFlash(self):
        return self._type == 'flash'

    @property
    def isRam(self):
        return self._type == 'ram'

    @property
    def isRom(self):
        return self._type == 'rom'

    @property
    def isDevice(self):
        return self._type == 'device'

    @property
    def isAlias(self):
        return self._type == 'alias'

    @property
    def isBootMemory(self):
        return self._is_boot_mem

    @property
    def isPoweredOnBoot(self):
        return self._isPoweredOnBoot

    @property
    def isCacheable(self):
        return self._isCacheable

    @property
    def invalidateCacheOnRun(self):
        return self._invalidateCacheOnRun
    
    @property
    def isTestable(self):
        return self._isTestable

    def __repr__(self):
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x blocksize=0x%x>" % (self.__class__.__name__, id(self), self.name, self.type, self.start, self.end, self.length, self.blocksize)

## @brief Contiguous region of RAM.
class RamRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, name='', isBootMemory=False,
                isPoweredOnBoot=True, isCacheable=True, invalidateCacheOnRun=True, isTestable=True):
        super(RamRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name,
            isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot, isCacheable=isCacheable,
            invalidateCacheOnRun=invalidateCacheOnRun, isTestable=isTestable)

## @brief Contiguous region of ROM.
class RomRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, name='', isBootMemory=False,
                isPoweredOnBoot=True, isCacheable=True, invalidateCacheOnRun=False, isTestable=True):
        super(RomRegion, self).__init__(type='rom', start=start, end=end, length=length, name=name,
            isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot, isCacheable=isCacheable,
            invalidateCacheOnRun=invalidateCacheOnRun, isTestable=isTestable)

## @brief Contiguous region of flash memory.
class FlashRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', isBootMemory=False,
                isPoweredOnBoot=True, isCacheable=True, invalidateCacheOnRun=True, isTestable=True):
        super(FlashRegion, self).__init__(type='flash', start=start, end=end, length=length,
            blocksize=blocksize, name=name, isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot,
            isCacheable=isCacheable, invalidateCacheOnRun=invalidateCacheOnRun, isTestable=isTestable)

## @brief Device or peripheral memory.
class DeviceRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, name='', isPoweredOnBoot=True):
        super(DeviceRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name,
            isBootMemory=False, isPoweredOnBoot=isPoweredOnBoot, isCacheable=False,
            invalidateCacheOnRun=True, isTestable=False)

## @brief Alias of another region.
class AliasRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', aliasOf=None, isBootMemory=False,
                isPoweredOnBoot=True, isCacheable=True, invalidateCacheOnRun=True):
        super(AliasRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name,
            isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot, isCacheable=isCacheable,
            invalidateCacheOnRun=invalidateCacheOnRun, isTestable=False)
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
    def regionCount(self):
        return len(self._regions)

    def addRegion(self, newRegion):
        self._regions.append(newRegion)
        self._regions.sort(key=lambda x:x.start)

    def getBootMemory(self):
        for r in self._regions:
            if r.isBootMemory:
                return r
        return None

    def getRegionForAddress(self, address):
        for r in self._regions:
            if r.containsAddress(address):
                return r
        return None

    def getRegionByName(self, name):
        for r in self._regions:
            if r.name == name:
                return r
        return None

    def isValidAddress(self, address):
        return self.getRegionForAddress(address) is not None

    def getContainedRegions(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return [r for r in self._regions if r.containedByRange(start, end)]

    def getIntersectingRegions(self, start, end=None, length=None, range=None):
        start, end = check_range(start, end, length, range)
        return [r for r in self._regions if r.intersectsRange(start, end)]
    
    def getRegionsOfType(self, type):
        for r in self._regions:
            if r.type == type:
                yield r

    ## @brief Generate GDB memory map XML.
    def getXML(self):
        root = ElementTree.Element('memory-map')
        for r in self._regions:
            mem = ElementTree.SubElement(root, 'memory', type=r.type, start=hex(r.start).rstrip("L"), length=hex(r.length).rstrip("L"))
            if r.isFlash:
                prop = ElementTree.SubElement(mem, 'property', name='blocksize')
                prop.text = hex(r.blocksize).rstrip("L")
        return MAP_XML_HEADER + ElementTree.tostring(root)

    ## @brief Enable iteration over the memory map.
    def __iter__(self):
        return iter(self._regions)

    def __repr__(self):
        return "<MemoryMap@0x%08x regions=%s>" % (id(self), repr(self._regions))




