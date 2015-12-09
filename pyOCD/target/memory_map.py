"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

__all__ = ['MemoryRegion', 'MemoryMap', 'RamRegion', 'RomRegion', 'FlashRegion']

MAP_XML_HEADER = """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
"""

## @brief One contiguous range of memory.
class MemoryRegion(object):
    def __init__(self, type='ram', start=0, end=0, length=0, blocksize=0, name='', isBootMemory=False, isPoweredOnBoot=True):
        self._type = type
        self._start = start
        if length != 0:
            self._end = self._start + length - 1
        else:
            self._end = end
        self._blocksize = blocksize
        if not name:
            self._name = self._type
        else:
            self._name = name
        self._is_boot_mem = isBootMemory
        self._isPoweredOnBoot = isPoweredOnBoot

    @property
    def type(self):
        return self._type

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
    def isBootMemory(self):
        return self._is_boot_mem

    @property
    def isPoweredOnBoot(self):
        return self._isPoweredOnBoot

    def containsAddress(self, address):
        return (address >= self.start) and (address <= self.end)

    def containsRange(self, start, end=None, length=None):
        assert (end is not None) ^ (length is not None)
        if end is None:
            end = start + length - 1
        return self.containsAddress(start) and self.containsAddress(end)

    def __str__(self):
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x blocksize=0x%x>" % (self.__class__.__name__, id(self), self.name, self.type, self.start, self.end, self.length, self.blocksize)

    def __repr__(self):
        return str(self)

## @brief Contiguous region of RAM.
class RamRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', isBootMemory=False, isPoweredOnBoot=True):
        super(RamRegion, self).__init__(type='ram', start=start, end=end, length=length, name=name, isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot)

## @brief Contiguous region of ROM.
class RomRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', isBootMemory=False, isPoweredOnBoot=True):
        super(RomRegion, self).__init__(type='rom', start=start, end=end, length=length, name=name, isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot)

## @brief Contiguous region of flash memory.
class FlashRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, blocksize=0, name='', isBootMemory=False, isPoweredOnBoot=True):
        super(FlashRegion, self).__init__(type='flash', start=start, end=end, length=length, blocksize=blocksize, name=name, isBootMemory=isBootMemory, isPoweredOnBoot=isPoweredOnBoot)

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

    def isValidAddress(self, address):
        return self.regionForAddress(address) is not None

    ## @brief Generate GDB memory map XML.
    def getXML(self):
        root = ElementTree.Element('memory-map')
        for r in self._regions:
            mem = ElementTree.SubElement(root, 'memory', type=r.type, start=hex(r.start), length=hex(r.length))
            if r.isFlash:
                prop = ElementTree.SubElement(mem, 'property', name='blocksize')
                prop.text = hex(r.blocksize)
        return MAP_XML_HEADER + ElementTree.tostring(root)

    ## @brief Enable iteration over the memory map.
    def __iter__(self):
        return iter(self._regions)




