# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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

from enum import Enum
import six
from functools import total_ordering

class MemoryType(Enum):
    """! @brief Known types of memory."""
    OTHER = 0
    RAM = 1
    ROM = 2
    FLASH = 3
    DEVICE = 4

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
@total_ordering
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
    
    def __hash__(self):
        h = hash("%08x%08x%08x" % (self.start, self.end, self.length))
        if self.region is not None:
            h ^= hash(self.region)
        return h
    
    def __eq__(self, other):
        return self.start == other.start and self.length == other.length
    
    def __lt__(self, other):
        return self.start < other.start or (self.start == other.start and self.length == other.length)

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
    DEFAULT_ATTRS = {
        'name': lambda r: r.attributes.get('name', r.type.name.lower()),
        'access': 'rwx',
        'alias': None,
        'blocksize': 0,
        'erased_byte_value': 0,
        'is_boot_memory': False,
        'is_default': True,
        'is_powered_on_boot': True,
        'is_cacheable': True,
        'invalidate_cache_on_run': True,
        'is_testable': True,
        'is_external': False,        
        'is_ram': lambda r: r.type == MemoryType.RAM,
        'is_rom': lambda r: r.type == MemoryType.ROM,
        'is_flash': lambda r: r.type == MemoryType.FLASH,
        'is_device': lambda r: r.type == MemoryType.DEVICE,
        'is_readable': lambda r: 'r' in r.access,
        'is_writable': lambda r: 'w' in r.access,
        'is_executable': lambda r: 'x' in r.access,
        'is_secure': lambda r: 's' in r.access,
        }
    
    def __init__(self, type=MemoryType.OTHER, start=0, end=0, length=0, **attrs):
        """! Memory region constructor.
        
        Optional region attributes passed as keyword arguments:
        - name: If a name is not provided, the name is set to the region type in lowercase.
        - access: composition of r, w, x, s
        - alias
        - blocksize
        - is_boot_memory
        - is_powered_on_boot
        - is_cacheable
        - invalidate_cache_on_run
        - is_testable
        """
        super(MemoryRegion, self).__init__(start=start, end=end, length=length)
        assert isinstance(type, MemoryType)
        self._map = None
        self._type = type
        self._attributes = attrs
        
        # Assign default values to any attributes missing from kw args.
        for k, v in self.DEFAULT_ATTRS.items():
            if k not in self._attributes:
                self._attributes[k] = v

    @property
    def map(self):
        return self._map

    @map.setter
    def map(self, theMap):
        self._map = theMap
        
    @property
    def type(self):
        return self._type
    
    @property
    def attributes(self):
        return self._attributes
        
    @property
    def alias(self):
        # Resolve alias reference.
        aliasValue = self._attributes['alias']
        if isinstance(aliasValue, six.string_types):
            referent = self._map.get_region_by_name(aliasValue)
            if referent is None:
                raise ValueError("unable to resolve memory region alias reference '%s'" % aliasValue)
            self._attributes['alias'] = referent
            return referent
        else:
            return aliasValue
        
    def __getattr__(self, name):
        v = self._attributes[name]
        if callable(v):
            v = v(self)
        return v

    def __repr__(self):
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x access=%s>" % (self.__class__.__name__, id(self), self.name, self.type, self.start, self.end, self.length, self.access)

## @brief Contiguous region of RAM.
class RamRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, **attrs):
        super(RamRegion, self).__init__(type=MemoryType.RAM, start=start, end=end, length=length, **attrs)

## @brief Contiguous region of ROM.
class RomRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, **attrs):
        attrs['access'] = attrs.get('access', 'rx')
        super(RomRegion, self).__init__(type=MemoryType.ROM, start=start, end=end, length=length, **attrs)

## @brief Contiguous region of flash memory.
class FlashRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, **attrs):
        # Import locally to prevent import loops.
        from ..flash.flash import Flash

        attrs['access'] = attrs.get('access', 'rx') # By default flash is not writable.
        attrs['erased_byte_value'] = attrs.get('erased_byte_value', 0xff)
        super(FlashRegion, self).__init__(type=MemoryType.FLASH, start=start, end=end, length=length, **attrs)
        self._algo = attrs.get('algo', None)
        self._flm = None
        self._flash = None
        
        if 'flash_class' in attrs:
            self._flash_class = attrs['flash_class']
            assert issubclass(self._flash_class, Flash)
        else:
            self._flash_class = Flash
    
    @property
    def algo(self):
        return self._algo
    
    @algo.setter
    def algo(self, flash_algo):
        self._algo = flash_algo
    
    @property
    def flm(self):
        return self._flm
    
    @flm.setter
    def flm(self, flm_path):
        self._flm = flm_path
    
    @property
    def flash_class(self):
        return self._flash_class
    
    @flash_class.setter
    def flash_class(self, klass):
        self._flash_class = klass
    
    @property
    def flash(self):
        return self._flash
    
    @flash.setter
    def flash(self, flashInstance):
        self._flash = flashInstance
        
    def is_erased(self, d):
        """! @brief Helper method to check if a block of data is erased.
        @param self
        @param d List of data or bytearray.
        @retval True The contents of d all match the erased byte value for this flash region.
        @retval False At least one byte in d did not match the erased byte value.
        """
        erasedByte = self.erased_byte_value
        for b in d:
            if b != erasedByte:
                return False
        return True

    def __repr__(self):
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x access=%s blocksize=0x%x>" % (self.__class__.__name__, id(self), self.name, self.type, self.start, self.end, self.length, self.access, self.blocksize)

## @brief Device or peripheral memory.
class DeviceRegion(MemoryRegion):
    def __init__(self, start=0, end=0, length=0, **attrs):
        attrs['access'] = attrs.get('access', 'rw') # By default flash is not executable.
        attrs['is_cacheable'] = False
        attrs['is_testable'] = False
        super(DeviceRegion, self).__init__(type=MemoryType.DEVICE, start=start, end=end, length=length, **attrs)

## @brief Map from memory type to class.                
MEMORY_TYPE_CLASS_MAP = {
        MemoryType.OTHER:   MemoryRegion,
        MemoryType.RAM:     RamRegion,
        MemoryType.ROM:     RomRegion,
        MemoryType.FLASH:   FlashRegion,
        MemoryType.DEVICE:  DeviceRegion,
    }

## @brief Memory map consisting of memory regions.
class MemoryMap(object):
    def __init__(self, *moreRegions):
        self._regions = []
        self.add_regions(*moreRegions)

    @property
    def regions(self):
        return self._regions

    @property
    def region_count(self):
        return len(self._regions)

    def add_regions(self, *moreRegions):
        if len(moreRegions):
            if isinstance(moreRegions[0], (list, tuple)):
                regionsToAdd = moreRegions[0]
            else:
                regionsToAdd = moreRegions
            
            for newRegion in regionsToAdd:
                self.add_region(newRegion)

    def add_region(self, newRegion):
        newRegion.map = self
        self._regions.append(newRegion)
        self._regions.sort()
    
    def remove_region(self, region):
        """! @brief Removes a memory region from the map.
        @param self
        @param region The region to remove. The region to remove is matched by identity, not value,
            so this parameter must be the exact object that you wish to remove from the map.
        """
        for i, r in enumerate(self._regions):
            if r is region:
                del self._regions[i]

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
    
    def get_first_region_of_type(self, type):
        for r in self.get_regions_of_type(type):
            return r
        return None

    ## @brief Enable iteration over the memory map.
    def __iter__(self):
        return iter(self._regions)

    def __repr__(self):
        return "<MemoryMap@0x%08x regions=%s>" % (id(self), repr(self._regions))




