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

@total_ordering
class MemoryRangeBase(object):
    """! @brief Base class for a range of memory.
    
    This base class provides the basic address range support and methods to test for containment
    or intersection with another range.
    """
    def __init__(self, start=0, end=0, length=None):
        self._start = start
        if length is not None:
            self._end = self._start + length - 1
        else:
            self._end = end
        assert self._end >= (self._start - 1)

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    @property
    def length(self):
        return self._end - self._start + 1

    def contains_address(self, address):
        return (address >= self.start) and (address <= self.end)

    def contains_range(self, start, end=None, length=None, range=None):
        """! @return Whether the given range is fully contained by the region."""
        start, end = check_range(start, end, length, range)
        return self.contains_address(start) and self.contains_address(end)

    def contained_by_range(self, start, end=None, length=None, range=None):
        """! @return Whether the region is fully within the bounds of the given range."""
        start, end = check_range(start, end, length, range)
        return start <= self.start and end >= self.end

    def intersects_range(self, start, end=None, length=None, range=None):
        """! @return Whether the region and the given range intersect at any point."""
        start, end = check_range(start, end, length, range)
        return (start <= self.start and end >= self.start) or (start <= self.end and end >= self.end) \
            or (start >= self.start and end <= self.end)
    
    def __hash__(self):
        return hash("%08x%08x%08x" % (self.start, self.end, self.length))
    
    def __eq__(self, other):
        return self.start == other.start and self.length == other.length
    
    def __lt__(self, other):
        return self.start < other.start or (self.start == other.start and self.length == other.length)

class MemoryRange(MemoryRangeBase):
    """! @brief A range of memory optionally tied to a region."""
    def __init__(self, start=0, end=0, length=None, region=None):
        super(MemoryRange, self).__init__(start=start, end=end, length=length)
        self._region = region

    @property
    def region(self):
        return self._region
    
    def __hash__(self):
        h = super(MemoryRange, self).__hash__()
        if self.region is not None:
            h ^= hash(self.region)
        return h
    
    def __eq__(self, other):
        return self.start == other.start and self.length == other.length and self.region == other.region

    def __repr__(self):
        return "<%s@0x%x start=0x%x end=0x%x length=0x%x region=%s>" % (self.__class__.__name__,
            id(self), self.start, self.end, self.length, self.region)

class MemoryRegion(MemoryRangeBase):
    """! @brief One contiguous range of memory.
    
    Memory regions have attributes accessible via the normal dot syntax.
    
    - `name`: Name of the region, which defaults to the region type in lowercase.
    - `access`: Composition of r, w, x, s.
    - `alias`: If set, this is the name of another region that of which this region is an alias.
    - `is_boot_memory`: Whether the device boots from this memory. This normally implies that the
        boot NVIC vector table is placed at the base address of this region, but that is not
        always the case.
    - `is_default`: Whether the region should be used as a default of the given type.
    - `is_powered_on_boot`: Whether the memory is powered and accessible without special configuration
        at system boot. For internal memories, this will almost always be true.
    - `is_cacheable`: Determines whether data should be cached from this region. True for most
        memory types, except DEVICE.
    - `invalidate_cache_on_run`: Whether to invalidate any cached data from the region whenever the
        target resumes execution or steps. Usually true, though this can be false for regions such
        as memory-mapped OTP or configuration flash.
    - `is_testable`: Whether pyOCD should consider the region in its functional tests.
    - `is_external`: If true, the region is backed by an external memory device such as SDRAM or QSPI.
    
    Several attributes are available whose values are computed from other attributes. These should
    not be set when creating the region.
    - `is_ram`
    - `is_rom`
    - `is_flash`
    - `is_device`
    - `is_readable`
    - `is_writable`
    - `is_executable`
    - `is_secure`
    - `is_nonsecure`
    """
    
    ## Default attribute values for all memory region types.
    DEFAULT_ATTRS = {
        'name': lambda r: r.type.name.lower(),
        'access': 'rwx',
        'alias': None,
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
        'is_nonsecure': lambda r: not r.is_secure,
        }
    
    def __init__(self, type=MemoryType.OTHER, start=0, end=0, length=None, **attrs):
        """! Memory region constructor.
        
        Memory regions are required to have non-zero lengths, unlike memory ranges.
        
        Some common optional region attributes passed as keyword arguments:
        - name: If a name is not provided, the name is set to the region type in lowercase.
        - access: composition of r, w, x, s
        - alias
        - is_boot_memory
        - is_powered_on_boot
        - is_testable
        """
        super(MemoryRegion, self).__init__(start=start, end=end, length=length)
        assert self.length > 0, "Memory regions must have a non-zero length."
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

class RamRegion(MemoryRegion):
    """! @brief Contiguous region of RAM."""
    def __init__(self, start=0, end=0, length=None, **attrs):
        super(RamRegion, self).__init__(type=MemoryType.RAM, start=start, end=end, length=length, **attrs)

class RomRegion(MemoryRegion):
    """! @brief Contiguous region of ROM."""

    # Default attribute values for ROM regions.
    DEFAULT_ATTRS = MemoryRegion.DEFAULT_ATTRS.copy()
    DEFAULT_ATTRS.update({
        'access': 'rx', # ROM is by definition not writable.
        })

    def __init__(self, start=0, end=0, length=None, **attrs):
        super(RomRegion, self).__init__(type=MemoryType.ROM, start=start, end=end, length=length, **attrs)

class DefaultFlashWeights:
    """! @brief Default weights for flash programming operations."""
    PROGRAM_PAGE_WEIGHT = 0.130
    ERASE_SECTOR_WEIGHT = 0.048
    ERASE_ALL_WEIGHT = 0.174

class FlashRegion(MemoryRegion):
    """! @brief Contiguous region of flash memory.
    
    Flash regions have a number of attributes in addition to those available in all region types.
    - `blocksize`: Erase sector size in bytes.
    - `page_size`: Program page size in bytes. If not set, this will default to the `blocksize`.
    - `phrase_size`: The minimum programming granularity in bytes. Defaults to the `page_size` if not set.
    - `erase_all_weight`: Time it takes to erase the entire region.
    - `erase_sector_weight`: Time it takes to erase one sector.
    - `program_page_weight`: Time it takes to program a single page.
    - `erased_byte_value`: The value of an erased byte of this flash. Most flash technologies erase to
        all 1s, which would be an `erased_byte_value` of 0xff.
    - `algo`: The flash algorithm dictionary.
    - `flm`: Path to an FLM flash algorithm.
    - `flash_class`: The class that manages individual flash algorithm operations. Must be either
        @ref pyocd.flash.flash.Flash "Flash", which is the default, or a subclass.
    - `flash`: After connection, this attribute holds the instance of `flash_class` for this region.
    - `are_erased_sectors_readable`: Specifies whether the flash controller allows reads of erased
        sectors, or will fault such reads. Default is True.
    
    `sector_size` and `blocksize` are aliases of each other. If one is set via the constructor, the
    other will have the same value.
    """

    # Add some default attribute values for flash regions.
    DEFAULT_ATTRS = MemoryRegion.DEFAULT_ATTRS.copy()
    DEFAULT_ATTRS.update({
        'blocksize': lambda r: r.sector_size, # Erase sector size. Alias for sector_size.
        'sector_size': lambda r: r.blocksize, # Erase sector size. Alias for blocksize.
        'page_size': lambda r: r.blocksize, # Program page size.
        'phrase_size': lambda r: r.page_size, # Minimum programmable unit.
        'erase_all_weight': DefaultFlashWeights.ERASE_ALL_WEIGHT,
        'erase_sector_weight': DefaultFlashWeights.ERASE_SECTOR_WEIGHT,
        'program_page_weight': DefaultFlashWeights.PROGRAM_PAGE_WEIGHT,
        'erased_byte_value': 0xff,
        'access': 'rx', # By default flash is not writable.
        'are_erased_sectors_readable': True,
        })

    def __init__(self, start=0, end=0, length=None, **attrs):
        # Import locally to prevent import loops.
        from ..flash.flash import Flash

        assert ('blocksize' in attrs) or ('sector_size' in attrs)
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

class DeviceRegion(MemoryRegion):
    """! @brief Device or peripheral memory."""

    # Default attribute values for device regions.
    DEFAULT_ATTRS = MemoryRegion.DEFAULT_ATTRS.copy()
    DEFAULT_ATTRS.update({
        'access': 'rw', # By default device regions are not executable.
        'is_cacheable': False,
        'is_testable': False,
        })

    def __init__(self, start=0, end=0, length=None, **attrs):
        super(DeviceRegion, self).__init__(type=MemoryType.DEVICE, start=start, end=end, length=length, **attrs)

## @brief Map from memory type to class.         
MEMORY_TYPE_CLASS_MAP = {
        MemoryType.OTHER:   MemoryRegion,
        MemoryType.RAM:     RamRegion,
        MemoryType.ROM:     RomRegion,
        MemoryType.FLASH:   FlashRegion,
        MemoryType.DEVICE:  DeviceRegion,
    }

class MemoryMap(object):
    """! @brief Memory map consisting of memory regions."""
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

    def __iter__(self):
        """! @brief Enable iteration over the memory map."""
        return iter(self._regions)

    def __repr__(self):
        return "<MemoryMap@0x%08x regions=%s>" % (id(self), repr(self._regions))




