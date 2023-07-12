# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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
import collections.abc
import copy
from functools import total_ordering
from typing import (Any, Callable, Dict, Iterable, Iterator, List, Optional, TYPE_CHECKING,
        Sequence, Tuple, Type, Union)
from typing_extensions import Self

from ..utility.strings import uniquify_name

if TYPE_CHECKING:
    from ..target.pack.flash_algo import PackFlashAlgo
    from ..flash.flash import Flash

class MemoryType(Enum):
    """@brief Known types of memory."""
    OTHER = 0
    RAM = 1
    ROM = 2
    FLASH = 3
    DEVICE = 4

def check_range(
            start: Union[int, "MemoryRangeBase", None] = None,
            end: Optional[int] = None,
            length: Optional[int] = None,
            range: Optional["MemoryRangeBase"] = None
        ) -> Tuple[int, int]:
    assert ((range is not None)
        or ((start is not None) and (isinstance(start, MemoryRangeBase)
            or ((end is not None) ^ (length is not None)))))
    if isinstance(start, MemoryRangeBase):
        range = start
    if range is not None:
        actual_start = range.start
        actual_end = range.end
    else:
        assert isinstance(start, int)
        actual_start = start
        if end is None:
            assert length is not None
            actual_end = actual_start + length - 1
        else:
            actual_end = end
    return actual_start, actual_end

@total_ordering
class MemoryRangeBase:
    """@brief Base class for a range of memory.

    This base class provides the basic address range support and methods to test for containment
    or intersection with another range.
    """
    def __init__(self, start: int = 0, end: int = 0, length: Optional[int] = None) -> None:
        self._start = start
        if length is not None:
            self._end = self._start + length - 1
        else:
            self._end = end
        assert self._end >= (self._start - 1)

    @property
    def start(self) -> int:
        return self._start

    @property
    def end(self) -> int:
        return self._end

    @property
    def length(self) -> int:
        return self._end - self._start + 1

    @property
    def is_empty(self) -> bool:
        """@brief Whether the range has a zero size."""
        return self.length == 0

    def contains_address(self, address: int) -> bool:
        return (address >= self.start) and (address <= self.end)

    def contains_range(
                self,
                start: Union[int, "MemoryRangeBase", None] = None,
                end: Optional[int] = None,
                length: Optional[int] = None,
                range: Optional["MemoryRangeBase"] = None
            ) -> bool:
        """@return Whether the given range is fully contained by the region."""
        start, end = check_range(start, end, length, range)
        return self.contains_address(start) and self.contains_address(end)

    def contained_by_range(
                self,
                start: Union[int, "MemoryRangeBase", None] = None,
                end: Optional[int] = None,
                length: Optional[int] = None,
                range: Optional["MemoryRangeBase"] = None
            ) -> bool:
        """@return Whether the region is fully within the bounds of the given range."""
        start, end = check_range(start, end, length, range)
        return start <= self.start and end >= self.end

    def intersects_range(
                self,
                start: Union[int, "MemoryRangeBase", None] = None,
                end: Optional[int] = None,
                length: Optional[int] = None,
                range: Optional["MemoryRangeBase"] = None
            ) -> bool:
        """@return Whether the region and the given range intersect at any point."""
        start, end = check_range(start, end, length, range)
        return (start <= self.start and end >= self.start) or (start <= self.end and end >= self.end) \
            or (start >= self.start and end <= self.end)

    def iter_split_by_address(self, addresses: Iterable[int]) -> Iterator["MemoryRange"]:
        """@brief Yield ranges by splitting the object at the given addresses.

        The values in _addresses_ are points at which _self_'s bounds are split. Each value in _addresses_
        which is contained by _self_ becomes the start address of a yielded MemoryRange object, as well as
        the end + 1 of the previous yielded range.

        If a value in _addresses_ is not contained by _self_, it is ignored. If _addresses_ is empty or
        contains only out of bounds values, a MemoryRange with the same bounds as _self_ is yielded, unless
        _self_ has zero length.

        @param self
        @param addresses Iterable of int addresses by which _self_ is split. Can be in any order, can be,
            empty and can contain values outside the bounds of _self_.
        """
        prev = self.start
        for a in sorted(a for a in addresses if self.contains_address(a)):
            if a > prev:
                yield MemoryRange(start=prev, end=(a - 1))
            prev = a
        if prev <= self.end:
            yield MemoryRange(start=prev, end=self.end)

    def iter_split_by_range(self, other: "MemoryRangeBase") -> Iterator["MemoryRange"]:
        """@brief Yield a list of ranges before, containing, and after the provided range.

        Up to three MemoryRange objects are yielded. No yielded range will have bounds outside those of
        self's.
        - If _self_ and _other_ do not intersect, no ranges are yielded.
        - If _other_ starts after _self_, a range
        """
        yield from self.iter_split_by_address([other.start, other.end + 1])

    def __hash__(self) -> int:
        return hash("%08x%08x%08x" % (self.start, self.end, self.length))

    def __eq__(self, other: "MemoryRangeBase") -> bool:
        return self.start == other.start and self.length == other.length

    def __lt__(self, other: "MemoryRangeBase") -> bool:
        return self.start < other.start or (self.start == other.start and self.length == other.length)

class MemoryRange(MemoryRangeBase):
    """@brief A range of memory optionally tied to a region."""
    def __init__(
                self,
                start: int = 0,
                end: int = 0,
                length: Optional[int] = None,
                region: Optional["MemoryRegion"] = None
            ) -> None:
        super().__init__(start=start, end=end, length=length)
        self._region = region

    @property
    def region(self) -> Optional["MemoryRegion"]:
        return self._region

    def __hash__(self) -> int:
        h = super().__hash__()
        if self.region is not None:
            h ^= hash(self.region)
        return h

    def __eq__(self, other: "MemoryRange") -> bool:
        return self.start == other.start and self.length == other.length and self.region == other.region

    def __repr__(self) -> str:
        return "<%s@0x%x start=0x%x end=0x%x length=0x%x region=%s>" % (self.__class__.__name__,
            id(self), self.start, self.end, self.length, self.region)

class MemoryRegion(MemoryRangeBase):
    """@brief One contiguous range of memory.

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
    - `has_subregions`: True if the region has nested subregions, accessible through the `.map` property.

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

    Memory regions can contain nested subregions. Any subregions must be fulled contained within the parent
    region's address range. Subregions must also have the same memory type, except that a parent region
    of type `MemoryType.OTHER` can contain any type of subregions.
    """

    ## Default attribute values for all memory region types.
    DEFAULT_ATTRS: Dict[str, Any] = {
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
        'is_ram': lambda r: r.type is MemoryType.RAM,
        'is_rom': lambda r: r.type is MemoryType.ROM,
        'is_flash': lambda r: r.type is MemoryType.FLASH,
        'is_device': lambda r: r.type is MemoryType.DEVICE,
        'is_readable': lambda r: 'r' in r.access,
        'is_writable': lambda r: 'w' in r.access,
        'is_executable': lambda r: 'x' in r.access,
        'is_erasable' : True,
        'is_secure': lambda r: 's' in r.access,
        'is_nonsecure': lambda r: not r.is_secure,
        }

    def __init__(
                self,
                type: MemoryType = MemoryType.OTHER,
                start: int = 0,
                end: int = 0,
                length: Optional[int] = None,
                **attrs: Any
            ) -> None:
        """Memory region constructor.

        Memory regions are required to have non-zero lengths, unlike memory ranges.

        Some common optional region attributes passed as keyword arguments:
        - name: If a name is not provided, the name is set to the region type in lowercase.
        - access: composition of r, w, x, s
        - alias
        - is_boot_memory
        - is_powered_on_boot
        - is_testable
        """
        super().__init__(start=start, end=end, length=length)
        assert self.length > 0, "Memory regions must have a non-zero length."
        assert isinstance(type, MemoryType)
        self._map: Optional[MemoryMap] = None
        self._type = type
        self._attributes = attrs
        self._submap = MemoryMap(
            start=self.start,
            end=self.end,
            region_validator=lambda r: (r.type == self._type) or (self._type is MemoryType.OTHER),
        )

        # Assign default values to any attributes missing from kw args.
        for k, v in self.DEFAULT_ATTRS.items():
            if k not in self._attributes:
                self._attributes[k] = v

    @property
    def map(self) -> Optional["MemoryMap"]:
        return self._map

    @map.setter
    def map(self, the_map: Optional["MemoryMap"]) -> None:
        self._map = the_map

    @property
    def submap(self) -> "MemoryMap":
        """@brief Memory map containing nested regions."""
        return self._submap

    @property
    def has_subregions(self) -> bool:
        return not self.submap.is_empty

    @property
    def type(self) -> MemoryType:
        return self._type

    @property
    def attributes(self) -> Dict[str, Any]:
        return self._attributes

    @property
    def alias(self) -> Any:
        # Resolve alias reference.
        alias_value = self._attributes['alias']
        if isinstance(alias_value, str) and self._map is not None:
            referent = self._map.get_first_matching_region(name=alias_value)
            if referent is None:
                raise ValueError("unable to resolve memory region alias reference '%s'" % alias_value)
            self._attributes['alias'] = referent
            return referent
        else:
            return alias_value

    def __getattr__(self, name: str) -> Any:
        try:
            v = self._attributes[name]
        except KeyError:
            # Transform the KeyError from a missing attribute to the expected AttributeError.
            raise AttributeError(name)
        else:
            if callable(v):
                v = v(self)
            return v

    def __setattr__(self, name: str, value: Any) -> None:
        """@brief Set an instance attribute.

        Overridden to handle region attributes contained in the ._attributes dict.
        """
        # Get our ._attributes dict instance attribute without going through our own __getattr__().
        # This can fail if called before ._attributes has been set the first time.
        try:
            attrs = super().__getattribute__('_attributes')
        except AttributeError:
            return super().__setattr__(name, value)

        # If the named attribute is contained in the ._attributes dict, set it there, otherwise
        # pass on to the super implementation.
        if name in attrs:
            attrs[name] = value
        else:
            return super().__setattr__(name, value)

    def _get_attributes_for_clone(self) -> Dict[str, Any]:
        """@brief Return a dict containing all the attributes of this region.

        This method must be overridden by subclasses to include in the returned dict any instance attributes
        not present in the `_attributes` attribute.
        """
        return dict(start=self.start, length=self.length, **self._attributes)

    def clone_with_changes(self, **modified_attrs: Any) -> Self:
        """@brief Create a duplicate this region with some of its attributes modified."""
        new_attrs = self._get_attributes_for_clone()
        new_attrs.update(modified_attrs)

        return self.__class__(**new_attrs)

    def __copy__(self) -> Any:
        return self.clone_with_changes()

    # Need to redefine __hash__ since we redefine __eq__.
    __hash__ = MemoryRangeBase.__hash__

    def __eq__(self, other: "MemoryRegion") -> bool:
        # Include type and attributes in equality comparison.
        return self.start == other.start and self.length == other.length \
            and self.type == other.type and self.attributes == other.attributes

    def __repr__(self) -> str:
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x access=%s>" % (self.__class__.__name__, id(self), self.name, self.type, self.start, self.end, self.length, self.access)

class RamRegion(MemoryRegion):
    """@brief Contiguous region of RAM."""
    def __init__(
                self,
                start: int = 0,
                end: int = 0,
                length: Optional[int] = None,
                **attrs: Any
            ) -> None:
        attrs['type'] = MemoryType.RAM
        super().__init__(start=start, end=end, length=length, **attrs)

class RomRegion(MemoryRegion):
    """@brief Contiguous region of ROM."""

    # Default attribute values for ROM regions.
    DEFAULT_ATTRS = MemoryRegion.DEFAULT_ATTRS.copy()
    DEFAULT_ATTRS.update({
        'access': 'rx', # ROM is by definition not writable.
        })

    def __init__(
                self,
                start: int = 0,
                end: int = 0,
                length: Optional[int] = None,
                **attrs: Any
            ) -> None:
        attrs['type'] = MemoryType.ROM
        super().__init__(start=start, end=end, length=length, **attrs)

class DefaultFlashWeights:
    """@brief Default weights for flash programming operations."""
    PROGRAM_PAGE_WEIGHT = 0.130
    ERASE_SECTOR_WEIGHT = 0.048
    ERASE_ALL_WEIGHT = 0.174

class FlashRegion(MemoryRegion):
    """@brief Contiguous region of flash memory.

    Flash regions have a number of attributes in addition to those available in all region types.
    - `blocksize`: Erase sector size in bytes.
    - `sector_size`: Alias for `blocksize`.
    - `page_size`: Program page size in bytes. If not set, this will default to the `blocksize`.
    - `phrase_size`: The minimum programming granularity in bytes. Defaults to the `page_size` if not set.
    - `erase_all_weight`: Time it takes to erase the entire region.
    - `erase_sector_weight`: Time it takes to erase one sector.
    - `program_page_weight`: Time it takes to program a single page.
    - `erased_byte_value`: The value of an erased byte of this flash. Most flash technologies erase to
        all 1s, which would be an `erased_byte_value` of 0xff.
    - `algo`: The flash algorithm dictionary.
    - `flm`: Path to an FLM flash algorithm, either a str or Path, or a PackFlashAlgo instance.
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

    _algo: Optional[Dict[str, Any]]
    _flm: Optional[Union[str, "PackFlashAlgo"]]
    _flash: Optional["Flash"]
    _flash_class: Type["Flash"]

    def __init__(
                self,
                start: int = 0,
                end: int = 0,
                length: Optional[int] = None,
                **attrs: Any
            ) -> None:
        # Import locally to prevent import loops.
        from ..flash.flash import Flash

        assert ('blocksize' in attrs) or ('sector_size' in attrs) or ('flm' in attrs)
        attrs['type'] = MemoryType.FLASH
        super().__init__(start=start, end=end, length=length, **attrs)
        self._algo = attrs.get('algo', None)
        self._flm = attrs.get('flm', None)
        self._flash = None

        if ('flash_class' in attrs) and (attrs['flash_class'] is not None):
            self._flash_class = attrs['flash_class']
            assert issubclass(self._flash_class, Flash)
        else:
            self._flash_class = Flash

        # Remove writable region attributes from attributes dict so there is only one copy.
        try:
            del self._attributes['algo']
        except KeyError:
            pass
        try:
            del self._attributes['flash_class']
        except KeyError:
            pass
        try:
            del self._attributes['flm']
        except KeyError:
            pass

    @property
    def algo(self) -> Optional[Dict[str, Any]]:
        return self._algo

    @algo.setter
    def algo(self, flash_algo: Dict[str, Any]) -> None:
        self._algo = flash_algo

    @property
    def flm(self) -> Optional[Union[str, "PackFlashAlgo"]]:
        return self._flm

    @flm.setter
    def flm(self, flm_path: str) -> None:
        self._flm = flm_path

        # Clear the flash algo dict when a new FLM is assigned. This makes it possible to override
        # a built-in/default flash algo.
        self._algo = None

    @property
    def flash_class(self) -> Type["Flash"]:
        return self._flash_class

    @flash_class.setter
    def flash_class(self, klass: Type["Flash"]) -> None:
        self._flash_class = klass

    @property
    def flash(self) -> Optional["Flash"]:
        return self._flash

    @flash.setter
    def flash(self, flash_instance: "Flash") -> None:
        self._flash = flash_instance

    def is_data_erased(self, d: Iterable[int]) -> bool:
        """@brief Helper method to check if a block of data is erased.
        @param self
        @param d List of data or bytearray.
        @retval True The contents of d all match the erased byte value for this flash region.
        @retval False At least one byte in d did not match the erased byte value.
        """
        erased_byte = self.erased_byte_value
        for b in d:
            if b != erased_byte:
                return False
        return True

    def _get_attributes_for_clone(self) -> Dict[str, Any]:
        """@brief Return a dict containing all the attributes of this region."""
        d = super()._get_attributes_for_clone()
        d.update(
                algo=self._algo,
                flash_class=self._flash_class,
                flm=self._flm,
                )
        return d

    # Need to redefine __hash__ since we redefine __eq__.
    __hash__ = MemoryRegion.__hash__

    def __eq__(self, other: "FlashRegion") -> bool:
        # Include flash algo, class, and flm in equality test.
        return super().__eq__(other) and self.algo == other.algo and \
                self.flash_class == other.flash_class and self.flm == other.flm

    def __repr__(self) -> str:
        return "<%s@0x%x name=%s type=%s start=0x%x end=0x%x length=0x%x access=%s blocksize=0x%x>" % (
                self.__class__.__name__, id(self), self.name, self.type, self.start, self.end,
                self.length, self.access, self.blocksize)

class DeviceRegion(MemoryRegion):
    """@brief Device or peripheral memory."""

    # Default attribute values for device regions.
    DEFAULT_ATTRS = MemoryRegion.DEFAULT_ATTRS.copy()
    DEFAULT_ATTRS.update({
        'access': 'rw', # By default device regions are not executable.
        'is_cacheable': False,
        'is_testable': False,
        })

    def __init__(
                self,
                start: int = 0,
                end: int = 0,
                length: Optional[int] = None,
                **attrs: Any
            ) -> None:
        attrs['type'] = MemoryType.DEVICE
        super().__init__(start=start, end=end, length=length, **attrs)

## @brief Map from memory type to class.
MEMORY_TYPE_CLASS_MAP: Dict[MemoryType, Type[MemoryRegion]] = {
        MemoryType.OTHER:   MemoryRegion,
        MemoryType.RAM:     RamRegion,
        MemoryType.ROM:     RomRegion,
        MemoryType.FLASH:   FlashRegion,
        MemoryType.DEVICE:  DeviceRegion,
    }

class MemoryMap(MemoryRangeBase, collections.abc.Sequence):
    """@brief Memory map consisting of memory regions.

    The normal way to create a memory map is to instantiate regions directly in the call to the
    constructor.

    @code
    map = MemoryMap(
                FlashRegion(    start=0,
                                length=0x4000,
                                blocksize=0x400,
                                is_boot_memory=True,
                                algo=FLASH_ALGO),

                RamRegion(      start=0x10000000,
                                length=0x1000)
                )
    @endcode

    The memory map can also be modified by adding and removing regions at runtime. Regardless of
    the order regions are added, the list of regions contained in the memory map is always
    maintained sorted by start address.

    MemoryMap objects implement the collections.abc.Sequence interface.
    """

    _regions: List[MemoryRegion]
    _region_validator: Callable[[MemoryRegion], bool]

    def __init__(
            self,
            *more_regions: Union[Sequence[MemoryRegion], MemoryRegion],
            **kwargs: Any,
            ) -> None:
        """@brief Constructor.

        All parameters passed to the constructor are assumed to be MemoryRegion instances, and
        are passed to add_regions(). The resulting memory map is sorted by region start address.

        @param self
        @param more_regions Zero or more MemoryRegion objects passed as separate parameters.

        Keyword arguments:
        - `start`
        - `end`
        - `length`
        - `region_validator`: Callable of the form `(MemoryRegion) -> bool`. Called with each region added to the map. If False is returned, a ValueError is raised rather than add the region.

        @exception ValueError The region validator returned false.
        """
        MemoryRangeBase.__init__(
            self,
            start=kwargs.get('start', 0),
            end=kwargs.get('end', 0xffffffff),
            length=kwargs.get('length')
        )
        self._regions = []
        self._region_validator = kwargs.get('region_validator', lambda r: True)
        self.add_regions(*more_regions)

    @property
    def regions(self) -> List[MemoryRegion]:
        """@brief List of all memory regions.

        Regions in the returned list are sorted by start address.
        """
        return self._regions

    @property
    def region_count(self) -> int:
        """@brief Number of memory regions in the map."""
        return len(self._regions)

    @property
    def is_empty(self) -> bool:
        """@brief Whether the map has zero regions."""
        return len(self._regions) == 0

    def clone(self) -> "MemoryMap":
        """@brief Create a duplicate of the memory map.

        The duplicate memory map contains shallow copies of each of the regions. This is intended
        to be used so that `Target` objects in different but simultaneously live sessions have
        independant copies of the target's memory map.
        """
        return MemoryMap(*[copy.copy(r) for r in self.regions])

    def add_regions(self, *more_regions: Union[Sequence[MemoryRegion], MemoryRegion]) -> None:
        """@brief Add multiple regions to the memory map.

        There are two options for passing the list of regions to be added. The first is to pass
        each region as a separate parameter, similar to how the constructor is intended to be used.
        The second option is to pass either a list or tuple of regions.

        The region list is kept sorted. If no regions are provided, the call is a no-op.

        @param self
        @param more_regions Either a single sequence of MemoryRegion objects, or one or more MemoryRegion
            objects passed as separate parameters.

        @exception ValueError The region is out of bounds or the validator returned false.
        """
        if len(more_regions):
            if isinstance(more_regions[0], collections.abc.Sequence):
                regions_to_add = more_regions[0]
            else:
                regions_to_add = more_regions

            for new_region in regions_to_add:
                assert isinstance(new_region, MemoryRegion)
                self.add_region(new_region)

    def add_region(self, new_region: MemoryRegion) -> None:
        """@brief Add one new region to the map.

        The region list is resorted after adding the provided region.

        @param self
        @param new_region An instance of MemoryRegion to add. A new instance that is a copy of this argument
            may be added to the memory map in order to guarantee unique region names (if the region has a
            name). The region must fall completely within the map's address bounds.

        @exception ValueError The region is out of bounds or the validator returned false.
        """
        # Check for an existing region with the same name. Multiple unnamed regions are allowed.
        existing_names = [r.name for r in self._regions if r]
        if new_region.name and (new_region.name in existing_names):
            new_region = new_region.clone_with_changes(name=uniquify_name(new_region.name, existing_names))

        # Validate the region.
        if not self.contains_range(new_region):
            raise ValueError(f"attempt add region {new_region} failed because it is out of bounds")
        if not self._region_validator(new_region):
            raise ValueError(f"attempt add region {new_region} failed because validator returned False")

        new_region.map = self
        self._regions.append(new_region)
        self._regions.sort()

    def remove_region(self, region: MemoryRegion) -> None:
        """@brief Removes a memory region from the map.
        @param self
        @param region The region to remove. The region to remove is matched by identity, not value,
            so this parameter must be the exact object that you wish to remove from the map.
        """
        for i, r in enumerate(self._regions):
            if r is region:
                del self._regions[i]

    def get_boot_memory(self) -> Optional[MemoryRegion]:
        """@brief Returns the first region marked as boot memory.

        @param self
        @return MemoryRegion or None.
        """
        for r in self._regions:
            if r.is_boot_memory:
                return r
        return None

    def get_region_for_address(self, address: int) -> Optional[MemoryRegion]:
        """@brief Returns the first region containing the given address.

        @param self
        @param address An integer target address.
        @return MemoryRegion or None.
        """
        for r in self._regions:
            if r.contains_address(address):
                return r
        return None

    def is_valid_address(self, address: int) -> bool:
        """@brief Determines whether an address is contained by any region.

        @param self
        @param address An integer target address.
        @return Boolean indicating whether the address was contained by a region.
        """
        return self.get_region_for_address(address) is not None

    def get_contained_regions(
                self,
                start: Union[int, "MemoryRangeBase"],
                end: Optional[int] = None,
                length: Optional[int] = None,
                range: Optional["MemoryRangeBase"] = None
            ) -> List[MemoryRegion]:
        """@brief Get all regions fully contained by an address range.

        @param self
        @param start The start address or a MemoryRange object.
        @param end Optional end address.
        @param length Optional length in bytes.
        @param range Optional MemoryRange object.
        @return List of all regions in the memory map that are fully enclosed by the specified
            address range.
        """
        start, end = check_range(start, end, length, range)
        return [r for r in self._regions if r.contained_by_range(start, end)]

    def get_intersecting_regions(
                self,
                start: Union[int, "MemoryRangeBase"],
                end: Optional[int] = None,
                length: Optional[int] = None,
                range: Optional["MemoryRangeBase"] = None
            ) -> List[MemoryRegion]:
        """@brief Get all regions intersected by an address range.

        @param self
        @param start The start address or a MemoryRange object.
        @param end Optional end address.
        @param length Optional length in bytes.
        @param range Optional MemoryRange object.
        @return List of all regions in the memory map that intersect with the specified address
            range.
        """
        start, end = check_range(start, end, length, range)
        return [r for r in self._regions if r.intersects_range(start, end)]

    def iter_matching_regions(self, **kwargs: Any) -> Iterator[MemoryRegion]:
        """@brief Iterate over regions matching given criteria.

        Useful attributes to match on include 'type', 'name', 'is_default', and others.

        @param self
        @param kwargs Values for region attributes that must match.
        """
        for r in self._regions:
            # Check attributes.
            mismatch = False
            for k, v in kwargs.items():
                try:
                    if getattr(r, k) != v:
                        mismatch = True
                        break
                except AttributeError:
                    # Don't match regions without the specified attribute.
                    mismatch = True
            if mismatch:
                continue

            yield r

    def get_first_matching_region(self, **kwargs: Any) -> Optional[MemoryRegion]:
        """@brief Get the first region matching a given memory type.

        The region of given type with the lowest start address is returned. If there are no regions
        with that type, None is returned instead.

        @param self
        @param type One of the MemoryType enums.
        @return A MemoryRegion object or None.
        """
        for r in self.iter_matching_regions(**kwargs):
            return r
        return None

    def get_default_region_of_type(self, type: MemoryType) -> Optional[MemoryRegion]:
        """@brief Get the default region of a given memory type.

        If there are multiple regions of the specified type marked as default, then the one with
        the lowest start address will be returned. None is returned if there are no default regions
        of the type.

        @param self
        @param type One of the MemoryType enums.
        @return A MemoryRegion object or None.
        """
        return self.get_first_matching_region(type=type, is_default=True)

    def __eq__(self, other: "MemoryMap") -> bool:
        return isinstance(other, MemoryMap) and (self._regions == other._regions)

    def __iter__(self) -> Iterator[MemoryRegion]:
        """@brief Enable iteration over the memory map."""
        return iter(self._regions)

    def __reversed__(self) -> Iterator[MemoryRegion]:
        """@brief Reverse iteration over the memory map."""
        return reversed(self._regions)

    def __getitem__(self, key: Union[int, str]) -> MemoryRegion:
        """@brief Return a region indexed by name or number."""
        if isinstance(key, str):
            result = self.get_first_matching_region(name=key)
            if result is None:
                raise IndexError(key)
            return result
        else:
            return self._regions[key]

    def __len__(self) -> int:
        """@brief Return the number of regions."""
        return len(self._regions)

    def __contains__(self, key: Union[int, str, MemoryRegion]) -> bool:
        if isinstance(key, int):
            return self.is_valid_address(key)
        elif isinstance(key, str):
            return self.get_first_matching_region(name=key) is not None
        else:
            return key in self._regions

    def __repr__(self) -> str:
        return "<MemoryMap@0x%08x regions=%s>" % (id(self), repr(self._regions))




