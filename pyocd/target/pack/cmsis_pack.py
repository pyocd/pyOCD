# -*- coding: utf-8 -*-
# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
# Copyright (c) 2020 Men Shiyun
# Copyright (c) 2020 Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
# Copyright (c) 2021 Chris Reed
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

from xml.etree.ElementTree import (ElementTree, Element)
import zipfile
import logging
import io
from typing import (Any, Callable, Dict, List, IO, Iterator, Optional, Tuple, TypeVar, Union)

from .flash_algo import PackFlashAlgo
from ...core import exceptions
from ...core.target import Target
from ...core.memory_map import (MemoryMap, MemoryRegion, MemoryType, MEMORY_TYPE_CLASS_MAP, FlashRegion, RamRegion)

LOG = logging.getLogger(__name__)

class MalformedCmsisPackError(exceptions.TargetSupportError):
    """@brief Exception raised for errors parsing a CMSIS-Pack."""
    pass

class _DeviceInfo:
    """@brief Simple container class to hold XML elements describing a device."""
    def __init__(self, element: Element, **kwargs):
        self.element: Element = element
        self.families: List[str] = kwargs.get('families', [])
        self.memories: List[Element] = kwargs.get('memories', [])
        self.algos: List[Element] = kwargs.get('algos', [])
        self.debugs: List[Element] = kwargs.get('debugs', [])

def _get_part_number_from_element(element: Element) -> str:
    """@brief Extract the part number from a device or variant XML element."""
    assert element.tag in ("device", "variant")
    # Both device and variant may have 'Dname' according to the latest spec.
    if 'Dname' in element.attrib:
        return element.attrib['Dname']
    elif element.tag == "variant":
        return element.attrib['Dvariant']
    else:
        raise ValueError("element is neither device nor variant")

class CmsisPack:
    """@brief Wraps a CMSIS Device Family Pack.

    This class provides a top-level interface for extracting device information from CMSIS-Packs.
    After an instance is constructed, a list of the devices described within the pack is available
    from the `devices` property. Each item in the list is a CmsisPackDevice object.

    The XML element hierarchy that defines devices is as follows.
    ```
    family [-> subFamily] -> device [-> variant]
    ```

    Internally, this class is responsible for collecting the device-related XML elements from each
    of the levels of the hierarchy described above. It determines which elements belong to each
    defined device and passes those to CmsisPackDevice. It is then CmsisPackDevice that performs
    the parsing of each element type into pyOCD-compatible data.
    """
    def __init__(self, file_or_path: Union[str, zipfile.ZipFile, IO[bytes]]) -> None:
        """@brief Constructor.

        Opens the CMSIS-Pack and builds instances of CmsisPackDevice for all the devices
        and variants defined within the pack.

        @param self
        @param file_or_path The .pack file to open. May be a string that is the path to the pack,
            or may be a ZipFile, or a file-like object that is already opened.

        @exception MalformedCmsisPackError The pack is not a zip file, or the .pdsc file is missing
            from within the pack.
        """
        if isinstance(file_or_path, zipfile.ZipFile):
            self._pack_file = file_or_path
        else:
            try:
                self._pack_file = zipfile.ZipFile(file_or_path, 'r')
            except zipfile.BadZipFile as err:
                raise MalformedCmsisPackError(f"Failed to open CMSIS-Pack '{file_or_path}': {err}") from err

        # Find the .pdsc file.
        for name in self._pack_file.namelist():
            if name.endswith('.pdsc'):
                self._pdscName = name
                break
        else:
            raise MalformedCmsisPackError(f"CMSIS-Pack '{file_or_path}' is missing a .pdsc file")

        with self._pack_file.open(self._pdscName) as pdscFile:
            self._pdsc = CmsisPackDescription(self, pdscFile)

    @property
    def filename(self) -> Optional[str]:
        """@brief Accessor for the filename or path of the .pack file."""
        return self._pack_file.filename

    @property
    def pdsc(self) -> "CmsisPackDescription":
        """@brief Accessor for the CmsisPackDescription instance for the pack's PDSC file."""
        return self._pdsc

    @property
    def devices(self) -> List["CmsisPackDevice"]:
        """@brief A list of CmsisPackDevice objects for every part number defined in the pack."""
        return self._pdsc.devices

    def get_file(self, filename) -> IO[bytes]:
        """@brief Return file-like object for a file within the pack.

        @param self
        @param filename Relative path within the pack. May use forward or back slashes.
        @return A BytesIO object is returned that contains all of the data from the file
            in the pack. This is done to isolate the returned file from how the pack was
            opened (due to particularities of the ZipFile implementation).
        """
        filename = filename.replace('\\', '/')
        return io.BytesIO(self._pack_file.read(filename))

class CmsisPackDescription:
    """@brief Parser for the PDSC XML file describing a CMSIS-Pack.
    """

    def __init__(self, pack: CmsisPack, pdsc_file: IO) -> None:
        """@brief Constructor.

        @param self This object.
        @param pack Reference to the CmsisPack instance.
        @param pdsc_file A file-like object for the .pdsc contained in _pack_.
        """
        self._pack = pack

        # Convert PDSC into an ElementTree.
        self._pdsc = ElementTree(file=pdsc_file)

        self._state_stack: List[_DeviceInfo] = []
        self._devices: List["CmsisPackDevice"] = []

        # Remember if we have already warned about overlapping memory regions
        # so we can limit these to one warning per DFP
        self._warned_overlapping_memory_regions = False

        # Extract devices.
        for family in self._pdsc.iter('family'):
            self._parse_devices(family)

    @property
    def pack(self) -> CmsisPack:
        """@brief Reference to the containing CmsisPack object."""
        return self._pack

    @property
    def devices(self) -> List["CmsisPackDevice"]:
        """@brief A list of CmsisPackDevice objects for every part number defined in the pack."""
        return self._devices

    def _parse_devices(self, parent: Element) -> None:
        # Extract device description elements we care about.
        newState = _DeviceInfo(element=parent)
        children: List[Element] = []
        for elem in parent:
            if elem.tag == 'memory':
                newState.memories.append(elem)
            elif elem.tag == 'algorithm':
                newState.algos.append(elem)
            elif elem.tag == 'debug':
                newState.debugs.append(elem)
            # Save any elements that we will recurse into.
            elif elem.tag in ('subFamily', 'device', 'variant'):
                children.append(elem)

        # Push the new device description state onto the stack.
        self._state_stack.append(newState)

        # Create a device object if this element defines one.
        if parent.tag in ('device', 'variant'):
            # Build device info from elements applying to this device.
            deviceInfo = _DeviceInfo(element=parent,
                                        families=self._extract_families(),
                                        memories=self._extract_memories(),
                                        algos=self._extract_algos(),
                                        debugs=self._extract_debugs()
                                        )

            dev = CmsisPackDevice(self.pack, deviceInfo)
            self._devices.append(dev)

        # Recursively process subelements.
        for elem in children:
            self._parse_devices(elem)

        self._state_stack.pop()

    def _extract_families(self) -> List[str]:
        """@brief Generate list of family names for a device."""
        families = []
        for state in self._state_stack:
            elem = state.element
            if elem.tag == 'family':
                families += [elem.attrib['Dvendor'], elem.attrib['Dfamily']]
            elif elem.tag == 'subFamily':
                families += [elem.attrib['DsubFamily']]
        return families

    ## Typevar used for _extract_items().
    V = TypeVar('V')

    def _extract_items(self, state_info_name: str, filter: Callable[[Dict[Any, V], Element], None]) -> List[V]:
        """@brief Generic extractor utility.

        Iterates over saved elements for the specified device state info for each level of the
        device state stack, from outer to inner, calling the provided filter callback each
        iteration. A dictionary object is created and repeatedly passed to the filter callback, so
        state can be stored across calls to the filter.

        The general idea is that the filter callback extracts some identifying information from the
        element it is given and uses that as a key in the dictionary. When the filter is called for
        more deeply nested elements, those elements will override the any previously examined
        elements with the same identifier.

        @return All values from the dictionary.
        """
        map = {}
        for state in self._state_stack:
            for elem in getattr(state, state_info_name):
                try:
                    filter(map, elem)
                except (KeyError, ValueError) as err:
                    LOG.debug("error parsing CMSIS-Pack: " + str(err))
        return list(map.values())

    def _extract_memories(self) -> List[Element]:
        """@brief Extract memory elements.

        The unique identifier is a bi-tuple of the memory's name, which is either the 'name' or 'id' attribute,
        in that order, plus the pname. If neither attribute exists, the region base and size are turned into
        a string.

        In addition to the name based filtering, memory regions are checked to prevent overlaps.
        """
        def get_start_and_size(elem: Element) -> Tuple[int, int]:
            try:
                start = int(elem.attrib['start'], base=0)
                size = int(elem.attrib['size'], base=0)
            except (KeyError, ValueError):
                LOG.warning("memory region missing address")
                raise
            return (start, size)

        def filter(map: Dict, elem: Element) -> None:
            # Inner memory regions are allowed to override outer memory
            # regions. If this is not done properly via name/id, we must make
            # sure not to report overlapping memory regions to gdb since it
            # will ignore those completely, see:
            # https://github.com/pyocd/pyOCD/issues/980
            start, size = get_start_and_size(elem)
            if 'name' in elem.attrib: # 'name' takes precedence over 'id'.
                name = elem.attrib['name']
            elif 'id' in elem.attrib:
                name = elem.attrib['id']
            else:
                # Neither option for memory name was specified, so use the address range.
                # Use the start and size for a name.
                name = "%08x:%08x" % (start, size)

            pname = elem.attrib.get('Pname', None)
            info = (name, pname)

            if info in map:
                del map[info]
            for k in list(map.keys()):
                prev_pname = k[1]
                # Previously, we would not check for overlaps if the pname was different. But because pyocd
                # currently only supports one memory map for the whole device, we have to ignore the pname for
                # now.
                prev_elem = map[k]
                prev_start, prev_size = get_start_and_size(prev_elem)
                # Overlap: start or end between previous start and previous end
                end = start + size - 1
                prev_end = prev_start + prev_size - 1
                if (prev_start <= start < prev_end) or (prev_start <= end < prev_end):
                    # Only report warnings for overlapping regions from the same processor. Allow regions for different
                    # processors to override each other, since we don't yet support maps for each processor.
                    if (pname == prev_pname) and not self._warned_overlapping_memory_regions:
                        filename = self.pack.filename if self.pack else "unknown"
                        LOG.warning("Overlapping memory regions in file %s (%s); deleting outer region. "
                                    "Further warnings will be suppressed for this file.",
                                    filename, _get_part_number_from_element(self._state_stack[-1].element))
                        self._warned_overlapping_memory_regions = True
                    del map[k]

            map[info] = elem

        return self._extract_items('memories', filter)

    def _extract_algos(self) -> List[Element]:
        """@brief Extract algorithm elements.

        The unique identifier is the algorithm's memory address range.

        Any algorithm elements with a 'style' attribuet not set to 'Keil' (case-insensitive) are
        skipped.
        """
        def filter(map: Dict, elem: Element) -> None:
            # We only support Keil FLM style flash algorithms (for now).
            if ('style' in elem.attrib) and (elem.attrib['style'].lower() != 'keil'):
                LOG.debug("skipping non-Keil flash algorithm")
                return

            # Both start and size are required.
            start = int(elem.attrib['start'], base=0)
            size = int(elem.attrib['size'], base=0)
            memrange = (start, size)

            # An algo with the same range as an existing algo will override the previous.
            map[memrange] = elem

        return self._extract_items('algos', filter)

    def _extract_debugs(self) -> List[Element]:
        """@brief Extract debug elements.

        If the debug element does not have a 'Pname' element, its identifier is set to "*" to
        represent that it applies to all processors.

        Otherwise, the identifier is the element's 'Pname' attribute combined with 'Punit' if
        present. When 'Pname' is detected and a "*" key is in the map, the map is cleared before
        adding the current element.
        """
        def filter(map: Dict, elem: Element) -> None:
            if 'Pname' in elem.attrib:
                name = elem.attrib['Pname']
                unit = elem.attrib.get('Punit', 0)
                name += str(unit)

                if '*' in map:
                    map.clear()
                map[name] = elem
            else:
                # No processor name was provided, so this debug element applies to
                # all processors.
                map.clear()
                map['*'] = elem

        return self._extract_items('debugs', filter)

def _get_bool_attribute(elem: Element, name: str, default: bool = False) -> bool:
    """@brief Extract an XML attribute with a boolean value.

    Supports "true"/"false" or "1"/"0" as the attribute values. Leading and trailing whitespace
    is stripped, and the comparison is case-insensitive.

    @param elem ElementTree.Element object.
    @param name String for the attribute name.
    @param default An optional default value if the attribute is missing. If not provided,
        the default is False.
    """
    if name not in elem.attrib:
        return default
    else:
        value = elem.attrib[name].strip().lower()
        if value in ("true", "1"):
            return True
        elif value in ("false", "0"):
            return False
        else:
            return default

class CmsisPackDevice:
    """@brief Wraps a device defined in a CMSIS Device Family Pack.

    Responsible for converting the XML elements that describe the device into objects
    usable by pyOCD. This includes the memory map and flash algorithms.

    An instance of this class can represent either a `<device>` or `<variant>` XML element from
    the PDSC.
    """

    def __init__(self, pack: CmsisPack, device_info: _DeviceInfo):
        """@brief Constructor.
        @param self
        @param pack The CmsisPack object that contains this device.
        @param device_info A _DeviceInfo object with the XML elements that describe this device.
        """
        self._pack: CmsisPack = pack
        self._info: _DeviceInfo = device_info
        self._part: str = _get_part_number_from_element(device_info.element)
        self._regions: List[MemoryRegion] = []
        self._saw_startup: bool = False
        self._default_ram: Optional[MemoryRegion] = None
        self._memory_map: Optional[MemoryMap] = None

    def _build_memory_regions(self) -> None:
        """@brief Creates memory region instances for the device.

        For each `<memory>` element in the device info, a memory region object is created and
        added to the `_regions` attribute. IROM or non-writable memories are created as RomRegions
        by this method. They will be converted to FlashRegions by _build_flash_regions().
        """
        for elem in self._info.memories:
            try:
                # Get the region name, type, and access permissions.
                if 'name' in elem.attrib:
                    name = elem.attrib['name']
                    access = elem.attrib['access']

                    if ('p' in access):
                        type = MemoryType.DEVICE
                    elif ('w' in access):
                        type = MemoryType.RAM
                    else:
                        type = MemoryType.ROM
                elif 'id' in elem.attrib:
                    name = elem.attrib['id']

                    if 'RAM' in name:
                        access = 'rwx'
                        type = MemoryType.RAM
                    else:
                        access = 'rx'
                        type = MemoryType.ROM
                else:
                    continue

                # Both start and size are required attributes.
                start = int(elem.attrib['start'], base=0)
                size = int(elem.attrib['size'], base=0)

                isDefault = _get_bool_attribute(elem, 'default')
                isStartup = _get_bool_attribute(elem, 'startup')
                if isStartup:
                    self._saw_startup = True

                attrs = {
                        'name': name,
                        'start': start,
                        'length': size,
                        'access': access,
                        'is_default': isDefault,
                        'is_boot_memory': isStartup,
                        'is_testable': isDefault,
                        'alias': elem.attrib.get('alias', None),
                    }

                # Create the memory region and add to map.
                region = MEMORY_TYPE_CLASS_MAP[type](**attrs)
                self._regions.append(region)

                # Record the first default ram for use in flash algos.
                if self._default_ram is None and type == MemoryType.RAM and isDefault:
                    self._default_ram = region
            except (KeyError, ValueError) as err:
                # Ignore errors.
                LOG.debug("ignoring error parsing memories for CMSIS-Pack devices %s: %s",
                    self.part_number, str(err))

    def _get_containing_region(self, addr: int) -> Optional[MemoryRegion]:
        """@brief Return the memory region containing the given address."""
        for region in self._regions:
            if region.contains_address(addr):
                return region
        return None

    def _build_flash_regions(self) -> None:
        """@brief Converts ROM memory regions to flash regions.

        Each ROM region in the `_regions` attribute is converted to a flash region if a matching
        flash algo can be found. If the flash has multiple sector sizes, then separate flash
        regions will be created for each sector size range. The flash algo is converted to a
        pyOCD-compatible flash algo dict by calling _get_pyocd_flash_algo().
        """
        # Must have a default ram.
        if self._default_ram is None:
            LOG.warning("CMSIS-Pack device %s has no default RAM defined, cannot program flash" % self.part_number)
            return

        # Can't import at top level due to import loops.
        from ...core.session import Session

        regions_to_delete = [] # List of regions to delete.
        regions_to_add = [] # List of FlashRegion objects to add.

        # Create flash algo dicts once we have the full memory map.
        for i, region in enumerate(self._regions):
            # We're only interested in ROM regions here.
            if region.type != MemoryType.ROM:
                continue

            # Look for matching flash algo.
            try:
                algo_element = self._find_matching_algo(region)
            except KeyError:
                # Must be a mask ROM or non-programmable flash.
                continue

            # Load flash algo from .FLM file.
            packAlgo = self._load_flash_algo(algo_element.attrib['name'])
            if packAlgo is None:
                LOG.warning("Failed to convert ROM region to flash region because flash algorithm '%s' could not be "
                            " found (%s)", algo_element.attrib['name'], self.part_number)
                continue

            # The ROM region will be replaced with one or more flash regions.
            regions_to_delete.append(region)

            # Log details of this flash algo if the debug option is enabled.
            current_session = Session.get_current()
            if current_session and current_session.options.get("debug.log_flm_info"):
                LOG.debug("Flash algo info: %s", packAlgo.flash_info)

            # Choose the page size. The check for <=32 is to handle some flash algos with incorrect
            # page sizes that are too small and probably represent the phrase size.
            page_size = packAlgo.page_size
            if page_size <= 32:
                page_size = min(s[1] for s in packAlgo.sector_sizes)

            # Select the RAM to use for the algo.
            try:
                # See if an explicit RAM range was specified for the algo.
                ram_start = int(algo_element.attrib['RAMstart'], base=0)

                # The region size comes either from the RAMsize attribute, the containing region's bounds, or
                # a large, arbitrary value.
                if 'RAMsize' in algo_element.attrib:
                    ram_size = int(algo_element.attrib['RAMsize'], base=0)
                else:
                    containing_region = self._get_containing_region(ram_start)
                    if containing_region is not None:
                        ram_size = containing_region.length - (ram_start - containing_region.start)
                    else:
                        # No size specified, and the RAMstart attribute is outside of a known region,
                        # so just use a relatively large arbitrary size. Because the algo is packed at the
                        # start of the provided region, this won't be a problem unless the DFP is
                        # actually erroneous.
                        ram_size = 128 * 1024

                ram_for_algo = RamRegion(start=ram_start, length=ram_size)
            except KeyError:
                # No RAM addresses were given, so go with the RAM marked default.
                ram_for_algo = self._default_ram

            # Construct the pyOCD algo using the largest sector size. We can share the same
            # algo for all sector sizes.
            algo = packAlgo.get_pyocd_flash_algo(page_size, ram_for_algo)

            # Create a separate flash region for each sector size range.
            regions_to_add += list(self._split_flash_region_by_sector_size(
                                            region, page_size, algo, packAlgo)) # type: ignore

        # Now update the regions list.
        for region in regions_to_delete:
            self._regions.remove(region)
        for region in regions_to_add:
            self._regions.append(region)

    def _split_flash_region_by_sector_size(self,
            region: MemoryRegion,
            page_size: int,
            algo: Dict[str, Any],
            pack_algo: PackFlashAlgo) -> Iterator[FlashRegion]:
        """@brief Yield separate flash regions for each sector size range."""
        # The sector_sizes attribute is a list of bi-tuples of (start-address, sector-size), sorted by start address.
        for j, (offset, sector_size) in enumerate(pack_algo.sector_sizes):
            start = region.start + offset

            # Determine the end address of the this sector range. For the last range, the end
            # is just the end of the entire region. Otherwise it's the start of the next
            # range - 1.
            if j + 1 >= len(pack_algo.sector_sizes):
                end = region.end
            else:
                end = region.start + pack_algo.sector_sizes[j + 1][0] - 1

            # Skip wrong start and end addresses
            if end < start:
                continue

            # Limit page size.
            if page_size > sector_size:
                region_page_size = sector_size
                LOG.warning("Page size (%d) is larger than sector size (%d) for flash region %s; "
                            "reducing page size to %d", page_size, sector_size, region.name,
                            region_page_size)
            else:
                region_page_size = page_size

            # If we don't have a boot memory yet, pick the first flash.
            if not self._saw_startup:
                is_boot = True
                self._saw_startup = True
            else:
                is_boot = region.is_boot_memory

            # Construct region name. If there is more than one sector size, we need to make the region's name unique.
            region_name = region.name
            if len(pack_algo.sector_sizes) > 1:
                region_name += f"_{sector_size:#x}"

            # Construct the flash region.
            yield FlashRegion(name=region_name,
                            access=region.access,
                            start=start,
                            end=end,
                            sector_size=sector_size,
                            page_size=region_page_size,
                            flm=pack_algo,
                            algo=algo,
                            erased_byte_value=pack_algo.flash_info.value_empty,
                            is_default=region.is_default,
                            is_boot_memory=is_boot,
                            is_testable=region.is_testable,
                            alias=region.alias)

    def _find_matching_algo(self, region: MemoryRegion) -> Element:
        """@brief Searches for a flash algo covering the regions's address range.'"""
        for algo in self._info.algos:
            # Both start and size are required attributes.
            algoStart = int(algo.attrib['start'], base=0)
            algoSize = int(algo.attrib['size'], base=0)
            algoEnd = algoStart + algoSize - 1

            # Check if the region indicated by start..size fits within the algo.
            if (algoStart <= region.start <= algoEnd) and (algoStart <= region.end <= algoEnd):
                return algo
        raise KeyError("no matching flash algorithm")

    def _load_flash_algo(self, filename: str) -> Optional[PackFlashAlgo]:
        """@brief Return the PackFlashAlgo instance for the given flash algo filename."""
        if self.pack is not None:
            try:
                algo_data = self.pack.get_file(filename)
                return PackFlashAlgo(algo_data)
            except FileNotFoundError:
                pass
        # Return default value.
        return None

    @property
    def pack(self) -> CmsisPack:
        """@brief The CmsisPack object that defines this device."""
        return self._pack

    @property
    def part_number(self) -> str:
        """@brief Part number for this device.

        This value comes from either the `Dname` or `Dvariant` attribute, depending on whether the
        device was created from a `<device>` or `<variant>` element.
        """
        return self._part

    @property
    def vendor(self) -> str:
        """@brief Vendor or manufacturer name."""
        return self._info.families[0].split(':')[0]

    @property
    def families(self) -> List[str]:
        """@brief List of families the device belongs to, ordered most generic to least."""
        return [f for f in self._info.families[1:]]

    @property
    def memory_map(self) -> MemoryMap:
        """@brief MemoryMap object."""
        # Lazily construct the memory map.
        if self._memory_map is None:
            self._build_memory_regions()
            self._build_flash_regions()

            # Warn if there was no boot memory.
            if not self._saw_startup:
                LOG.warning("CMSIS-Pack device %s has no identifiable boot memory", self.part_number)

            self._memory_map = MemoryMap(self._regions)

        return self._memory_map

    @property
    def svd(self) -> Optional[IO[bytes]]:
        """@brief File-like object for the device's SVD file.
        @todo Support multiple cores.
        """
        try:
            svdPath = self._info.debugs[0].attrib['svd']
            return self._pack.get_file(svdPath)
        except (KeyError, IndexError):
            return None

    @property
    def default_reset_type(self) -> Target.ResetType:
        """@brief One of the Target.ResetType enums.
        @todo Support multiple cores.
        """
        try:
            resetSequence = self._info.debugs[0].attrib['defaultResetSequence']
            if resetSequence == 'ResetHardware':
                return Target.ResetType.HW
            elif resetSequence == 'ResetSystem':
                return Target.ResetType.SW_SYSRESETREQ
            elif resetSequence == 'ResetProcessor':
                return Target.ResetType.SW_VECTRESET
            else:
                return Target.ResetType.SW
        except (KeyError, IndexError):
            return Target.ResetType.SW

    def __repr__(self):
        return "<%s@%x %s>" % (self.__class__.__name__, id(self), self.part_number)




