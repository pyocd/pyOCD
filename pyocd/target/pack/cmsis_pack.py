# -*- coding: utf-8 -*-
# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
# Copyright (c) 2020 Men Shiyun
# Copyright (c) 2020 Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
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

from dataclasses import (dataclass, field)
from xml.etree.ElementTree import (ElementTree, Element)
import zipfile
import logging
import io
import errno
from pathlib import Path
from typing import (Any, Callable, Dict, List, IO, Optional, Tuple, TypeVar, Set, Union)

from .flash_algo import PackFlashAlgo
from ...core import exceptions
from ...core.memory_map import (
    FlashRegion,
    MemoryMap,
    MemoryRange,
    MemoryRegion,
    MemoryType,
    MEMORY_TYPE_CLASS_MAP,
)

LOG = logging.getLogger(__name__)

class MalformedCmsisPackError(exceptions.TargetSupportError):
    """@brief Exception raised for errors parsing a CMSIS-Pack."""
    pass

@dataclass
class _DeviceInfo:
    """@brief Simple container class to hold XML elements describing a device."""
    element: Element
    families: List[str] = field(default_factory=list)
    memories: List[Element] = field(default_factory=list)
    algos: List[Element] = field(default_factory=list)
    debugs: List[Element] = field(default_factory=list)

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
    def __init__(self, file_or_path: Union[str, zipfile.ZipFile, IO[bytes], Path]) -> None:
        """@brief Constructor.

        Opens the CMSIS-Pack and builds instances of CmsisPackDevice for all the devices
        and variants defined within the pack.

        @param self
        @param file_or_path The .pack file to open. These values are supported:
            - String that is the path to a .pack file (a Zip file).
            - String that is the path to the root directory of an expanded pack.
            - `ZipFile` object.
            - File-like object that is already opened.

        @exception MalformedCmsisPackError The pack is not a zip file, or the .pdsc file is missing
            from within the pack.
        """
        self._is_dir = False
        if isinstance(file_or_path, zipfile.ZipFile):
            self._pack_file = file_or_path
        else:
            # Check for an expanded pack as a directory.
            if isinstance(file_or_path, (str, Path)):
                path = Path(file_or_path).expanduser()
                file_or_path = str(path) # Update with expanded path.

                self._is_dir = path.is_dir()
                if self._is_dir:
                    self._dir_path = path

            if not self._is_dir:
                try:
                    self._pack_file = zipfile.ZipFile(file_or_path, 'r')
                except zipfile.BadZipFile as err:
                    raise MalformedCmsisPackError(f"Failed to open CMSIS-Pack '{file_or_path}': {err}") from err

        # Find the .pdsc file.
        if self._is_dir:
            for child_path in self._dir_path.iterdir():
                if child_path.suffix == '.pdsc':
                    self._pdsc_name = child_path.name
                    break
            else:
                raise MalformedCmsisPackError(f"CMSIS-Pack '{file_or_path}' is missing a .pdsc file")
        else:
            for name in self._pack_file.namelist():
                if name.endswith('.pdsc'):
                    self._pdsc_name = name
                    break
            else:
                raise MalformedCmsisPackError(f"CMSIS-Pack '{file_or_path}' is missing a .pdsc file")

        if self._is_dir:
            with (self._dir_path / self._pdsc_name).open('rb') as pdsc_file:
                self._pdsc = CmsisPackDescription(self, pdsc_file)
        else:
            with self._pack_file.open(self._pdsc_name) as pdsc_file:
                self._pdsc = CmsisPackDescription(self, pdsc_file)

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

    def get_file(self, filename: str) -> IO[bytes]:
        """@brief Return file-like object for a file within the pack.

        @param self
        @param filename Relative path within the pack. May use forward or back slashes.
        @return A BytesIO object is returned that contains all of the data from the file
            in the pack. This is done to isolate the returned file from how the pack was
            opened (due to particularities of the ZipFile implementation).
        """
        filename = filename.replace('\\', '/')

        # Some vendors place their pdsc in some subdirectories of the pack archive,
        # use relative directory to the pdsc file while reading other files.
        pdsc_base = self._pdsc_name.rsplit('/', 1)
        if len(pdsc_base) == 2:
            filename = f'{pdsc_base[0]}/{filename}'

        if self._is_dir:
            path = self._dir_path / filename
            return io.BytesIO(path.read_bytes())
        else:
            return io.BytesIO(self._pack_file.read(filename))

class CmsisPackDescription:
    """@brief Parser for the PDSC XML file describing a CMSIS-Pack.
    """

    def __init__(self, pack: CmsisPack, pdsc_file: IO[bytes]) -> None:
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
    def pack_name(self) -> Optional[str]:
        """@brief Name of the CMSIS-Pack.
        @return Contents of the required <name> element, or None if missing.
        """
        return self._pdsc.findtext('name')

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

            # Support ._pack being None for testing.
            dev = CmsisPackDevice(self, deviceInfo, self._pack.get_file if self._pack else None)
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
    _V = TypeVar('_V')

    def _extract_items(
                self,
                state_info_name: str,
                filter: Callable[[Dict[Any, _V], Element], None]
            ) -> List[_V]:
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
                    LOG.debug("error parsing CMSIS-Pack %s: %s", self.pack_name, err)
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
                LOG.debug("%s DFP: skipping non-Keil flash algorithm", self.pack_name)
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
    usable by pyOCD. This includes the memory map and flash algorithms. All extraction of data
    into usuable data structures is done lazily, since a CmsisPackDevice instance will be
    created for every device in installed DFPs but only one will actually be used per session.

    An instance of this class can represent either a `<device>` or `<variant>` XML element from
    the PDSC.
    """

    def __init__(self, pdsc: CmsisPackDescription, device_info: _DeviceInfo,
            get_pack_file_cb: Optional[Callable[[str], IO[bytes]]]) -> None:
        """@brief Constructor.
        @param self
        @param pdsc The CmsisPackDescription object that contains this device.
        @param device_info A _DeviceInfo object with the XML elements that describe this device.
        @param get_pack_file_cb Callable taking a relative filename and returning an open bytes file. May
            raise IOError exceptions. If not supplied, then no flash algorithms or other files used by
            the device description are accessible (primarily for testing).
        """
        self._pdsc = pdsc
        self._info: _DeviceInfo = device_info
        self._get_pack_file_cb = get_pack_file_cb
        self._part: str = _get_part_number_from_element(device_info.element)
        self._regions: List[MemoryRegion] = []
        self._saw_startup: bool = False
        self._default_ram: Optional[MemoryRegion] = None
        self._memory_map: Optional[MemoryMap] = None
        self._processed_algos: Set[Element] = set() # Algo elements we've converted to regions.

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

                is_default = _get_bool_attribute(elem, 'default')
                is_startup = _get_bool_attribute(elem, 'startup')
                if is_startup:
                    self._saw_startup = True

                attrs = {
                        'name': name,
                        'start': start,
                        'length': size,
                        'access': access,
                        'is_default': is_default,
                        'is_boot_memory': is_startup,
                        'is_testable': is_default,
                        'alias': elem.attrib.get('alias', None),
                    }

                # See if we can convert ROM memory to flash.
                if type is MemoryType.ROM and self._set_flash_attributes(attrs):
                    type = MemoryType.FLASH

                    # If we don't have a boot memory yet, pick the first flash.
                    if not self._saw_startup:
                        attrs['is_boot_memory'] = True
                        self._saw_startup = True

                # Create the memory region and add to map.
                region = MEMORY_TYPE_CLASS_MAP[type](**attrs)
                self._regions.append(region)

                # Record the first default ram for use in flash algos.
                if (self._default_ram is None) and (type is MemoryType.RAM) and is_default:
                    self._default_ram = region
            except (KeyError, ValueError) as err:
                # Ignore errors.
                LOG.debug("ignoring error parsing memories for CMSIS-Pack devices %s: %s",
                    self.part_number, str(err))

        # Now create flash regions for any algos we didn't process.
        for algo in [a for a in self._info.algos if a not in self._processed_algos]:
            # Should this algo be loaded by default?
            is_default = _get_bool_attribute(algo, 'default')
            if not is_default:
                LOG.debug("%s DFP (%s): not loading non-default flash algorithm '%s'",
                    self.pack_description.pack_name, self.part_number, algo.attrib['name'])
                continue

            # Load flash algo from .FLM file so we can get its address range, etc.
            pack_algo = self._load_flash_algo(algo.attrib['name'])
            if pack_algo is None:
                LOG.warning(f"{self.pack_description.pack_name} DFP ({self.part_number}): "
                    f"failed to find or load flash algorithm '{algo.attrib['name']}'")
                continue

            # If we don't have a boot memory yet, pick the first flash.
            if not self._saw_startup:
                is_boot_memory = True
                self._saw_startup = True
            else:
                is_boot_memory = False

            ram_attrs = self._get_flash_ram_attributes(algo)

            # Create the memory region.
            region = FlashRegion(
                        name=pack_algo.flash_info.name.decode(encoding='ascii'),
                        start=pack_algo.flash_start,
                        length=pack_algo.flash_size,
                        access='rx',
                        flm=pack_algo,
                        sector_size=0,
                        # Mark the flash memory as inaccessible at boot, just to be safe. There's
                        # no real way to be sure about this. The vendor should have create a
                        # <memory> element!
                        is_default=False,
                        # Similarly, disallow testing of this region since we're not sure. This will
                        # make it impossible to run functional tests on some devices without a user
                        # script to help out.
                        is_testable=False,
                        **ram_attrs,
                        )
            self._regions.append(region)

    def _get_flash_ram_attributes(self, algo_element: Element) -> Dict[str, int]:
        attrs: Dict[str, int] = {}
        if 'RAMstart' in algo_element.attrib:
            attrs['_RAMstart'] = int(algo_element.attrib['RAMstart'], base=0)
            if 'RAMsize' in algo_element.attrib:
                attrs['_RAMsize'] = int(algo_element.attrib['RAMsize'], base=0)
            else:
                LOG.warning(
                    f"{self.pack_description.pack_name} DFP ({self.part_number}): "
                    f"flash algorithm '{algo_element.attrib['name']}' has RAMstart but is "
                    "missing RAMsize")

        return attrs

    def _set_flash_attributes(self, attrs: dict) -> bool:
        try:
            # Look for matching flash algo.
            # TODO multiple matching algos per region
            algo_element = self._find_matching_algo(MemoryRange(attrs['start'], length=attrs['length']))
        except KeyError:
            # Must be a mask ROM or non-programmable flash.
            return False

        # Mark this algo as processed.
        self._processed_algos.add(algo_element)

        # Load flash algo from .FLM file.
        pack_algo = self._load_flash_algo(algo_element.attrib['name'])
        if pack_algo is None:
            LOG.warning(f"{self.pack_description.pack_name} DFP ({self.part_number}): "
                f"failed to find or load flash algorithm '{algo_element.attrib['name']}'")
            return False

        attrs['flm'] = pack_algo

        # Save the algo element's RAM attributes in the region for later use in
        # CoreSightTarget.create_flash().
        ram_attrs = self._get_flash_ram_attributes(algo_element)
        attrs.update(ram_attrs)

        # Set sector size to a fixed value to prevent any possibility of infinite recursion due to
        # the default lambdas for sector_size and blocksize returning each other's value.
        attrs['sector_size'] = 0

        # We have at least a partially matching algo. Change type to flash.
        return True

    def _find_matching_algo(self, range: MemoryRange) -> Element:
        """@brief Searches for a flash algo overlapping the regions's address range.

        The algo and region's ranges just have to overlap. There are some DFPs that specify algos that
        don't fully cover the region range, and potentially vice versa. It is possible that one algo
        covers more than one region, but that is handled by the method calling this one (per region).
        """
        for algo in self._info.algos:
            try:
                # Both start and size are required attributes.
                algo_range = MemoryRange(start=self._get_int_attribute(algo, 'start'),
                                            length=self._get_int_attribute(algo, 'size'))
            except MalformedCmsisPackError:
                # Ignore this algorithm. A warning has already been logged.
                continue

            # Check if the region and the algo overlap.
            if range.intersects_range(range=algo_range):
                # Verify this is a valid algorithm specification.
                if 'name' not in algo.attrib:
                    LOG.debug(
                        f"{self.pack_description.pack_name} DFP ({self.part_number}): flash algorithm "
                        f"covering {algo_range.start:x}-{algo_range.end:x} missing required 'name' element")
                else:
                    return algo
        raise KeyError("no matching flash algorithm")

    def _load_flash_algo(self, filename: str) -> Optional[PackFlashAlgo]:
        """@brief Return the PackFlashAlgo instance for the given flash algo filename."""
        try:
            algo_data = self.get_file(filename)
            return PackFlashAlgo(algo_data)
        except FileNotFoundError:
            # Return default value.
            return None

    def get_file(self, filename: str) -> IO[bytes]:
        """@brief Return file-like object for a file within the containing pack.

        @param self
        @param filename Relative path within the pack. May use forward or back slashes.
        @return A BytesIO object is returned that contains all of the data from the file
            in the pack. This is done to isolate the returned file from how the pack was
            opened (due to particularities of the ZipFile implementation).

        @exception OSError A problem occurred opening the file.
        @exception FileNotFoundError In addition to the usual case of the file actually not being found,
            this exception is raised if no `get_pack_file_cb` was passed to the constructor.
        """
        if self._get_pack_file_cb:
            return self._get_pack_file_cb(filename)
        else:
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", filename)

    @property
    def pack_description(self) -> CmsisPackDescription:
        """@brief The CmsisPackDescription object that defines this device."""
        return self._pdsc

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
            return self.get_file(svdPath)
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




