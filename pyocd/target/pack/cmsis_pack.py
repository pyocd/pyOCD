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
from typing import Optional

from .flash_algo import PackFlashAlgo
from ...core import exceptions
from ...core.target import Target
from ...core.memory_map import (MemoryMap, MemoryType, MEMORY_TYPE_CLASS_MAP, FlashRegion)

LOG = logging.getLogger(__name__)

class MalformedCmsisPackError(exceptions.TargetSupportError):
    """! @brief Exception raised for errors parsing a CMSIS-Pack."""
    pass

class _DeviceInfo(object):
    """! @brief Simple container class to hold XML elements describing a device."""
    def __init__(self, **kwargs):
        self.element = kwargs.get('element', None)
        self.families = kwargs.get('families', [])
        self.memories = kwargs.get('memories', [])
        self.algos = kwargs.get('algos', [])
        self.debugs = kwargs.get('debugs', [])

def _get_part_number_from_element(element: Element) -> str:
    """! @brief Extract the part number from a device or variant XML element."""
    assert element.tag in ("device", "variant")
    if element.tag == "device":
        return element.attrib['Dname']
    elif element.tag == "variant":
        return element.attrib['Dvariant']
    else:
        raise ValueError("element is neither device nor variant")

class CmsisPack(object):
    """! @brief Wraps a CMSIS Device Family Pack.
    
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
    def __init__(self, file_or_path):
        """! @brief Constructor.
        
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
    def filename(self):
        """! @brief Accessor for the filename or path of the .pack file."""
        return self._pack_file.filename
    
    @property
    def pdsc(self):
        """! @brief Accessor for the CmsisPackDescription instance for the pack's PDSC file."""
        return self._pdsc
    
    @property
    def devices(self):
        """! @brief A list of CmsisPackDevice objects for every part number defined in the pack."""
        return self._pdsc.devices
    
    def get_file(self, filename):
        """! @brief Return file-like object for a file within the pack.
        
        @param self
        @param filename Relative path within the pack. May use forward or back slashes.
        @return A BytesIO object is returned that contains all of the data from the file
            in the pack. This is done to isolate the returned file from how the pack was
            opened (due to particularities of the ZipFile implementation).
        """
        filename = filename.replace('\\', '/')
        return io.BytesIO(self._pack_file.read(filename))

class CmsisPackDescription(object):
    def __init__(self, pack, pdsc_file):
        """! @brief Constructor.
        
        @param self This object.
        @param pack Reference to the CmsisPack instance.
        @param pdsc_file A file-like object for the .pdsc contained in _pack_.
        """
        self._pack = pack
        
        # Convert PDSC into an ElementTree.
        self._pdsc = ElementTree(file=pdsc_file)

        self._state_stack = []
        self._devices = []
        
        # Remember if we have already warned about overlapping memory regions
        # so we can limit these to one warning per DFP
        self._warned_overlapping_memory_regions = False
        
        # Extract devices.
        for family in self._pdsc.iter('family'):
            self._parse_devices(family)
    
    @property
    def pack(self):
        """! @brief Reference to the containing CmsisPack object."""
        return self._pack
    
    @property
    def devices(self):
        """! @brief A list of CmsisPackDevice objects for every part number defined in the pack."""
        return self._devices
    
    def _parse_devices(self, parent):
        # Extract device description elements we care about.
        newState = _DeviceInfo(element=parent)
        children = []
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

    def _extract_families(self):
        families = []
        for state in self._state_stack:
            elem = state.element
            if elem.tag == 'family':
                families += [elem.attrib['Dvendor'], elem.attrib['Dfamily']]
            elif elem.tag == 'subFamily':
                families += [elem.attrib['DsubFamily']]
        return families

    def _extract_items(self, state_info_name, filter):
        map = {}
        for state in self._state_stack:
            for elem in getattr(state, state_info_name):
                try:
                    filter(map, elem)
                except (KeyError, ValueError) as err:
                    LOG.debug("error parsing CMSIS-Pack: " + str(err))
        return list(map.values())

    def _extract_memories(self):
        def get_start_and_size(elem):
            try:
                start = int(elem.attrib['start'], base=0)
                size = int(elem.attrib['size'], base=0)
            except (KeyError, ValueError):
                LOG.warning("memory region missing address")
                raise
            return (start, size)
        def filter(map, elem):
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

    def _extract_algos(self):
        def filter(map, elem):
            # We only support Keil FLM style flash algorithms (for now).
            if ('style' in elem.attrib) and (elem.attrib['style'] != 'Keil'):
                LOG.debug("skipping non-Keil flash algorithm")
                return None, None
    
            # Both start and size are required.
            start = int(elem.attrib['start'], base=0)
            size = int(elem.attrib['size'], base=0)
            memrange = (start, size)
    
            # An algo with the same range as an existing algo will override the previous.
            map[memrange] = elem
        
        return self._extract_items('algos', filter)
    
    def _extract_debugs(self):
        def filter(map, elem):
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

def _get_bool_attribute(elem, name, default=False):
    """! @brief Extract an XML attribute with a boolean value.
    
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

class CmsisPackDevice(object):
    """! @brief Wraps a device defined in a CMSIS Device Family Pack.
    
    Responsible for converting the XML elements that describe the device into objects
    usable by pyOCD. This includes the memory map and flash algorithms.
    
    An instance of this class can represent either a `<device>` or `<variant>` XML element from
    the PDSC.
    """

    def __init__(self, pack, device_info):
        """! @brief Constructor.
        @param self
        @param pack The CmsisPack object that contains this device.
        @param device_info A _DeviceInfo object with the XML elements that describe this device.
        """
        self._pack = pack
        self._info = device_info
        self._part = _get_part_number_from_element(device_info.element)
        self._regions = []
        self._saw_startup = False
        self._default_ram = None
        self._memory_map = None
            
    def _build_memory_regions(self):
        """! @brief Creates memory region instances for the device.
        
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
    
    def _build_flash_regions(self):
        """! @brief Converts ROM memory regions to flash regions.
        
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
            algo = self._find_matching_algo(region)
            if algo is None:
                # Must be a mask ROM or non-programmable flash.
                continue

            # Load flash algo from .FLM file.
            packAlgo = self._load_flash_algo(algo.attrib['name'])
            if packAlgo is None:
                LOG.warning("Failed to convert ROM region to flash region because flash algorithm '%s' could not be "
                            " found (%s)", algo.attrib['name'], self.part_number)
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
            
            # Construct the pyOCD algo using the largest sector size. We can share the same
            # algo for all sector sizes.
            algo = packAlgo.get_pyocd_flash_algo(page_size, self._default_ram)

            # Create a separate flash region for each sector size range. The sector_sizes attribute
            # is a list of bi-tuples of (start-address, sector-size), sorted by start address.
            for j, sectorInfo in enumerate(packAlgo.sector_sizes):
                # Unpack this sector range's start address and sector size.
                offset, sector_size = sectorInfo
                start = region.start + offset
                
                # Determine the end address of the this sector range. For the last range, the end
                # is just the end of the entire region. Otherwise it's the start of the next
                # range - 1.
                if j + 1 >= len(packAlgo.sector_sizes):
                    end = region.end
                else:
                    end = region.start + packAlgo.sector_sizes[j + 1][0] - 1
                
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
                    isBoot = True
                    self._saw_startup = True
                else:
                    isBoot = region.is_boot_memory
                
                # Construct the flash region.
                rangeRegion = FlashRegion(name=region.name,
                                access=region.access,
                                start=start,
                                end=end,
                                sector_size=sector_size,
                                page_size=region_page_size,
                                flm=packAlgo,
                                algo=algo,
                                erased_byte_value=packAlgo.flash_info.value_empty,
                                is_default=region.is_default,
                                is_boot_memory=isBoot,
                                is_testable=region.is_testable,
                                alias=region.alias)
                regions_to_add.append(rangeRegion)
        
        # Now update the regions list.
        for region in regions_to_delete:
            self._regions.remove(region)
        for region in regions_to_add:
            self._regions.append(region)
    
    def _find_matching_algo(self, region):
        """! @brief Searches for a flash algo covering the regions's address range.'"""
        for algo in self._info.algos:
            # Both start and size are required attributes.
            algoStart = int(algo.attrib['start'], base=0)
            algoSize = int(algo.attrib['size'], base=0)
            algoEnd = algoStart + algoSize - 1
        
            # Check if the region indicated by start..size fits within the algo.
            if (algoStart <= region.start <= algoEnd) and (algoStart <= region.end <= algoEnd):
                return algo
        return None
    
    def _load_flash_algo(self, filename: str) -> Optional[PackFlashAlgo]:
        """! @brief Return the PackFlashAlgo instance for the given flash algo filename."""
        if self.pack is not None:
            try:
                algo_data = self.pack.get_file(filename)
                return PackFlashAlgo(algo_data)
            except FileNotFoundError:
                pass
        # Return default value.
        return None

    @property
    def pack(self):
        """! @brief The CmsisPack object that defines this device."""
        return self._pack
    
    @property
    def part_number(self):
        """! @brief Part number for this device.
        
        This value comes from either the `Dname` or `Dvariant` attribute, depending on whether the
        device was created from a `<device>` or `<variant>` element.
        """
        return self._part
    
    @property
    def vendor(self):
        """! @brief Vendor or manufacturer name."""
        return self._info.families[0].split(':')[0]
    
    @property
    def families(self):
        """! @brief List of families the device belongs to, ordered most generic to least."""
        return [f for f in self._info.families[1:]]
    
    @property
    def memory_map(self):
        """! @brief MemoryMap object."""
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
    def svd(self):
        """! @brief File-like object for the device's SVD file.
        @todo Support multiple cores.
        """
        try:
            svdPath = self._info.debugs[0].attrib['svd']
            return self._pack.get_file(svdPath)
        except (KeyError, IndexError):
            return None
    
    @property
    def default_reset_type(self):
        """! @brief One of the Target.ResetType enums.
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
        
        

 
