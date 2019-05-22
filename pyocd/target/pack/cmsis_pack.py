# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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

from __future__ import print_function
from xml.etree.ElementTree import ElementTree
import zipfile
from collections import namedtuple
import logging
import io
import itertools
import six
import struct

# zipfile from Python 2 has a misspelled BadZipFile exception class.
try:
    from zipfile import BadZipFile
except ImportError:
    from zipfile import BadZipfile as BadZipFile

from .flash_algo import PackFlashAlgo
from ... import core
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
            except BadZipFile as err:
                six.raise_from(MalformedCmsisPackError("Failed to open CMSIS-Pack '{}': {}".format(
                    file_or_path, err)), err)
        
        # Find the .pdsc file.
        for name in self._pack_file.namelist():
            if name.endswith('.pdsc'):
                self._pdscName = name
                break
        else:
            raise MalformedCmsisPackError("CMSIS-Pack '{}' is missing a .pdsc file".format(file_or_path))
        
        # Convert PDSC into an ElementTree.
        with self._pack_file.open(self._pdscName) as pdscFile:
            self._pdsc = ElementTree(file=pdscFile)

        self._state_stack = []
        self._devices = []
        
        # Extract devices.
        for family in self._pdsc.iter('family'):
            self._parse_devices(family)
    
    @property
    def pdsc(self):
        """! @brief Accessor for the ElementTree instance for the pack's PDSC file."""
        return self._pdsc
    
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
            
            dev = CmsisPackDevice(self, deviceInfo)
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
        def filter(map, elem):
            if 'name' in elem.attrib:
                name = elem.attrib['name']
            elif 'id' in elem.attrib:
                name = elem.attrib['id']
            else:
                # Neither option for memory name was specified, so skip this region.
                LOG.debug("skipping unnamed memmory region")
                return
        
            map[name] = elem
        
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
        
        if device_info.element.tag == "device":
            self._part = device_info.element.attrib['Dname']
        elif device_info.element.tag == "variant":
            self._part = device_info.element.attrib['Dvariant']
        
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

            # Remove the ROM region that we'll replace with flash region(s).
            del self._regions[i]

            # Load flash algo from .FLM file.
            algoData = self.pack.get_file(algo.attrib['name'])
            packAlgo = PackFlashAlgo(algoData)
            
            # Log details of this flash algo if the debug option is enabled.
            current_session = core.session.Session.get_current()
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

            # Create a separate flash region for each sector size range.
            for i, sectorInfo in enumerate(packAlgo.sector_sizes):
                start, sector_size = sectorInfo
                if i + 1 >= len(packAlgo.sector_sizes):
                    nextStart = region.length
                else:
                    nextStart, _ = packAlgo.sector_sizes[i + 1]
                
                length = nextStart - start
                start += region.start
                
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
                                length=length,
                                sector_size=sector_size,
                                page_size=region_page_size,
                                flm=packAlgo,
                                algo=algo,
                                erased_byte_value=packAlgo.flash_info.value_empty,
                                is_default=region.is_default,
                                is_boot_memory=isBoot,
                                is_testable=region.is_testable,
                                alias=region.alias)
                self._regions.append(rangeRegion)
    
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
        return "<%s@%x %s %s>" % (self.__class__.__name__, id(self), self.part_number, self._info)
        
        

 
