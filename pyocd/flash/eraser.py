# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

import logging
from enum import Enum

from ..core.memory_map import MemoryType

LOG = logging.getLogger(__name__)

class FlashEraser(object):
    """! @brief Class that manages high level flash erasing.
    
    Can erase a target in one of three modes:
    - chip erase: Erase all flash on the target.
    - mass erase: Also erase all flash on the target. However, on some targets, a mass erase has
        special properties such as unlocking security or erasing additional configuration regions
        that are not erased by a chip erase. If a target does not have a special mass erase, then
        it simply reverts to a chip erase.
    - sector erase: One or more sectors are erased.
    """
    class Mode(Enum):
        MASS = 1
        CHIP = 2
        SECTOR = 3
    
    def __init__(self, session, mode):
        """! @brief Constructor.
        
        @param self
        @param session The session instance.
        @param mode One of the FlashEraser.Mode enums to select mass, chip, or sector erase.
        """
        self._session = session
        self._mode = mode
    
    def erase(self, addresses=None):
        """! @brief Perform the type of erase operation selected when the object was created.
        
        For sector erase mode, an iterable of sector addresses specifications must be provided via
        the _addresses_ parameter. The address iterable elements can be either strings, tuples,
        or integers. Tuples must have two elements, the start and end addresses of a range to erase.
        Integers are simply an address within the single page to erase.
        
        String address specifications may be in one of three formats: "<address>", "<start>-<end>",
        or "<start>+<length>". Each field denoted by angled brackets is an integer literal in
        either decimal or hex notation.
        
        Examples:
        - "0x1000" - erase the one sector at 0x1000
        - "0x1000-0x4fff" - erase sectors from 0x1000 up to but not including 0x5000
        - "0x8000+0x800" - erase sectors starting at 0x8000 through 0x87ff
        
        @param self
        @param addresses List of addresses or address ranges of the sectors to erase.
        """
        if self._mode == self.Mode.MASS:
            self._mass_erase()
        elif self._mode == self.Mode.CHIP:
            self._chip_erase()
        elif self._mode == self.Mode.SECTOR and addresses:
            self._sector_erase(addresses)
        else:
            LOG.warning("No operation performed")
    
    def _mass_erase(self):
        LOG.info("Mass erasing device...")
        if self._session.target.mass_erase():
            LOG.info("Successfully erased.")
        else:
            LOG.error("Mass erase failed.")
    
    def _chip_erase(self):
        LOG.info("Erasing chip...")
        # Erase all flash regions. This may be overkill if either each region's algo erases
        # all regions on the chip. But there's no current way to know whether this will happen,
        # so prefer to be certain.
        for region in self._session.target.memory_map.iter_matching_regions(type=MemoryType.FLASH):
            if region.flash is not None:
                if region.flash.is_erase_all_supported:
                    region.flash.init(region.flash.Operation.ERASE)
                    region.flash.erase_all()
                    region.flash.cleanup()
                else:
                    self._sector_erase([(region.start, region.end)])
        LOG.info("Done")
    
    def _sector_erase(self, addresses):
        flash = None
        currentRegion = None

        for spec in addresses:
            # Convert the spec into a start and end address.
            sector_addr, end_addr = self._convert_spec(spec)
            
            while sector_addr < end_addr:
                # Look up the flash memory region for the current address.
                region = self._session.target.memory_map.get_region_for_address(sector_addr)
                if region is None:
                    LOG.warning("address 0x%08x is not within a memory region", sector_addr)
                    break
                if not region.is_flash:
                    LOG.warning("address 0x%08x is not in flash", sector_addr)
                    break
            
                # Handle switching regions.
                if region is not currentRegion:
                    # Clean up previous flash.
                    if flash is not None:
                        flash.cleanup()
                
                    currentRegion = region
                    flash = region.flash
                    flash.init(flash.Operation.ERASE)
        
                assert flash is not None
                
                # Get sector info for the current address.
                sector_info = flash.get_sector_info(sector_addr)
                assert sector_info, ("sector address 0x%08x within flash region '%s' is invalid"
                                        % (sector_addr, region.name))
                
                # Align first page address.
                delta = sector_addr % sector_info.size
                if delta:
                    LOG.warning("sector address 0x%08x is unaligned", sector_addr)
                    sector_addr -= delta
        
                # Erase this page.
                LOG.info("Erasing sector 0x%08x (%d bytes)", sector_addr, sector_info.size)
                flash.erase_sector(sector_addr)
                
                sector_addr += sector_info.size

        if flash is not None:
            flash.cleanup()

    def _convert_spec(self, spec):
        if isinstance(spec, str):
            # Convert spec from string to range.
            if '-' in spec:
                a, b = spec.split('-')
                page_addr = int(a, base=0)
                end_addr = int(b, base=0)
            elif '+' in spec:
                a, b = spec.split('+')
                page_addr = int(a, base=0)
                length = int(b, base=0)
                end_addr = page_addr + length
            else:
                page_addr = int(spec, base=0)
                end_addr = page_addr + 1
        elif isinstance(spec, tuple):
            page_addr = spec[0]
            end_addr = spec[1]
        else:
            page_addr = spec
            end_addr = page_addr + 1
        return page_addr, end_addr


