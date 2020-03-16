# pyOCD debugger
# Copyright (c) 2015-2018 Arm Limited
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

from ..core import exceptions
from .component import CoreSightComponent
from .gpr import GPR
from .component_ids import COMPONENT_MAP
from ..utility.conversion import pairwise
from ..utility.mask import (bit_invert, align_down)
from ..utility.timeout import Timeout

# CoreSight identification register offsets.
DEVARCH = 0xfbc
DEVID = 0xfc8
DEVTYPE = 0xfcc
PIDR4 = 0xfd0
PIDR0 = 0xfe0
CIDR0 = 0xff0
IDR_END = 0x1000

# Range of identification registers to read at once and offsets in results.
#
# To improve component identification performance, we read all of a components
# CoreSight ID registers in a single read. Reading starts at the DEVARCH register.
IDR_READ_START = DEVARCH
IDR_READ_COUNT = (IDR_END - IDR_READ_START) // 4
DEVARCH_OFFSET = (DEVARCH - IDR_READ_START) // 4
DEVTYPE_OFFSET = (DEVTYPE - IDR_READ_START) // 4
PIDR4_OFFSET = (PIDR4 - IDR_READ_START) // 4
PIDR0_OFFSET = (PIDR0 - IDR_READ_START) // 4
CIDR0_OFFSET = (CIDR0 - IDR_READ_START) // 4

# Component ID register fields.
CIDR_PREAMBLE_MASK = 0xffff0fff
CIDR_PREAMBLE_VALUE = 0xb105000d

CIDR_COMPONENT_CLASS_MASK = 0x0000f000
CIDR_COMPONENT_CLASS_SHIFT = 12

# Component classes.
ROM_TABLE_CLASS = 0x1
CORESIGHT_CLASS = 0x9
GENERIC_CLASS = 0xe
SYSTEM_CLASS = 0xf # CoreLink, PrimeCell, or other system component with no standard register layout.

# Peripheral ID register fields.
PIDR_PART_MASK = 0x00000fff
PIDR_DESIGNER_MASK = 0x0007f000 # JEP106 ID
PIDR_DESIGNER_SHIFT = 12
PIDR_REVISION_MASK = 0x00f00000
PIDR_REVISION_SHIFT = 20
PIDR_DESIGNER2_MASK = 0x0f00000000 # JEP106 continuation
PIDR_DESIGNER2_SHIFT = 32

# JEP106 codes
#  [11:8] continuation
#  [6:0]  ID
ARM_ID = 0x43b
FSL_ID = 0x00e

# DEVARCH register fields.
DEVARCH_ARCHITECT_MASK = 0x7ff
DEVARCH_ARCHITECT_SHIFT = 21
DEVARCH_PRESENT_MASK = (1<<20)
DEVARCH_REVISION_MASK = 0x000f0000
DEVARCH_REVISION_SHIFT = 16
DEVARCH_ARCHID_MASK = 0xffff

LOG = logging.getLogger(__name__)

class CoreSightComponentID(object):
    """! @brief Reads and parses CoreSight architectural component ID registers.
    
    Reads the CIDR, PIDR, DEVID, and DEVARCH registers present at well known offsets
    in the memory map of all CoreSight components. The various fields from these
    registers are made available as attributes.
    """
    
    def __init__(self, parent_rom_table, ap, top_addr, power_id=None):
        self.parent_rom_table = parent_rom_table
        self.ap = ap
        self.address = top_addr
        self.top_address = top_addr
        self.power_id = power_id
        self.component_class = 0
        self.is_rom_table = False
        self.cidr = 0
        self.pidr = 0
        self.designer = 0
        self.part = 0
        self.devarch = 0
        self.archid = 0
        self.devtype = 0
        self.devid = [0, 0, 0]
        self.name = ''
        self.factory = None
        self.valid = False

    def read_id_registers(self):
        """! @brief Read Component ID, Peripheral ID, and DEVID/DEVARCH registers."""
        # Read registers as a single block read for performance reasons.
        regs = self.ap.read_memory_block32(self.top_address + IDR_READ_START, IDR_READ_COUNT)
        self.cidr = self._extract_id_register_value(regs, CIDR0_OFFSET)
        self.pidr = (self._extract_id_register_value(regs, PIDR4_OFFSET) << 32) | self._extract_id_register_value(regs, PIDR0_OFFSET)

        # Check if the component has a valid CIDR value
        if (self.cidr & CIDR_PREAMBLE_MASK) != CIDR_PREAMBLE_VALUE:
            LOG.warning("Invalid coresight component, cidr=0x%x", self.cidr)
            return

        # Extract class and determine if this is a ROM table.
        component_class = (self.cidr & CIDR_COMPONENT_CLASS_MASK) >> CIDR_COMPONENT_CLASS_SHIFT
        is_rom_table = (component_class == ROM_TABLE_CLASS)
        
        # Extract JEP106 designer ID.
        self.designer = ((self.pidr & PIDR_DESIGNER_MASK) >> PIDR_DESIGNER_SHIFT) \
                        | ((self.pidr & PIDR_DESIGNER2_MASK) >> (PIDR_DESIGNER2_SHIFT - 8))
        self.part = self.pidr & PIDR_PART_MASK
        
        # For CoreSight-class components, extract additional fields.
        if component_class == CORESIGHT_CLASS:
             self.devarch = regs[DEVARCH_OFFSET]
             self.devid = regs[1:4]
             self.devid.reverse()
             self.devtype = regs[DEVTYPE_OFFSET]
             
             if self.devarch & DEVARCH_PRESENT_MASK:
                 self.archid = self.devarch & DEVARCH_ARCHID_MASK
        
        # Determine component name.
        if is_rom_table:
            self.name = 'ROM'
            self.factory = ROMTable.create
        else:
            key = (self.designer, component_class, self.part, self.devtype, self.archid)
            info = COMPONENT_MAP.get(key, None)
            if info is not None:
                self.name = info.name
                self.factory = info.factory
            else:
                self.name = '???'

        self.component_class = component_class
        self.is_rom_table = is_rom_table
        self.valid = True

    def _extract_id_register_value(self, regs, offset):
        result = 0
        for i in range(4):
            value = regs[offset + i]
            result |= (value & 0xff) << (i * 8)
        return result

    def __repr__(self):
        if not self.valid:
            return "<%08x:%s cidr=%x, pidr=%x, component invalid>" % (self.address, self.name, self.cidr, self.pidr)
        if self.power_id is not None:
            pwrid = " pwrid=%d" % self.power_id
        else:
            pwrid = ""
        if self.component_class == CORESIGHT_CLASS:
            return "<%08x:%s class=%d designer=%03x part=%03x devtype=%02x archid=%04x devid=%x:%x:%x%s>" % (
                self.address, self.name, self.component_class, self.designer, self.part,
                self.devtype, self.archid, self.devid[0], self.devid[1], self.devid[2], pwrid)
        else:
            return "<%08x:%s class=%d designer=%03x part=%03x%s>" % (
                self.address, self.name,self.component_class, self.designer, self.part, pwrid)


class ROMTable(CoreSightComponent):
    """! @brief CoreSight ROM table base class.
    
    This abstract class provides common functionality for ROM tables. Most importantly it has the
    static create() factory method.
    
    After a ROMTable is created, its init() method should be called. This will read and parse the
    table and any child ROM tables. For every component it finds in the table(s), it creates a
    CoreSightComponentID instance. The full collection of component IDs is available in the
    _components_ property. The for_each() method will execute a callable for all of the receiving
    ROM table and its children's components.
    
    Power domains controlled by Granular Power Requestor components are supported. They are
    automatically enabled as parsing proceeds so that components can be accessed to read their ID
    registers.
    """

    # 9 entries is enough entries to cover the standard Cortex-M4 ROM table for devices with ETM.
    ROM_TABLE_ENTRY_READ_COUNT = 9

    @staticmethod
    def create(memif, cmpid, addr=None, parent_table=None):
        """! @brief Factory method for creating ROM table components.
        
        This static method instantiates the appropriate subclass for the ROM table component
        described by the cmpid parameter.
        
        @param memif MemoryInterface used to access the ROM table.
        @param cmpid The CoreSightComponentID instance for this ROM table.
        @param addr Optional base address for this ROM table, if already known.
        @param parent_table Optional ROM table that pointed to this one.
        """
        assert cmpid is not None
        
        # Create appropriate ROM table class.
        if cmpid.component_class == ROM_TABLE_CLASS:
            return Class1ROMTable(memif, cmpid, addr, parent_table)
        else:
            raise exceptions.DebugError("unexpected ROM table device class (%s)" % cmpid)
    
    def __init__(self, ap, cmpid=None, addr=None, parent_table=None):
        """! @brief Constructor."""
        assert cmpid is not None
        assert cmpid.is_rom_table
        super(ROMTable, self).__init__(ap, cmpid, addr)
        assert self.address is not None
        if parent_table is not None:
            parent_table.add_child(self)
        self._depth = (self.parent.depth + 1) if self.parent else 0
        self._components = []
        self.name = 'ROM'
        self.gpr = None
    
    @property
    def depth(self):
        """! @brief Number of parent ROM tables."""
        return self._depth
    
    @property
    def components(self):
        """! @brief List of CoreSightComponentID instances for components found in this table.
        
        This property contains only the components for this ROM table, not any child tables.
        
        Child ROM tables will be represented in the list by ROMTable instances rather than
        CoreSightComponentID.
        """
        return self._components
    
    @property
    def depth_indent(self):
        """! @brief String of whitespace with a width corresponding to the table's depth.'"""
        return "  " * self._depth

    def init(self):
        """! @brief Read and parse the ROM table.
        
        As table entries for CoreSight components are read, a CoreSightComponentID instance will be
        created and the ID registers read. These ID objects are added to the _components_ property.
        If any child ROM tables are discovered, they will automatically be created and inited.
        """
        LOG.info("%s%s Class 0x%x ROM table #%d @ 0x%08x (designer=%03x part=%03x)",
            self.depth_indent, self.ap.short_description, self.cmpid.component_class, self.depth,
            self.address, self.cmpid.designer, self.cmpid.part)
        self._components = []

        self._read_table()
    
    def _read_table(self):
        raise NotImplementedError()

    def for_each(self, action, filter=None):
        """! @brief Apply an action to every component defined in the ROM table and child tables.
        
        This method iterates over every entry in the ROM table. For each entry it calls the
        filter function if provided. If the filter passes (returns True or was not provided) then
        the action function is called.
        
        The ROM table must have been initialized by calling init() prior to using this method.
        
        @param self This object.
        @param action Callable that accepts a single parameter, a CoreSightComponentID instance.
        @param filter Optional filter callable. Must accept a CoreSightComponentID instance and
            return a boolean indicating whether to perform the action (True applies action).
        """
        for component in self._components:
            # Recurse into child ROM tables.
            if isinstance(component, ROMTable):
                component.for_each(action, filter)
                continue
            
            # Skip component if the filter returns False.
            if filter is not None and not filter(component):
                continue
            
            # Perform the action.
            action(component)

class Class1ROMTable(ROMTable):
    """! @brief CoreSight Class 0x1 ROM table component and parser.
    
    An object of this class represents a CoreSight Class 0x1 ROM table. It supports reading the table
    and any child tables. For each entry in the table, a CoreSightComponentID object is created
    that further reads the component's CoreSight identification registers.
    
    Granular Power Requestor (GPR) components are supported to automatically enable power domains
    required to access components, as indicated by the component entry in the ROM table.
    """

    # Constants for Class 0x1 ROM tables.
    ROM_TABLE_ENTRY_PRESENT_MASK = 0x1

    # Mask for ROM table entry size. 1 if 32-bit entries.
    ROM_TABLE_32BIT_FORMAT_MASK = 0x2

    # ROM table entry power ID fields.
    ROM_TABLE_POWERIDVALID_MASK = 0x4
    ROM_TABLE_POWERID_MASK = 0x01f0
    ROM_TABLE_POWERID_SHIFT = 4

    # 2's complement offset to debug component from ROM table base address.
    ROM_TABLE_ADDR_OFFSET_NEG_MASK = 0x80000000
    ROM_TABLE_ADDR_OFFSET_MASK = 0xfffff000

    ROM_TABLE_MAX_ENTRIES = 960

    def _read_table(self):
        entryAddress = self.address
        foundEnd = False
        entriesRead = 0
        entryNumber = 0
        while not foundEnd and entriesRead < self.ROM_TABLE_MAX_ENTRIES:
            # Read several entries at a time for performance.
            readCount = min(self.ROM_TABLE_MAX_ENTRIES - entriesRead, self.ROM_TABLE_ENTRY_READ_COUNT)
            entries = self.ap.read_memory_block32(entryAddress, readCount)
            entriesRead += readCount

            for entry in entries:
                # Zero entry indicates the end of the table.
                if entry == 0:
                    foundEnd = True
                    break
                try:
                    self._handle_table_entry(entry, entryNumber)
                except exceptions.TransferError as err:
                    LOG.error("Error attempting to probe CoreSight component referenced by "
                            "ROM table entry #%d: %s", entryNumber, err,
                            exc_info=self.session.get_current().log_tracebacks)

                entryAddress += 4
                entryNumber += 1

    def _power_component(self, number, powerid, entry):
        if self.gpr is None:
            LOG.warning("ROM table entry #%d specifies power ID #%d, but no power requestor "
                "component has been seen; skipping component (entry=0x%08x)",
                number, powerid, entry)
            return False
    
        # Power up the domain.
        if not self.gpr.power_up_one(powerid):
            LOG.error("Failed to power up power domain #%d", powerid)
            return False
        else:
            LOG.info("Enabled power to power domain #%d", powerid)
            return True

    def _handle_table_entry(self, entry, number):
        # Nonzero entries can still be disabled, so check the present bit before handling.
        if (entry & self.ROM_TABLE_ENTRY_PRESENT_MASK) == 0:
            return
        # Verify the entry format is 32-bit.
        if (entry & self.ROM_TABLE_32BIT_FORMAT_MASK) == 0:
            return

        # Get the component's top 4k address.
        offset = entry & self.ROM_TABLE_ADDR_OFFSET_MASK
        if (entry & self.ROM_TABLE_ADDR_OFFSET_NEG_MASK) != 0:
            offset = ~bit_invert(offset)
        address = self.address + offset
        
        # Check power ID.
        if (entry & self.ROM_TABLE_POWERIDVALID_MASK) != 0:
            powerid = (entry & self.ROM_TABLE_POWERID_MASK) >> self.ROM_TABLE_POWERID_SHIFT
            
            # Attempt to power up this component. Skip this component if we the attempt fails.
            if not self._power_component(number, powerid, entry):
                return
        else:
            powerid = None

        # Create component instance.
        cmpid = CoreSightComponentID(self, self.ap, address, powerid)
        cmpid.read_id_registers()
        
        # Is this component a power requestor?
        if cmpid.factory == GPR.factory:
            # Create the GPR instance and stash it.
            self.gpr = cmpid.factory(self.ap, cmpid, None)
            self.gpr.init()

        LOG.info("%s[%d]%s", self.depth_indent, number, str(cmpid))

        # Recurse into child ROM tables.
        if cmpid.is_rom_table:
            cmp = ROMTable.create(self.ap, cmpid, address, parent_table=self)
            cmp.init()
        else:
            cmp = cmpid

        if cmp is not None:
            self.components.append(cmp)

