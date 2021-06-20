# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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
from time import sleep

from ..core import exceptions
from .component import CoreSightComponent
from .gpr import GPR
from .component_ids import COMPONENT_MAP
from ..utility.conversion import pairwise
from ..utility.mask import (bit_invert, align_down)
from ..utility.timeout import Timeout

LOG = logging.getLogger(__name__)

class CoreSightComponentID(object):
    """! @brief Reads and parses CoreSight architectural component ID registers.
    
    Reads the CIDR, PIDR, DEVID, and DEVARCH registers present at well known offsets
    in the memory map of all CoreSight components. The various fields from these
    registers are made available as attributes.
    """

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

    # Peripheral ID register fields.
    PIDR_PART_MASK = 0x00000fff
    PIDR_DESIGNER_MASK = 0x0007f000 # JEP106 ID
    PIDR_DESIGNER_SHIFT = 12
    PIDR_REVISION_MASK = 0x00f00000
    PIDR_REVISION_SHIFT = 20
    PIDR_DESIGNER2_MASK = 0x0f00000000 # JEP106 continuation
    PIDR_DESIGNER2_SHIFT = 32

    # DEVARCH register fields.
    DEVARCH_ARCHITECT_MASK = 0x7ff
    DEVARCH_ARCHITECT_SHIFT = 21
    DEVARCH_PRESENT_MASK = (1<<20)
    DEVARCH_REVISION_MASK = 0x000f0000
    DEVARCH_REVISION_SHIFT = 16
    DEVARCH_ARCHID_MASK = 0xffff

    CLASS_0X9_ROM_TABLE_ARCHID = 0x0af7
    
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
        regs = self.ap.read_memory_block32(self.top_address + self.IDR_READ_START, self.IDR_READ_COUNT)
        self.cidr = self._extract_id_register_value(regs, self.CIDR0_OFFSET)
        self.pidr = (self._extract_id_register_value(regs, self.PIDR4_OFFSET) << 32) \
                    | self._extract_id_register_value(regs, self.PIDR0_OFFSET)

        # Check if the component has a valid CIDR value
        if (self.cidr & self.CIDR_PREAMBLE_MASK) != self.CIDR_PREAMBLE_VALUE:
            LOG.warning("Invalid coresight component, cidr=0x%x", self.cidr)
            return

        # Extract class.
        self.component_class = (self.cidr & self.CIDR_COMPONENT_CLASS_MASK) >> self.CIDR_COMPONENT_CLASS_SHIFT
        
        # Extract JEP106 designer ID.
        self.designer = ((self.pidr & self.PIDR_DESIGNER_MASK) >> self.PIDR_DESIGNER_SHIFT) \
                        | ((self.pidr & self.PIDR_DESIGNER2_MASK) >> (self.PIDR_DESIGNER2_SHIFT - 8))
        self.part = self.pidr & self.PIDR_PART_MASK
        
        # Handle Class 0x1 and Type 0x9 components.
        if self.component_class == self.ROM_TABLE_CLASS:
            # Class 0x1 ROM table.
            self.is_rom_table = True
        elif self.component_class == self.CORESIGHT_CLASS:
            # For CoreSight-class components, extract additional fields.
             self.devarch = regs[self.DEVARCH_OFFSET]
             self.devid = regs[1:4]
             self.devid.reverse()
             self.devtype = regs[self.DEVTYPE_OFFSET]
             
             if self.devarch & self.DEVARCH_PRESENT_MASK:
                 self.archid = self.devarch & self.DEVARCH_ARCHID_MASK

             # Identify a Class 0x9 ROM table.
             self.is_rom_table = (self.archid == self.CLASS_0X9_ROM_TABLE_ARCHID)
        
        # Determine component name.
        if self.is_rom_table:
            self.name = 'ROM'
            self.factory = ROMTable.create
        else:
            key = (self.designer, self.component_class, self.part, self.devtype, self.archid)
            info = COMPONENT_MAP.get(key, None)
            if info is not None:
                self.name = info.name
                self.factory = info.factory
            else:
                # Try just the archid with no partno or devtype as backup.
                key = (self.designer, self.component_class, None, None, self.archid)
                info = COMPONENT_MAP.get(key, None)
                if info is not None:
                    self.name = info.name
                    self.factory = info.factory
                else:
                    self.name = '???'

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
        if self.component_class == self.CORESIGHT_CLASS:
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
        if cmpid.component_class == CoreSightComponentID.ROM_TABLE_CLASS:
            return Class1ROMTable(memif, cmpid, addr, parent_table)
        elif cmpid.component_class == CoreSightComponentID.CORESIGHT_CLASS:
            return Class9ROMTable(memif, cmpid, addr, parent_table)
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
                            exc_info=self.ap.dp.session.get_current().log_tracebacks)

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
    
class Class9ROMTable(ROMTable):
    """! @brief CoreSight Class 0x9 ROM table component and parser.
    
    Handles parsing of class 0x9 ROM tables as defined in ADIv6.
    
    In addition to GPR (Granular Power Requestor) components for power domain management, this class
    supports the optional power request functionality present in class 0x9 ROM tables.
    """

    # Constants for Class 0x9 ROM tables.
    ROM_TABLE_ENTRY_PRESENT_MASK = 0x3
    ROM_TABLE_ENTRY_POWERIDVALID_MASK = 0x4
    ROM_TABLE_ENTRY_POWERID_MASK = 0x01f0
    ROM_TABLE_ENTRY_POWERID_SHIFT = 4

    ROM_TABLE_ENTRY_NOT_PRESENT_FINAL = 0x0
    ROM_TABLE_ENTRY_NOT_PRESENT_NOT_FINAL = 0x2
    ROM_TABLE_ENTRY_PRESENT = 0x3

    ROM_TABLE_DBGPCRn = 0xa00
    ROM_TABLE_DBGPSRn = 0xa80
    ROM_TABLE_SYSPCRn = 0xb00
    ROM_TABLE_SYSPSRn = 0xb80
    ROM_TABLE_PRIDR0 = 0xc00
    ROM_TABLE_DBGRSTRR = 0xc10
    ROM_TABLE_DBGRSTAR = 0xc14
    ROM_TABLE_SYSRSTRR = 0xc18
    ROM_TABLE_SYSRSTAR = 0xc1c
    ROM_TABLE_AUTHSTATUS = 0xfb8

    ROM_TABLE_DBGPCRn_PRESENT_MASK = 0x00000001
    ROM_TABLE_DBGPCRn_PR_MASK = 0x00000002
    ROM_TABLE_DBGPSRn_PS_MASK = 0x00000003
    
    ROM_TABLE_DBGPSRn_PS_MAYBE_NOT_POWERED = 0x0
    ROM_TABLE_DBGPSRn_PS_IS_POWERED = 0x1
    ROM_TABLE_DBGPSRn_PS_MUST_REMAIN_POWERED = 0x3
    
    ROM_TABLE_PRIDR0_VERSION_MASK = 0x0000000f
    ROM_TABLE_PRIDR0_VERSION = 1 # Current version number of the power request functionality.

    ROM_TABLE_DEVID_CP_MASK = 0x00000040
    ROM_TABLE_DEVID_PRR_MASK = 0x00000020
    ROM_TABLE_DEVID_SYSMEM_MASK = 0x00000010
    ROM_TABLE_DEVID_FORMAT_MASK = 0x0000000f

    ROM_TABLE_FORMAT_32BIT = 0x0
    ROM_TABLE_FORMAT_64BIT = 0x1

    ROM_TABLE_MAX_ENTRIES = 512 # Maximum 32-bit entries.

    # 2's complement offset to debug component from ROM table base address.
    ROM_TABLE_ADDR_OFFSET_NEG_MASK = { 32: (1 << 31), 64: (1 << 63) }
    ROM_TABLE_ADDR_OFFSET_MASK = { 32: 0xfffff000, 64: 0xfffffffffffff000 }
    
    # 5 second timeout on power domain requests.
    POWER_REQUEST_TIMEOUT = 5.0
    
    def __init__(self, ap, cmpid=None, addr=None, parent_table=None):
        """! @brief Component constructor."""
        super(Class9ROMTable, self).__init__(ap, cmpid, addr, parent_table)
        
        self._pridr_version = None

        # Extract flags from DEVID.
        self._has_com_port = ((self.cmpid.devid[0] & self.ROM_TABLE_DEVID_CP_MASK) != 0)
        self._has_prr = ((self.cmpid.devid[0] & self.ROM_TABLE_DEVID_PRR_MASK) != 0)
        self._is_sysmem = ((self.cmpid.devid[0] & self.ROM_TABLE_DEVID_SYSMEM_MASK) != 0)
        is_64bit = ((self.cmpid.devid[0] & self.ROM_TABLE_DEVID_FORMAT_MASK) != 0)
        self._width = 64 if is_64bit else 32
        LOG.debug("cp=%d prr=%d sysmem=%d w=%d", self._has_com_port, self._has_prr, self._is_sysmem, self._width)
    
    @property
    def has_com_port(self):
        """! @brief Whether the ROM table includes COM Port functionality."""
        return self._has_com_port
    
    @property
    def has_prr(self):
        """! @brief Whether the ROM table includes power and reset requesting functionality."""
        return self._has_prr
    
    @property
    def is_sysmem(self):
        """! @brief Whether the ROM table is present in system memory."""
        return self._is_sysmem

    def _read_table(self):
        """! @brief Reads and parses the ROM table."""
        # Compute multipliers for 32- or 64-bit.
        entrySizeMultiplier = self._width // 32
        actualMaxEntries = self.ROM_TABLE_MAX_ENTRIES // entrySizeMultiplier
        # Ensure 64-bit format is read as pairs of 32-bit values.
        entryReadCount = align_down(self.ROM_TABLE_ENTRY_READ_COUNT, entrySizeMultiplier)
        
        entryAddress = self.address
        foundEnd = False
        entriesRead = 0
        entryNumber = 0
        
        while not foundEnd and entriesRead < actualMaxEntries:
            # Read several entries at a time for performance.
            readCount = min(actualMaxEntries - entriesRead, entryReadCount)
            entries = self.ap.read_memory_block32(entryAddress, readCount)
            entriesRead += readCount

            # For 64-bit entries, combine pairs of 32-bit values into single 64-bit value.
            if self._width == 64:
                entries = [(lo | (hi << 32)) for lo, hi in pairwise(entries)]
            
            for entry in entries:
                present = entry & self.ROM_TABLE_ENTRY_PRESENT_MASK
                
                # Zero entry indicates the end of the table.
                if present == self.ROM_TABLE_ENTRY_NOT_PRESENT_FINAL:
                    foundEnd = True
                    break
                elif present == self.ROM_TABLE_ENTRY_PRESENT:
                    try:
                        self._handle_table_entry(entry, entryNumber)
                    except exceptions.TransferError as err:
                        LOG.error("Error attempting to probe CoreSight component referenced by "
                                "ROM table entry #%d: %s", entryNumber, err,
                                exc_info=self.ap.dp.session.get_current().log_tracebacks)

                entryAddress += 4 * entrySizeMultiplier
                entryNumber += 1

    def _power_component(self, number, powerid, entry):
        """! @brief Enable power to a component defined by a ROM table entry."""
        if not self._has_prr:
            # Attempt GPR method of power domain enabling.
            return super(Class9ROMTable, self)._power_component(number, powerid, entry)
        
        # Check power request functionality version here so we can provide a nice warning message.
        if not self.check_power_request_version():
            LOG.warning("Class 0x9 ROM table #%d @ 0x%08x has unsupported version (%d) of power "
                        "request functionality, needed for entry #%d (entry=0x%08x). Skipping "
                        "component.", self.depth, self.address, self._pridr_version, number, entry)
            return False
        
        if not self.power_debug_domain(powerid):
            LOG.error("Failed to power up power domain #%d", powerid)
            return False
        else:
            LOG.info("Enabled power to power domain #%d", powerid)
            return True

    def _handle_table_entry(self, entry, number):
        """! @brief Parse one ROM table entry."""
        # Get the component's top 4k address.
        offset = entry & self.ROM_TABLE_ADDR_OFFSET_MASK[self._width]
        if (entry & self.ROM_TABLE_ADDR_OFFSET_NEG_MASK[self._width]) != 0:
            offset = ~bit_invert(offset, width=self._width)
        address = self.address + offset
        
        # Check power ID.
        if (entry & self.ROM_TABLE_ENTRY_POWERIDVALID_MASK) != 0:
            powerid = (entry & self.ROM_TABLE_ENTRY_POWERID_MASK) >> self.ROM_TABLE_ENTRY_POWERID_SHIFT
            
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
            self._components.append(cmp)
    
    def check_power_request_version(self):
        """! @brief Verify the power request functionality version."""
        # Cache the PRIDR0 VERSION field the first time.
        if self._pridr_version is None:
            pridr = self.ap.read32(self.address + self.ROM_TABLE_PRIDR0)
            self._pridr_version = pridr & self.ROM_TABLE_PRIDR0_VERSION_MASK

        return self._pridr_version == self.ROM_TABLE_PRIDR0_VERSION

    def power_debug_domain(self, domain_id, enable=True):
        """! @brief Control power for a specified power domain managed by this ROM table."""
        # Compute register addresses for this power domain.
        dbgpcr_addr = self.address + self.ROM_TABLE_DBGPCRn + (4 * domain_id)
        dbgpsr_addr = self.address + self.ROM_TABLE_DBGPSRn + (4 * domain_id)
        
        # Check the domain request PRESENT bit.
        dbgpcr = self.ap.read32(dbgpcr_addr)
        if (dbgpcr & self.ROM_TABLE_DBGPCRn_PRESENT_MASK) == 0:
            LOG.warning("Power request functionality for power domain #%d is not present.",
                domain_id)
            return False
        
        # Check if the PR bit matches our request.
        pr = (dbgpcr & self.ROM_TABLE_DBGPCRn_PR_MASK) != 0
        if pr == enable:
            return True

        # If enabling, we need to check the power domain status. If the domain is in the "must
        # remain powered" state, then we have to wait for it to exit this state before re-enabling
        # power. See Figure D4-3 "Debug power request process", page D4-317, in the ADIv6
        # specification [IHI0074B].
        if enable:
            with Timeout(self.POWER_REQUEST_TIMEOUT) as time_out:
                while time_out.check():
                    power_status = self.ap.read32(dbgpsr_addr) & self.ROM_TABLE_DBGPSRn_PS_MASK
                    if power_status != self.ROM_TABLE_DBGPSRn_PS_MUST_REMAIN_POWERED:
                        break
                else:
                    LOG.warning("Power request handshake did not complete for power domain #%d.",
                        domain_id)
                    return False
        
        # Change power enable bit.
        if enable:
            dbgpcr |= self.ROM_TABLE_DBGPCRn_PR_MASK
        else:
            dbgpcr &= ~self.ROM_TABLE_DBGPCRn_PR_MASK
        self.ap.write32(dbgpcr_addr, dbgpcr)
        
        # Wait for status bits to update.
        with Timeout(self.POWER_REQUEST_TIMEOUT) as time_out:
            while time_out.check():
                power_status = self.ap.read32(dbgpsr_addr)
                if power_status == self.ROM_TABLE_DBGPSRn_PS_IS_POWERED:
                    # Sleep for 100 ms.
                    sleep(0.1)
                    break
                elif power_status == self.ROM_TABLE_DBGPSRn_PS_MUST_REMAIN_POWERED:
                    break
            else:
                LOG.warning("Power request handshake did not complete for power domain #%d.",
                    domain_id)
                return False

        # Successfully changed state of the power domain.
        return True
