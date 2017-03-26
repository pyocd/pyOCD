"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2018 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from .component import CoreSightComponent
from .cortex_m import CortexM
from .fpb import FPB
from .dwt import DWT
from ..utility.mask import invert32
from collections import namedtuple
import logging

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

# ROM table constants.
ROM_TABLE_ENTRY_PRESENT_MASK = 0x1

# Mask for ROM table entry size. 1 if 32-bit entries.
ROM_TABLE_32BIT_FORMAT_MASK = 0x2

# 2's complement offset to debug component from ROM table base address.
ROM_TABLE_ADDR_OFFSET_NEG_MASK = 0x80000000
ROM_TABLE_ADDR_OFFSET_MASK = 0xfffff000
ROM_TABLE_ADDR_OFFSET_SHIFT = 12

# 9 entries is enough entries to cover the standard Cortex-M4 ROM table for devices with ETM.
ROM_TABLE_ENTRY_READ_COUNT = 9
ROM_TABLE_MAX_ENTRIES = 960

# DEVARCH register fields.
DEVARCH_ARCHITECT_MASK = 0x7ff
DEVARCH_ARCHITECT_SHIFT = 21
DEVARCH_PRESENT_MASK = (1<<20)
DEVARCH_REVISION_MASK = 0x000f0000
DEVARCH_REVISION_SHIFT = 16
DEVARCH_ARCHID_MASK = 0xffff

# CoreSight devtype
#  Major Type [3:0]
#  Minor Type [7:4]
#
# CoreSight Major Types
#  0 = Miscellaneous
#  1 = Trace Sink
#  2 = Trace Link
#  3 = Trace Source
#  4 = Debug Control
#  5 = Debug Logic
#
# Known devtype values
#  0x11 = TPIU
#  0x21 = ETB
#  0x12 = Trace funnel (CSFT)
#  0x13 = CPU trace source (ETM, MTB?)
#  0x43 = ITM
#  0x14 = ECT/CTI/CTM
#  0x31 = MTB
#  0x34 = Granular Power Requestor

## Pairs a component name with a factory method.
CmpInfo = namedtuple('ComponentInfo', 'name factory')

## Map from (designer, class, part, devtype, archid) to component name and class.
COMPONENT_MAP = {
  # Designer|Component Class |Part  |Type |Archid 
    (ARM_ID, CORESIGHT_CLASS, 0x906, 0x14, 0)      : CmpInfo('CTI',       None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x907, 0x21, 0)      : CmpInfo('ETB',       None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x908, 0x12, 0)      : CmpInfo('CSTF',      None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x912, 0x11, 0)      : CmpInfo('TPIU',      None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x923, 0x11, 0)      : CmpInfo('TPIU-M3',   None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x924, 0x13, 0)      : CmpInfo('ETM-M3',    None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x925, 0x13, 0)      : CmpInfo('ETM-M4',    None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x932, 0x31, 0x0a31) : CmpInfo('MTB-M0+',   None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x975, 0x13, 0x4a13) : CmpInfo('ETM-M7',    None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x9a1, 0x11, 0)      : CmpInfo('TPIU-M4',   None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x9a4, 0x34, 0x0a34) : CmpInfo('GPR',       None            ), # Granular Power Requestor
    (ARM_ID, CORESIGHT_CLASS, 0x9a6, 0x14, 0x1a14) : CmpInfo('CTI',       None            ),
    (ARM_ID, CORESIGHT_CLASS, 0x9a9, 0x11, 0)      : CmpInfo('TPIU-M7',   None            ),
    (ARM_ID, CORESIGHT_CLASS, 0xd20, 0x11, 0)      : CmpInfo('TPIU-M23',  None            ),
    (ARM_ID, CORESIGHT_CLASS, 0xd20, 0x13, 0)      : CmpInfo('ETM-M23',   None            ),
    (ARM_ID, CORESIGHT_CLASS, 0xd20, 0x00, 0x1a02) : CmpInfo('DWT',       DWT.factory     ), # M23
    (ARM_ID, CORESIGHT_CLASS, 0xd20, 0x00, 0x1a03) : CmpInfo('BPU',       FPB.factory     ), # M23
    (ARM_ID, CORESIGHT_CLASS, 0xd20, 0x00, 0x2a04) : CmpInfo('SCS-M23',   CortexM.factory ), # M23
    (ARM_ID, CORESIGHT_CLASS, 0xd21, 0x00, 0x1a01) : CmpInfo('ITM',       None            ), # M33
    (ARM_ID, CORESIGHT_CLASS, 0xd21, 0x00, 0x1a02) : CmpInfo('DWT',       DWT.factory     ), # M33
    (ARM_ID, CORESIGHT_CLASS, 0xd21, 0x00, 0x1a03) : CmpInfo('BPU',       FPB.factory     ), # M33
    (ARM_ID, CORESIGHT_CLASS, 0xd21, 0x00, 0x1a14) : CmpInfo('CTI',       None            ), # M33
    (ARM_ID, CORESIGHT_CLASS, 0xd21, 0x00, 0x2a04) : CmpInfo('SCS-M33',   CortexM.factory ), # M33
    (ARM_ID, CORESIGHT_CLASS, 0xd21, 0x00, 0x4a13) : CmpInfo('ETM',       None            ), # M33
    (ARM_ID, GENERIC_CLASS,   0x000, 0x00, 0)      : CmpInfo('SCS-M3',    CortexM.factory ),
    (ARM_ID, GENERIC_CLASS,   0x001, 0x00, 0)      : CmpInfo('ITM',       None            ),
    (ARM_ID, GENERIC_CLASS,   0x002, 0x00, 0)      : CmpInfo('DWT',       DWT.factory     ),
    (ARM_ID, GENERIC_CLASS,   0x003, 0x00, 0)      : CmpInfo('FPB',       FPB.factory     ),
    (ARM_ID, GENERIC_CLASS,   0x008, 0x00, 0)      : CmpInfo('SCS-M0+',   CortexM.factory ),
    (ARM_ID, GENERIC_CLASS,   0x00a, 0x00, 0)      : CmpInfo('DWT-M0+',   DWT.factory     ),
    (ARM_ID, GENERIC_CLASS,   0x00b, 0x00, 0)      : CmpInfo('BPU',       FPB.factory     ),
    (ARM_ID, GENERIC_CLASS,   0x00c, 0x00, 0)      : CmpInfo('SCS-M4',    CortexM.factory ),
    (ARM_ID, GENERIC_CLASS,   0x00e, 0x00, 0)      : CmpInfo('FPB',       FPB.factory     ),
    (ARM_ID, SYSTEM_CLASS,    0x101, 0x00, 0)      : CmpInfo('TSGEN',     None            ), # Timestamp Generator
    (FSL_ID, CORESIGHT_CLASS, 0x000, 0x04, 0)      : CmpInfo('MTBDWT',    None            ),
    }

## @brief Reads and parses CoreSight architectural component ID registers.
#
# Reads the CIDR, PIDR, DEVID, and DEVARCH registers present at well known offsets
# in the memory map of all CoreSight components. The various fields from these
# registers are made available as attributes.
class CoreSightComponentID(object):
    def __init__(self, ap, top_addr):
        self.ap = ap
        self.address = top_addr
        self.top_address = top_addr
        self.component_class = 0
        self.is_rom_table = False
        self.cidr = 0
        self.pidr = 0
        self.designer = 0
        self.part = 0
        self.devarch = 0
        self.archid = 0
        self.devtype = 0
        self.devid = 0
        self.name = ''
        self.factory = None
        self.valid = False

    def read_id_registers(self):
        # Read Component ID, Peripheral ID, and DEVID/DEVARCH registers. This is done as a single
        # block read for performance reasons.
        regs = self.ap.read_memory_block32(self.top_address + IDR_READ_START, IDR_READ_COUNT)
        self.cidr = self._extract_id_register_value(regs, CIDR0_OFFSET)
        self.pidr = (self._extract_id_register_value(regs, PIDR4_OFFSET) << 32) | self._extract_id_register_value(regs, PIDR0_OFFSET)

        # Check if the component has a valid CIDR value
        if (self.cidr & CIDR_PREAMBLE_MASK) != CIDR_PREAMBLE_VALUE:
            logging.warning("Invalid coresight component, cidr=0x%x", self.cidr)
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
             self.devtype = regs[DEVTYPE_OFFSET]
             
             if self.devarch & DEVARCH_PRESENT_MASK:
                 self.archid = self.devarch & DEVARCH_ARCHID_MASK
        
        # Determine component name.
        if is_rom_table:
            self.name = 'ROM'
            self.factory = ROMTable
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
        if self.component_class == CORESIGHT_CLASS:
            return "<%08x:%s class=%d designer=%03x part=%03x devtype=%02x archid=%04x devid=%x:%x:%x>" % (
                self.address, self.name, self.component_class, self.designer, self.part,
                self.devtype, self.archid, self.devid[0], self.devid[1], self.devid[2])
        else:
            return "<%08x:%s class=%d designer=%03x part=%03x>" % (
                self.address, self.name,self.component_class, self.designer, self.part)


class ROMTable(CoreSightComponent):
    """! @brief CoreSight ROM table component and parser.
    
    An object of this class represents a CoreSight ROM table. It supports reading the table
    and any child tables. For each entry in the table, a CoreSightComponentID object is created
    that further reads the component's CoreSight identification registers.
    """
    def __init__(self, ap, cmpid=None, addr=None, parent_table=None):
        # If no table address is provided, use the root ROM table for the AP.
        if addr is None:
            addr = ap.rom_addr
        super(ROMTable, self).__init__(ap, cmpid, addr)
        self.parent = parent_table
        self.number = (self.parent.number + 1) if self.parent else 0
        self.components = []
        self.name = 'ROM'
    
    @property
    def depth_indent(self):
        return "  " * self.number

    def init(self):
        if self.cmpid is None:
            self.cmpid = CoreSightComponentID(self.ap, self.address)
            self.cmpid.read_id_registers()
        if not self.cmpid.is_rom_table:
            logging.warning("Warning: ROM table @ 0x%08x has unexpected CIDR component class (0x%x)", self.address, self.cmpid.component_class)
            return
        self._read_table()

    def _read_table(self):
        logging.info("%sAP#%d ROM table #%d @ 0x%08x (designer=%03x part=%03x)",
            self.depth_indent, self.ap.ap_num, self.number, self.address, self.cmpid.designer, self.cmpid.part)
        self.components = []

        entryAddress = self.address
        foundEnd = False
        entriesRead = 0
        while not foundEnd and entriesRead < ROM_TABLE_MAX_ENTRIES:
            # Read several entries at a time for performance.
            readCount = min(ROM_TABLE_MAX_ENTRIES - entriesRead, ROM_TABLE_ENTRY_READ_COUNT)
            entries = self.ap.read_memory_block32(entryAddress, readCount)
            entriesRead += readCount

            for entry in entries:
                # Zero entry indicates the end of the table.
                if entry == 0:
                    foundEnd = True
                    break
                self._handle_table_entry(entry)

                entryAddress += 4

    def _handle_table_entry(self, entry):
        # Nonzero entries can still be disabled, so check the present bit before handling.
        if (entry & ROM_TABLE_ENTRY_PRESENT_MASK) == 0:
            return
        # Verify the entry format is 32-bit.
        if (entry & ROM_TABLE_32BIT_FORMAT_MASK) == 0:
            return

        # Get the component's top 4k address.
        offset = entry & ROM_TABLE_ADDR_OFFSET_MASK
        if (entry & ROM_TABLE_ADDR_OFFSET_NEG_MASK) != 0:
            offset = ~invert32(offset)
        address = self.address + offset

        # Create component instance.
        cmpid = CoreSightComponentID(self.ap, address)
        cmpid.read_id_registers()

        logging.info("%s[%d]%s", self.depth_indent, len(self.components), str(cmpid))

        # Recurse into child ROM tables.
        if cmpid.is_rom_table:
            cmp = ROMTable(self.ap, cmpid, address, parent_table=self)
            cmp.init()
        else:
            cmp = cmpid

        if cmp is not None:
            self.components.append(cmp)

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
        for component in self.components:
            # Recurse into child ROM tables.
            if isinstance(component, ROMTable):
                component.for_each(action, filter)
                continue
            
            # Skip component if the filter returns False.
            if filter is not None and not filter(component):
                continue
            
            # Perform the action.
            action(component)

