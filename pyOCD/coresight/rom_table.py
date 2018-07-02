"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

from ..utility.mask import invert32
import logging

# CoreSight identification register offsets.
PIDR4 = 0xfd0
PIDR0 = 0xfe0
CIDR0 = 0xff0
DEVTYPE = 0xfcc
DEVID = 0xfc8
DEVARCH = 0xfbc

# Number of identification registers to read at once and offsets in results.
IDR_COUNT = 17
DEVARCH_OFFSET = 0
DEVTYPE_OFFSET = 4
PIDR4_OFFSET = 5
PIDR0_OFFSET = 9
CIDR0_OFFSET = 13

# Component ID register fields.
CIDR_PREAMBLE_MASK = 0xffff0fff
CIDR_PREAMBLE_VALUE = 0xb105000d

CIDR_COMPONENT_CLASS_MASK = 0x0000f000
CIDR_COMPONENT_CLASS_SHIFT = 12

# Component classes.
CIDR_ROM_TABLE_CLASS = 0x1
CIDR_CORESIGHT_CLASS = 0x9
CIDR_GENERIC_IP_CLASS = 0xe
CIDR_SYSTEM_CLASS = 0xf # CoreLink, PrimeCell, or other system component with no standard register layout.

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
#  0x34 = Granular Power Requestor

# Map from (designer, class, part, archid) to component name (eventually class).
COMPONENT_MAP = {
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x906, 0)      : 'CTI',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x907, 0)      : 'ETB',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x908, 0)      : 'CSTF',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x912, 0)      : 'TPIU',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x923, 0)      : 'TPIU-M3',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x924, 0)      : 'ETM-M3',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x925, 0)      : 'ETM-M4',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x932, 0x0a31) : 'MTB-M0+',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x975, 0)      : 'ETM-M7',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x9a1, 0)      : 'TPIU-M4',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x9a4, 0x0a34) : 'GPR', # Granular Power Requestor
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x9a6, 0x1a14) : 'CTI',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0x9a9, 0)      : 'TPIU-M7',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0xd21, 0x1a01) : 'ITM',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0xd21, 0x1a02) : 'DWT',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0xd21, 0x1a03) : 'BPU',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0xd21, 0x1a14) : 'CTI',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0xd21, 0x2a04) : 'SCS-M33',
    (ARM_ID, CIDR_CORESIGHT_CLASS,  0xd21, 0x4a13) : 'ETM',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x000, 0)      : 'SCS-M3',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x001, 0)      : 'ITM',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x002, 0)      : 'DWT',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x003, 0)      : 'FPB',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x008, 0)      : 'SCS-M0+',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x00a, 0)      : 'DWT-M0+',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x00b, 0)      : 'BPU',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x00c, 0)      : 'SCS-M4',
    (ARM_ID, CIDR_GENERIC_IP_CLASS, 0x00e, 0)      : 'FPB',
    (ARM_ID, CIDR_SYSTEM_CLASS,     0x101, 0)      : 'TSGEN', # Timestamp Generator
    (FSL_ID, CIDR_CORESIGHT_CLASS,  0x000, 0)      : 'MTBDWT',
    }

class CoreSightComponent(object):
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
        self.valid = False

    def read_id_registers(self):
        # Read Component ID, Peripheral ID, and DEVID/DEVARCH registers. This is done as a single
        # block read for performance reasons.
        regs = self.ap.readBlockMemoryAligned32(self.top_address + DEVARCH, IDR_COUNT)
        self.cidr = self._extract_id_register_value(regs, CIDR0_OFFSET)
        self.pidr = (self._extract_id_register_value(regs, PIDR4_OFFSET) << 32) | self._extract_id_register_value(regs, PIDR0_OFFSET)

        # Check if the component has a valid CIDR value
        if (self.cidr & CIDR_PREAMBLE_MASK) != CIDR_PREAMBLE_VALUE:
            logging.warning("Invalid coresight component, cidr=0x%x", self.cidr)
            return

        # Extract class and determine if this is a ROM table.
        component_class = (self.cidr & CIDR_COMPONENT_CLASS_MASK) >> CIDR_COMPONENT_CLASS_SHIFT
        is_rom_table = (component_class == CIDR_ROM_TABLE_CLASS)
        
        # Extract JEP106 designer ID.
        self.designer = ((self.pidr & PIDR_DESIGNER_MASK) >> PIDR_DESIGNER_SHIFT) \
                        | ((self.pidr & PIDR_DESIGNER2_MASK) >> (PIDR_DESIGNER2_SHIFT - 8))
        self.part = self.pidr & PIDR_PART_MASK
        
        # For CoreSight-class components, extract additional fields.
        if component_class == CIDR_CORESIGHT_CLASS:
             self.devarch = regs[DEVARCH_OFFSET]
             self.devid = regs[1:4]
             self.devtype = regs[DEVTYPE_OFFSET]
             
             if self.devarch & DEVARCH_PRESENT_MASK:
                 self.archid = self.devarch & DEVARCH_ARCHID_MASK
        
        # Determine component name.
        if is_rom_table:
            self.name = 'ROM'
        else:
            key = (self.designer, component_class, self.part, self.archid)
            self.name = COMPONENT_MAP.get(key, '')

        self.component_class = component_class
        self.is_rom_table = is_rom_table
        self.valid = True

    def _extract_id_register_value(self, regs, offset):
        result = 0
        for i in range(4):
            value = regs[offset + i]
            result |= (value & 0xff) << (i * 8)
        return result

    def __str__(self):
        if not self.valid:
            return "<%08x:%s cidr=%x, pidr=%x, component invalid>" % (self.address, self.name, self.cidr, self.pidr)
        if self.component_class == CIDR_CORESIGHT_CLASS:
            return "<%08x:%s class=%d designer=%03x part=%03x devtype=%02x archid=%04x devid=%x:%x:%x>" % (
                self.address, self.name, self.component_class, self.designer, self.part,
                self.devtype, self.archid, self.devid[0], self.devid[1], self.devid[2])
        else:
            return "<%08x:%s class=%d designer=%03x part=%03x>" % (
                self.address, self.name,self.component_class, self.designer, self.part)


class ROMTable(CoreSightComponent):
    def __init__(self, ap, top_addr=None, parent_table=None):
        # If no table address is provided, use the root ROM table for the AP.
        if top_addr is None:
            top_addr = ap.rom_addr
        super(ROMTable, self).__init__(ap, top_addr)
        self.parent = parent_table
        self.number = (self.parent.number + 1) if self.parent else 0
        self.components = []
    
    @property
    def depth_indent(self):
        return "  " * self.number

    def init(self):
        self.read_id_registers()
        if not self.is_rom_table:
            logging.warning("Warning: ROM table @ 0x%08x has unexpected CIDR component class (0x%x)", self.address, self.component_class)
            return
        self.read_table()

    def read_table(self):
        logging.info("%sAP#%d ROM table #%d @ 0x%08x (designer=%03x part=%03x)",
            self.depth_indent, self.ap.ap_num, self.number, self.address, self.designer, self.part)
        self.components = []

        entryAddress = self.address
        foundEnd = False
        entriesRead = 0
        while not foundEnd and entriesRead < ROM_TABLE_MAX_ENTRIES:
            # Read several entries at a time for performance.
            readCount = min(ROM_TABLE_MAX_ENTRIES - entriesRead, ROM_TABLE_ENTRY_READ_COUNT)
            entries = self.ap.readBlockMemoryAligned32(entryAddress, readCount)
            entriesRead += readCount

            for entry in entries:
                # Zero entry indicates the end of the table.
                if entry == 0:
                    foundEnd = True
                    break
                self.handle_table_entry(entry)

                entryAddress += 4

    def handle_table_entry(self, entry):
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
        cmp = CoreSightComponent(self.ap, address)
        cmp.read_id_registers()

        logging.info("%s[%d]%s", self.depth_indent, len(self.components), str(cmp))

        # Recurse into child ROM tables.
        if cmp.is_rom_table:
            cmp = ROMTable(self.ap, address, parent_table=self)
            cmp.init()

        self.components.append(cmp)


