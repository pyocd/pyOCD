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

PIDR4 = 0xfd0
PIDR0 = 0xfe0
CIDR0 = 0xff0
DEVTYPE = 0xfcc
DEVID = 0xfc8
IDR_COUNT = 12
PIDR4_OFFSET = 0
PIDR0_OFFSET = 4
CIDR0_OFFSET = 8

CIDR_PREAMBLE_MASK = 0xffff0fff
CIDR_PREAMBLE_VALUE = 0xb105000d

CIDR_COMPONENT_CLASS_MASK = 0xf000
CIDR_COMPONENT_CLASS_SHIFT = 12

CIDR_ROM_TABLE_CLASS = 0x1
CIDR_CORESIGHT_CLASS = 0x9

PIDR_4KB_COUNT_MASK = 0xf000000000
PIDR_4KB_COUNT_SHIFT = 36

ROM_TABLE_ENTRY_PRESENT_MASK = 0x1

# Mask for ROM table entry size. 1 if 32-bit, 0 if 8-bit.
ROM_TABLE_32BIT_MASK = 0x2

# 2's complement offset to debug component from ROM table base address.
ROM_TABLE_ADDR_OFFSET_NEG_MASK = 0x80000000
ROM_TABLE_ADDR_OFFSET_MASK = 0xfffff000
ROM_TABLE_ADDR_OFFSET_SHIFT = 12

# 9 entries is enough entries to cover the standard Cortex-M4 ROM table for devices with ETM.
ROM_TABLE_ENTRY_READ_COUNT = 9
ROM_TABLE_MAX_ENTRIES = 960

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
#  0x13 = CPU trace source
#  0x21 = ETB
#  0x12 = Trace funnel
#  0x14 = ECT

# Map from PIDR to component name (eventually class).
PID_TABLE = {
        0x4001bb932 : 'MTB-M0+',
        0x00008e000 : 'MTBDWT',
        0x4000bb9a6 : 'CTI',
        0x4000bb4c0 : 'ROM',
        0x4000bb008 : 'SCS-M0+',
        0x4000bb00a : 'DWT-M0+',
        0x4000bb00b : 'BPU',
        0x4000bb00c : 'SCS-M4',
        0x4003bb002 : 'DWT',
        0x4002bb003 : 'FPB',
        0x4003bb001 : 'ITM',
        0x4000bb9a1 : 'TPIU-M4',
        0x4000bb925 : 'ETM-M4',
        0x4003bb907 : 'ETB',
        0x4001bb908 : 'CSTF',
        0x4000bb000 : 'SCS-M3',
        0x4003bb923 : 'TPIU-M3',
        0x4003bb924 : 'ETM-M3'
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
        self.devtype = 0
        self.devid = 0
        self.count_4kb = 0
        self.name = ''
        self.valid = False

    def read_id_registers(self):
        # Read Component ID and Peripheral ID registers. This is done as a single block read
        # for performance reasons.
        regs = self.ap.readBlockMemoryAligned32(self.top_address + PIDR4, IDR_COUNT)
        self.cidr = self._extract_id_register_value(regs, CIDR0_OFFSET)
        self.pidr = (self._extract_id_register_value(regs, PIDR4_OFFSET) << 32) | self._extract_id_register_value(regs, PIDR0_OFFSET)

        # Check if the component has a valid CIDR value
        if (self.cidr & CIDR_PREAMBLE_MASK) != CIDR_PREAMBLE_VALUE:
            logging.warning("Invalid coresight component, cidr=0x%x", self.cidr)
            return

        self.name = PID_TABLE.get(self.pidr, '')

        component_class = (self.cidr & CIDR_COMPONENT_CLASS_MASK) >> CIDR_COMPONENT_CLASS_SHIFT
        is_rom_table = (component_class == CIDR_ROM_TABLE_CLASS)

        count_4kb = 1 << ((self.pidr & PIDR_4KB_COUNT_MASK) >> PIDR_4KB_COUNT_SHIFT)
        if count_4kb > 1:
            address = self.top_address - (4096 * (count_4kb - 1))

        # From section 10.4 of ARM Debug InterfaceArchitecture Specification ADIv5.0 to ADIv5.2
        # In a ROM Table implementation:
        # - The Component class field, CIDR1.CLASS is 0x1, identifying the component as a ROM Table.
        # - The PIDR4.SIZE field must be 0. This is because a ROM Table must occupy a single 4KB block of memory.
        if is_rom_table and count_4kb != 1:
            logging.warning("Invalid rom table size=%x * 4KB", count_4kb)
            return

        if component_class == CIDR_CORESIGHT_CLASS:
            self.devid, self.devtype = self.ap.readBlockMemoryAligned32(self.top_address + DEVID, 2)

        self.component_class = component_class
        self.is_rom_table = is_rom_table
        self.count_4kb = count_4kb
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
            return "<%08x:%s cidr=%x, pidr=%x, class=%d, devtype=%x, devid=%x>" % (self.address, self.name, self.cidr, self.pidr, self.component_class, self.devtype, self.devid)
        else:
            return "<%08x:%s cidr=%x, pidr=%x, class=%d>" % (self.address, self.name, self.cidr, self.pidr, self.component_class)


class ROMTable(CoreSightComponent):
    def __init__(self, ap, top_addr=None, parent_table=None):
        # If no table address is provided, use the root ROM table for the AP.
        if top_addr is None:
            top_addr = ap.rom_addr
        super(ROMTable, self).__init__(ap, top_addr)
        self.parent = parent_table
        self.number = (self.parent.number + 1) if self.parent else 0
        self.entry_size = 0
        self.components = []

    def init(self):
        self.read_id_registers()
        if not self.is_rom_table:
            logging.warning("Warning: ROM table @ 0x%08x has unexpected CIDR component class (0x%x)", self.address, self.component_class)
            return
        if self.count_4kb != 1:
            logging.warning("Warning: ROM table @ 0x%08x is larger than 4kB (%d 4kb pages)", self.address, self.count_4kb)
        self.read_table()

    def read_table(self):
        logging.info("ROM table #%d @ 0x%08x cidr=%x pidr=%x", self.number, self.address, self.cidr, self.pidr)
        self.components = []

        # Switch to the 8-bit table entry reader if we already know the entry size.
        if self.entry_size == 8:
            self.read_table_8()

        entryAddress = self.address
        foundEnd = False
        entriesRead = 0
        while not foundEnd and entriesRead < ROM_TABLE_MAX_ENTRIES:
            # Read several entries at a time for performance.
            readCount = min(ROM_TABLE_MAX_ENTRIES - entriesRead, ROM_TABLE_ENTRY_READ_COUNT)
            entries = self.ap.readBlockMemoryAligned32(entryAddress, readCount)
            entriesRead += readCount

            # Determine entry size if unknown.
            if self.entry_size == 0:
                self.entry_size = 32 if (entries[0] & ROM_TABLE_32BIT_MASK) else 8
                if self.entry_size == 8:
                    # Read 8-bit table.
                    self.read_table_8()
                    return

            for entry in entries:
                # Zero entry indicates the end of the table.
                if entry == 0:
                    foundEnd = True
                    break
                self.handle_table_entry(entry)

                entryAddress += 4

    def read_table_8(self):
        entryAddress = self.address
        while True:
            # Read the full 32-bit table entry spread across four bytes.
            entry = self.ap.read8(entryAddress)
            entry |= self.ap.read8(entryAddress + 4) << 8
            entry |= self.ap.read8(entryAddress + 8) << 16
            entry |= self.ap.read8(entryAddress + 12) << 24

            # Zero entry indicates the end of the table.
            if entry == 0:
                break
            self.handle_table_entry(entry)

            entryAddress += 16

    def handle_table_entry(self, entry):
        # Nonzero entries can still be disabled, so check the present bit before handling.
        if (entry & ROM_TABLE_ENTRY_PRESENT_MASK) == 0:
            return

        # Get the component's top 4k address.
        offset = entry & ROM_TABLE_ADDR_OFFSET_MASK
        if (entry & ROM_TABLE_ADDR_OFFSET_NEG_MASK) != 0:
            offset = ~invert32(offset)
        address = self.address + offset

        # Create component instance.
        cmp = CoreSightComponent(self.ap, address)
        cmp.read_id_registers()

        logging.info("[%d]%s", len(self.components), str(cmp))

        # Recurse into child ROM tables.
        if cmp.is_rom_table:
            cmp = ROMTable(self.ap, address, parent_table=self)
            cmp.init()

        self.components.append(cmp)


