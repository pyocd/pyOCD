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
        self.cidr = 0
        self.pidr = 0
        self.devtype = 0
        self.devid = 0
        self.count_4kb = 0
        self.name = ''

    def read_id_registers(self):
        # Read Component ID and Peripheral ID registers.
        self.cidr = self.read_id_register_set(CIDR0)
        self.pidr = (self.read_id_register_set(PIDR4) << 32) | self.read_id_register_set(PIDR0)

        self.name = PID_TABLE.get(self.pidr, '')

        self.component_class = (self.cidr & CIDR_COMPONENT_CLASS_MASK) >> CIDR_COMPONENT_CLASS_SHIFT
        self.is_rom_table = (self.component_class == CIDR_ROM_TABLE_CLASS)

        self.count_4kb = 1 << ((self.pidr & PIDR_4KB_COUNT_MASK) >> PIDR_4KB_COUNT_SHIFT)
        if self.count_4kb > 1:
            address = self.top_address - (4096 * (self.count_4kb - 1))
#             print "addr=%x" % address

        if self.component_class == CIDR_CORESIGHT_CLASS:
            self.devtype = self.ap.read32(self.top_address + DEVTYPE)
            self.devid = self.ap.read32(self.top_address + DEVID)

    def read_id_register_set(self, offset):
        result = 0
        for i in range(4):
            value = self.ap.read32(self.top_address + offset + i * 4)
            result |= (value & 0xff) << (i * 8)
        return result

    def __str__(self):
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
        self.entry_size = self.get_entry_size()
        self.read_table()

    ## @brief Read the first word to get the size of all entries.
    #
    # ROM tables are required to have all entries be the same size.
    #
    # @retval 32
    # @retval 8
    def get_entry_size(self):
        data = self.ap.read32(self.address)
        if data & ROM_TABLE_32BIT_MASK:
            return 32
        else:
            return 8

    def read_table(self):
        logging.info("ROM table #%d @ 0x%08x", self.number, self.address)
        self.components = []
        if self.entry_size == 32:
            self.read_table_32()
        else:
            self.read_table_8()

    def read_table_32(self):
        entryAddress = self.address
        while True:
            entry = self.ap.read32(entryAddress)

            # Zero entry indicates the end of the table.
            if entry == 0:
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

        offset = entry & ROM_TABLE_ADDR_OFFSET_MASK
        if (entry & ROM_TABLE_ADDR_OFFSET_NEG_MASK) != 0:
            offset = ~invert32(offset)
        address = self.address + offset
#         print "Found ROM entry: offset=%x, addr=%x" % (offset, address)

        cmp = CoreSightComponent(self.ap, address)
        cmp.read_id_registers()

        logging.info("[%d]%s", len(self.components), str(cmp))

        if cmp.is_rom_table:
            cmp = ROMTable(self.ap, address, parent_table=self)
            cmp.init()

        self.components.append(cmp)


