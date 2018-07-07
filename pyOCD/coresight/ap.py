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

from ..pyDAPAccess import DAPAccess
from .rom_table import ROMTable
from .dap import (AP_REG, _ap_addr_to_reg, READ, WRITE, AP_ACC, APSEL_SHIFT, LOG_DAP)
from ..utility import conversion
import logging

AP_ROM_TABLE_ADDR_REG = 0xf8
AP_ROM_TABLE_FORMAT_MASK = 0x2
AP_ROM_TABLE_ENTRY_PRESENT_MASK = 0x1

MEM_AP_IDR_TO_WRAP_SIZE = {
    0x24770011 : 0x1000,    # Used on m4 & m3 - Documented in arm_cortexm4_processor_trm_100166_0001_00_en.pdf
                            #                   and arm_cortexm3_processor_trm_100165_0201_00_en.pdf
    0x44770001 : 0x400,     # Used on m1 - Documented in DDI0413D_cortexm1_r1p0_trm.pdf
    0x04770031 : 0x400,     # Used on m0+? at least on KL25Z, KL46, LPC812
    0x04770021 : 0x400,     # Used on m0? used on nrf51, lpc11u24
    0x64770001 : 0x400,     # Used on m7
    0x74770001 : 0x400,     # Used on m0+ on KL28Z
    0x84770001 : 0x400,     # Used on K32W042
    }

# AP Control and Status Word definitions
CSW_SIZE     =  0x00000007
CSW_SIZE8    =  0x00000000
CSW_SIZE16   =  0x00000001
CSW_SIZE32   =  0x00000002
CSW_ADDRINC  =  0x00000030
CSW_NADDRINC =  0x00000000
CSW_SADDRINC =  0x00000010
CSW_PADDRINC =  0x00000020
CSW_DBGSTAT  =  0x00000040
CSW_TINPROG  =  0x00000080
CSW_HPROT    =  0x02000000
CSW_MSTRTYPE =  0x20000000
CSW_MSTRCORE =  0x00000000
CSW_MSTRDBG  =  0x20000000
CSW_RESERVED =  0x01000000

CSW_VALUE = (CSW_RESERVED | CSW_MSTRDBG | CSW_HPROT | CSW_DBGSTAT | CSW_SADDRINC)

TRANSFER_SIZE = {8: CSW_SIZE8,
                 16: CSW_SIZE16,
                 32: CSW_SIZE32
                 }

# Debug Exception and Monitor Control Register
DEMCR = 0xE000EDFC
# DWTENA in armv6 architecture reference manual
DEMCR_TRCENA = (1 << 24)

class AccessPort(object):
    def __init__(self, dp, ap_num):
        self.dp = dp
        self.ap_num = ap_num
        self.link = dp.link
        self.idr = 0
        self.rom_addr = 0
        self.has_rom_table = False
        self.rom_table = None
        self.inited_primary = False
        self.inited_secondary = False
        if LOG_DAP:
            self.logger = self.dp.logger.getChild('ap%d' % ap_num)

    def init(self, bus_accessible=True):
        if not self.inited_primary:
            self.idr = self.read_reg(AP_REG['IDR'])

            # Init ROM table
            self.rom_addr = self.read_reg(AP_ROM_TABLE_ADDR_REG)
            self.has_rom_table = (self.rom_addr != 0xffffffff) and ((self.rom_addr & AP_ROM_TABLE_ENTRY_PRESENT_MASK) != 0)
            self.rom_addr &= 0xfffffffc # clear format and present bits

            self.inited_primary = True
        if not self.inited_secondary and self.has_rom_table and bus_accessible:
            self.init_rom_table()
            self.inited_secondary = True

    def init_rom_table(self):
        self.rom_table = ROMTable(self)
        self.rom_table.init()

    def read_reg(self, addr, now=True):
        return self.dp.readAP((self.ap_num << APSEL_SHIFT) | addr, now)

    def write_reg(self, addr, data):
        self.dp.writeAP((self.ap_num << APSEL_SHIFT) | addr, data)

class MEM_AP(AccessPort):
    def __init__(self, dp, ap_num):
        super(MEM_AP, self).__init__(dp, ap_num)

        # Default to the smallest size supported by all targets.
        # A size smaller than the supported size will decrease performance
        # due to the extra address writes, but will not create any
        # read/write errors.
        self.auto_increment_page_size = 0x400

    def init(self, bus_accessible=True):
        super(MEM_AP, self).init(bus_accessible)

        # Look up the page size based on AP ID.
        try:
            self.auto_increment_page_size = MEM_AP_IDR_TO_WRAP_SIZE[self.idr]
        except KeyError:
            logging.warning("Unknown MEM-AP IDR: 0x%x" % self.idr)

    ## @brief Write a single memory location.
    #
    # By default the transfer size is a word
    def writeMemory(self, addr, data, transfer_size=32):
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("writeMem:%06d (addr=0x%08x, size=%d) = 0x%08x {", num, addr, transfer_size, data)
        self.write_reg(AP_REG['CSW'], CSW_VALUE | TRANSFER_SIZE[transfer_size])
        if transfer_size == 8:
            data = data << ((addr & 0x03) << 3)
        elif transfer_size == 16:
            data = data << ((addr & 0x02) << 3)

        try:
            self.write_reg(AP_REG['TAR'], addr)
            self.write_reg(AP_REG['DRW'], data)
        except DAPAccess.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            raise
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise
        if LOG_DAP:
            self.logger.info("writeMem:%06d }", num)

    ## @brief Read a memory location.
    #
    # By default, a word will be read.
    def readMemory(self, addr, transfer_size=32, now=True):
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("readMem:%06d (addr=0x%08x, size=%d) {", num, addr, transfer_size)
        res = None
        try:
            self.write_reg(AP_REG['CSW'], CSW_VALUE |
                         TRANSFER_SIZE[transfer_size])
            self.write_reg(AP_REG['TAR'], addr)
            result_cb = self.read_reg(AP_REG['DRW'], now=False)
        except DAPAccess.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            raise
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise

        def readMemCb():
            try:
                res = result_cb()
                if transfer_size == 8:
                    res = (res >> ((addr & 0x03) << 3) & 0xff)
                elif transfer_size == 16:
                    res = (res >> ((addr & 0x02) << 3) & 0xffff)
                if LOG_DAP:
                    self.logger.info("readMem:%06d %s(addr=0x%08x, size=%d) -> 0x%08x }", num, "" if now else "...", addr, transfer_size, res)
            except DAPAccess.TransferFaultError as error:
                # Annotate error with target address.
                self._handle_error(error, num)
                error.fault_address = addr
                raise
            except DAPAccess.Error as error:
                self._handle_error(error, num)
                raise
            return res

        if now:
            result = readMemCb()
            return result
        else:
            return readMemCb

    # write aligned word ("data" are words)
    def _writeBlock32(self, addr, data):
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("_writeBlock32:%06d (addr=0x%08x, size=%d) {", num, addr, len(data))
        # put address in TAR
        self.write_reg(AP_REG['CSW'], CSW_VALUE | CSW_SIZE32)
        self.write_reg(AP_REG['TAR'], addr)
        try:
            reg = _ap_addr_to_reg((self.ap_num << APSEL_SHIFT) | WRITE | AP_ACC | AP_REG['DRW'])
            self.link.reg_write_repeat(len(data), reg, data)
        except DAPAccess.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            raise
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise
        if LOG_DAP:
            self.logger.info("_writeBlock32:%06d }", num)

    # read aligned word (the size is in words)
    def _readBlock32(self, addr, size):
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("_readBlock32:%06d (addr=0x%08x, size=%d) {", num, addr, size)
        # put address in TAR
        self.write_reg(AP_REG['CSW'], CSW_VALUE | CSW_SIZE32)
        self.write_reg(AP_REG['TAR'], addr)
        try:
            reg = _ap_addr_to_reg((self.ap_num << APSEL_SHIFT) | READ | AP_ACC | AP_REG['DRW'])
            resp = self.link.reg_read_repeat(size, reg)
        except DAPAccess.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            raise
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise
        if LOG_DAP:
            self.logger.info("_readBlock32:%06d }", num)
        return resp

    ## @brief Shorthand to write a 32-bit word.
    def write32(self, addr, value):
        self.writeMemory(addr, value, 32)

    ## @brief Shorthand to write a 16-bit halfword.
    def write16(self, addr, value):
        self.writeMemory(addr, value, 16)

    ## @brief Shorthand to write a byte.
    def write8(self, addr, value):
        self.writeMemory(addr, value, 8)

    ## @brief Shorthand to read a 32-bit word.
    def read32(self, addr, now=True):
        return self.readMemory(addr, 32, now)

    ## @brief Shorthand to read a 16-bit halfword.
    def read16(self, addr, now=True):
        return self.readMemory(addr, 16, now)

    ## @brief Shorthand to read a byte.
    def read8(self, addr, now=True):
        return self.readMemory(addr, 8, now)

    ## @brief Read a block of unaligned bytes in memory.
    # @return an array of byte values
    def readBlockMemoryUnaligned8(self, addr, size):
        res = []

        # try to read 8bits data
        if (size > 0) and (addr & 0x01):
            mem = self.readMemory(addr, 8)
            res.append(mem)
            size -= 1
            addr += 1

        # try to read 16bits data
        if (size > 1) and (addr & 0x02):
            mem = self.readMemory(addr, 16)
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        # try to read aligned block of 32bits
        if (size >= 4):
            mem = self.readBlockMemoryAligned32(addr, size//4)
            res += conversion.u32leListToByteList(mem)
            size -= 4*len(mem)
            addr += 4*len(mem)

        if (size > 1):
            mem = self.readMemory(addr, 16)
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        if (size > 0):
            mem = self.readMemory(addr, 8)
            res.append(mem)
            size -= 1
            addr += 1

        return res

    ## @brief Write a block of unaligned bytes in memory.
    def writeBlockMemoryUnaligned8(self, addr, data):
        size = len(data)
        idx = 0

        #try to write 8 bits data
        if (size > 0) and (addr & 0x01):
            self.writeMemory(addr, data[idx], 8)
            size -= 1
            addr += 1
            idx += 1

        # try to write 16 bits data
        if (size > 1) and (addr & 0x02):
            self.writeMemory(addr, data[idx] | (data[idx+1] << 8), 16)
            size -= 2
            addr += 2
            idx += 2

        # write aligned block of 32 bits
        if (size >= 4):
            data32 = conversion.byteListToU32leList(data[idx:idx + (size & ~0x03)])
            self.writeBlockMemoryAligned32(addr, data32)
            addr += size & ~0x03
            idx += size & ~0x03
            size -= size & ~0x03

        # try to write 16 bits data
        if (size > 1):
            self.writeMemory(addr, data[idx] | (data[idx+1] << 8), 16)
            size -= 2
            addr += 2
            idx += 2

        #try to write 8 bits data
        if (size > 0):
            self.writeMemory(addr, data[idx], 8)
            size -= 1
            addr += 1
            idx += 1

        return

    ## @brief Write a block of aligned words in memory.
    def writeBlockMemoryAligned32(self, addr, data):
        size = len(data)
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            self._writeBlock32(addr, data[:n//4])
            data = data[n//4:]
            size -= n//4
            addr += n
        return

    ## @brief Read a block of aligned words in memory.
    #
    # @return An array of word values
    def readBlockMemoryAligned32(self, addr, size):
        resp = []
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            resp += self._readBlock32(addr, n//4)
            size -= n//4
            addr += n
        return resp

    def _handle_error(self, error, num):
        self.dp._handle_error(error, num)

class AHB_AP(MEM_AP):
    def init_rom_table(self):
        # Turn on DEMCR.TRCENA before reading the ROM table. Some ROM table entries will
        # come back as garbage if TRCENA is not set.
        try:
            demcr = self.read32(DEMCR)
            self.write32(DEMCR, demcr | DEMCR_TRCENA)
            self.dp.flush()
        except DAPAccess.Error:
            # Ignore exception and read whatever we can of the ROM table.
            pass

        # Invoke superclass.
        super(AHB_AP, self).init_rom_table()


