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

from ..core import (exceptions, memory_interface)
from .rom_table import ROMTable
from ..utility import conversion
import logging

# Set to True to enable logging of all DP and AP accesses.
LOG_DAP = False

# Common AP register addresses
AP_BASE = 0xF8
AP_IDR = 0xFC

# MEM-AP register addresses
MEM_AP_CSW = 0x00
MEM_AP_TAR = 0x04
MEM_AP_DRW = 0x0C

A32 = 0x0c
APSEL_SHIFT = 24
APSEL = 0xff000000
APBANKSEL = 0x000000f0
APREG_MASK = 0x000000fc

AP_ROM_TABLE_FORMAT_MASK = 0x2
AP_ROM_TABLE_ENTRY_PRESENT_MASK = 0x1

# AP IDR bitfields:
# [31:28] Revision
# [27:24] JEP106 continuation (0x4 for ARM)
# [23:17] JEP106 vendor ID (0x3B for ARM)
# [16:13] Class (0b1000=Mem-AP)
# [12:8]  Reserved
# [7:4]   AP Variant (non-zero for JTAG-AP)
# [3:0]   AP Type
AP_IDR_REVISION_MASK = 0xf0000000
AP_IDR_REVISION_SHIFT = 28
AP_IDR_JEP106_MASK = 0x0ffe0000
AP_IDR_JEP106_SHIFT = 17
AP_IDR_CLASS_MASK = 0x0001e000
AP_IDR_CLASS_SHIFT = 13
AP_IDR_VARIANT_MASK = 0x000000f0
AP_IDR_VARIANT_SHIFT = 4
AP_IDR_TYPE_MASK = 0x0000000f

AP_JEP106_ARM = 0x23b

# AP classes
AP_CLASS_NONE   = 0x00000 # No class defined
AP_CLASS_MEM_AP = 0x8 # MEM-AP

# MEM-AP type constants
AP_TYPE_AHB = 0x1
AP_TYPE_APB = 0x2
AP_TYPE_AXI = 0x4
AP_TYPE_AHB5 = 0x5

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
    ## @brief Determine if an AP exists with the given AP number.
    # @param dp DebugPort instance.
    # @param ap_num The AP number (APSEL) to probe.
    # @return Boolean indicating if a valid AP exists with APSEL=ap_num.
    @staticmethod
    def probe(dp, ap_num):
        idr = dp.read_ap((ap_num << APSEL_SHIFT) | AP_IDR)
        return idr != 0
    
    ## @brief Create a new AP object.
    #
    # Determines the type of the AP by examining the IDR value and creates a new
    # AP object of the appropriate class. See #AP_TYPE_MAP for the mapping of IDR
    # fields to class.
    # 
    # @param dp DebugPort instance.
    # @param ap_num The AP number (APSEL) to probe.
    # @return An AccessPort subclass instance.
    #
    # @exception RuntimeError Raised if there is not a valid AP for the ap_num.
    @staticmethod
    def create(dp, ap_num):
        # Attempt to read the IDR for this APSEL. If we get a zero back then there is
        # no AP present, so we return None.
        idr = dp.read_ap((ap_num << APSEL_SHIFT) | AP_IDR)
        if idr == 0:
            raise RuntimeError("Invalid APSEL=%d", ap_num)
        
        # Extract IDR fields used for lookup.
        designer = (idr & AP_IDR_JEP106_MASK) >> AP_IDR_JEP106_SHIFT
        apClass = (idr & AP_IDR_CLASS_MASK) >> AP_IDR_CLASS_SHIFT
        variant = (idr & AP_IDR_VARIANT_MASK) >> AP_IDR_VARIANT_SHIFT
        apType = idr & AP_IDR_TYPE_MASK

        # Get the AccessPort class to instantiate.        
        key = (designer, apClass, variant, apType)
        klass = AP_TYPE_MAP.get(key, AccessPort)
        
        ap = klass(dp, ap_num)
        ap.init()
        return ap
    
    def __init__(self, dp, ap_num):
        self.dp = dp
        self.ap_num = ap_num
        self.link = dp.link
        self.idr = 0
        self.rom_addr = 0
        self.has_rom_table = False
        self.rom_table = None
        self.core = None
        if LOG_DAP:
            self.logger = self.dp.logger.getChild('ap%d' % ap_num)

    def init(self):
        self.idr = self.read_reg(AP_IDR)

        # Init ROM table
        self.rom_addr = self.read_reg(AP_BASE)
        self.has_rom_table = (self.rom_addr != 0xffffffff) and ((self.rom_addr & AP_ROM_TABLE_ENTRY_PRESENT_MASK) != 0)
        self.rom_addr &= 0xfffffffc # clear format and present bits

    def init_rom_table(self):
        if self.has_rom_table:
            self.rom_table = ROMTable(self)
            self.rom_table.init()

    def read_reg(self, addr, now=True):
        return self.dp.read_ap((self.ap_num << APSEL_SHIFT) | addr, now)

    def write_reg(self, addr, data):
        self.dp.write_ap((self.ap_num << APSEL_SHIFT) | addr, data)
    
    def reset_did_occur(self):
        pass

class MEM_AP(AccessPort, memory_interface.MemoryInterface):
    def __init__(self, dp, ap_num):
        super(MEM_AP, self).__init__(dp, ap_num)
        
        ## Cached CSW value.
        self._csw = -1

        # Default to the smallest size supported by all targets.
        # A size smaller than the supported size will decrease performance
        # due to the extra address writes, but will not create any
        # read/write errors.
        self.auto_increment_page_size = 0x400
        
        # Ask the probe for an accelerated memory interface for this AP. If it provides one,
        # then bind our memory interface APIs to its methods. Otherwise use our standard
        # memory interface based on AP register accesses.
        memoryInterface = self.dp.link.get_memory_interface_for_ap(self.ap_num)
        if memoryInterface is not None:
            logging.debug("Using accelerated memory access interface")
            self.write_memory = memoryInterface.write_memory
            self.read_memory = memoryInterface.read_memory
            self.write_memory_block32 = memoryInterface.write_memory_block32
            self.read_memory_block32 = memoryInterface.read_memory_block32
        else:
            self.write_memory = self._write_memory
            self.read_memory = self._read_memory
            self.write_memory_block32 = self._write_memory_block32
            self.read_memory_block32 = self._read_memory_block32

    def read_reg(self, addr, now=True):
        ap_regaddr = addr & APREG_MASK
        if ap_regaddr == MEM_AP_CSW and self._csw != -1 and now:
            return self._csw
        return super(MEM_AP, self).read_reg(addr, now)

    def write_reg(self, addr, data):
        ap_regaddr = addr & APREG_MASK

        # Don't need to write CSW if it's not changing value.
        if ap_regaddr == MEM_AP_CSW:
            if data == self._csw:
                if LOG_DAP:
                    num = self.dp.next_access_number
                    self.logger.info("write_ap:%06d cached (addr=0x%08x) = 0x%08x", num, addr, data)
                return
            self._csw = data

        try:
            super(MEM_AP, self).write_reg(addr, data)
        except exceptions.ProbeError:
            # Invalidate cached CSW on exception.
            if ap_regaddr == MEM_AP_CSW:
                self._csw = -1
            raise
    
    def reset_did_occur(self):
        # TODO use notifications to invalidate CSW cache.
        self._csw = -1

    ## @brief Write a single memory location.
    #
    # By default the transfer size is a word
    def _write_memory(self, addr, data, transfer_size=32):
        assert (addr & (transfer_size // 8 - 1)) == 0
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("write_mem:%06d (addr=0x%08x, size=%d) = 0x%08x {", num, addr, transfer_size, data)
        self.write_reg(MEM_AP_CSW, CSW_VALUE | TRANSFER_SIZE[transfer_size])
        if transfer_size == 8:
            data = data << ((addr & 0x03) << 3)
        elif transfer_size == 16:
            data = data << ((addr & 0x02) << 3)

        try:
            self.write_reg(MEM_AP_TAR, addr)
            self.write_reg(MEM_AP_DRW, data)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = transfer_size // 8
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise
        if LOG_DAP:
            self.logger.info("write_mem:%06d }", num)

    ## @brief Read a memory location.
    #
    # By default, a word will be read.
    def _read_memory(self, addr, transfer_size=32, now=True):
        assert (addr & (transfer_size // 8 - 1)) == 0
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("read_mem:%06d (addr=0x%08x, size=%d) {", num, addr, transfer_size)
        res = None
        try:
            self.write_reg(MEM_AP_CSW, CSW_VALUE | TRANSFER_SIZE[transfer_size])
            self.write_reg(MEM_AP_TAR, addr)
            result_cb = self.read_reg(MEM_AP_DRW, now=False)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = transfer_size // 8
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise

        def read_mem_cb():
            try:
                res = result_cb()
                if transfer_size == 8:
                    res = (res >> ((addr & 0x03) << 3) & 0xff)
                elif transfer_size == 16:
                    res = (res >> ((addr & 0x02) << 3) & 0xffff)
                if LOG_DAP:
                    self.logger.info("read_mem:%06d %s(addr=0x%08x, size=%d) -> 0x%08x }", num, "" if now else "...", addr, transfer_size, res)
            except exceptions.TransferFaultError as error:
                # Annotate error with target address.
                self._handle_error(error, num)
                error.fault_address = addr
                error.fault_length = transfer_size // 8
                raise
            except exceptions.Error as error:
                self._handle_error(error, num)
                raise
            return res

        if now:
            result = read_mem_cb()
            return result
        else:
            return read_mem_cb

    ## @brief Write a single transaction's worth of aligned words.
    #
    # The transaction must not cross the MEM-AP's auto-increment boundary.
    def _write_block32(self, addr, data):
        assert (addr & 0x3) == 0
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("_write_block32:%06d (addr=0x%08x, size=%d) {", num, addr, len(data))
        # put address in TAR
        self.write_reg(MEM_AP_CSW, CSW_VALUE | CSW_SIZE32)
        self.write_reg(MEM_AP_TAR, addr)
        try:
            self.link.write_ap_multiple(MEM_AP_DRW, data)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = len(data) * 4
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise
        if LOG_DAP:
            self.logger.info("_write_block32:%06d }", num)

    ## @brief Read a single transaction's worth of aligned words.
    #
    # The transaction must not cross the MEM-AP's auto-increment boundary.
    def _read_block32(self, addr, size):
        assert (addr & 0x3) == 0
        num = self.dp.next_access_number
        if LOG_DAP:
            self.logger.info("_read_block32:%06d (addr=0x%08x, size=%d) {", num, addr, size)
        # put address in TAR
        self.write_reg(MEM_AP_CSW, CSW_VALUE | CSW_SIZE32)
        self.write_reg(MEM_AP_TAR, addr)
        try:
            resp = self.link.read_ap_multiple(MEM_AP_DRW, size)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = size * 4
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise
        if LOG_DAP:
            self.logger.info("_read_block32:%06d }", num)
        return resp

    ## @brief Write a block of aligned words in memory.
    def _write_memory_block32(self, addr, data):
        assert (addr & 0x3) == 0
        size = len(data)
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            self._write_block32(addr, data[:n//4])
            data = data[n//4:]
            size -= n//4
            addr += n
        return

    ## @brief Read a block of aligned words in memory.
    #
    # @return An array of word values
    def _read_memory_block32(self, addr, size):
        assert (addr & 0x3) == 0
        resp = []
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            resp += self._read_block32(addr, n//4)
            size -= n//4
            addr += n
        return resp

    def _handle_error(self, error, num):
        self.dp._handle_error(error, num)
        self._csw = -1

class AHB_AP(MEM_AP):
    def init_rom_table(self):
        # Turn on DEMCR.TRCENA before reading the ROM table. Some ROM table entries will
        # come back as garbage if TRCENA is not set.
        try:
            demcr = self.read32(DEMCR)
            self.write32(DEMCR, demcr | DEMCR_TRCENA)
            self.dp.flush()
        except exceptions.TransferError:
            # Ignore exception and read whatever we can of the ROM table.
            pass

        # Invoke superclass.
        super(AHB_AP, self).init_rom_table()

## @brief AHB-AP with a 4k auto increment wrap size.
#
# The only known AHB-AP with a 4k wrap is the one documented in the CM3 and CM4 TRMs.
# It has an IDR of 0x24770011, which decodes to AHB-AP, variant 1, version 2.
class AHB_AP_4k_Wrap(AHB_AP):
    def __init__(self, dp, ap_num):
        super(AHB_AP_4k_Wrap, self).__init__(dp, ap_num)

        # Set a 4 kB auto increment wrap size.
        self.auto_increment_page_size = 0x1000

## Map from AP IDR fields to AccessPort subclass.
#
# The dict key is a 4-tuple of (JEP106 code, AP class, variant, type).
#
# Known AP IDRs:
# 0x24770011 AHB-AP with 0x1000 wrap
#               Used on m4 & m3 - Documented in arm_cortexm4_processor_trm_100166_0001_00_en.pdf
#               and arm_cortexm3_processor_trm_100165_0201_00_en.pdf
# 0x34770001 AHB-AP Documented in DDI0314H_coresight_components_trm.pdf
# 0x44770001 AHB-AP Used on m1 - Documented in DDI0413D_cortexm1_r1p0_trm.pdf
# 0x04770031 AHB-AP Used on m0+? at least on KL25Z, KL46, LPC812
# 0x04770021 AHB-AP Used on m0? used on nrf51, lpc11u24
# 0x64770001 AHB-AP Used on m7, documented in DDI0480G_coresight_soc_trm.pdf
# 0x74770001 AHB-AP Used on m0+ on KL28Z
# 0x84770001 AHB-AP Used on K32W042
# 0x14770005 AHB5-AP Used on M33. Note that M33 r0p0 incorrect fails to report this IDR.
# 0x54770002 APB-AP used on M33.
AP_TYPE_MAP = {
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 0, AP_TYPE_AHB) : AHB_AP,
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 1, AP_TYPE_AHB) : AHB_AP_4k_Wrap,
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 2, AP_TYPE_AHB) : AHB_AP,
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 3, AP_TYPE_AHB) : AHB_AP,
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 0, AP_TYPE_APB) : MEM_AP,
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 0, AP_TYPE_AXI) : MEM_AP,
    (AP_JEP106_ARM, AP_CLASS_MEM_AP, 0, AP_TYPE_AHB5) : AHB_AP,
    }

