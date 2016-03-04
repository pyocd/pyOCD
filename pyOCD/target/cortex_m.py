"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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
from xml.etree.ElementTree import (Element, SubElement, tostring)

from .target import Target
from pyOCD.target.dap import (DP_REG, AP_REG, Dap)
from pyOCD.pyDAPAccess import DAPAccess
from ..gdbserver import signals
from ..utility import conversion
import logging
import struct

# CPUID PARTNO values
ARM_CortexM0 = 0xC20
ARM_CortexM1 = 0xC21
ARM_CortexM3 = 0xC23
ARM_CortexM4 = 0xC24
ARM_CortexM0p = 0xC60

# User-friendly names for core types.
CORE_TYPE_NAME = {
                 ARM_CortexM0 : "Cortex-M0",
                 ARM_CortexM1 : "Cortex-M1",
                 ARM_CortexM3 : "Cortex-M3",
                 ARM_CortexM4 : "Cortex-M4",
                 ARM_CortexM0p : "Cortex-M0+"
               }

AHB_IDR_TO_WRAP_SIZE = {
    0x24770011 : 0x1000,    # Used on m4 & m3 - Documented in arm_cortexm4_processor_trm_100166_0001_00_en.pdf
                            #                   and arm_cortexm3_processor_trm_100165_0201_00_en.pdf
    0x44770001 : 0x400,     # Used on m1 - Documented in DDI0413D_cortexm1_r1p0_trm.pdf
    0x04770031 : 0x400,     # Used on m0+? at least on KL25Z, KL46, LPC812
    0x04770021 : 0x400,     # Used on m0? used on nrf51, lpc11u24
    0x74770001 : 0x400,     # Used on m0+ on KL28Z
    }

WATCH_TYPE_TO_FUNCT = {
                        Target.WATCHPOINT_READ: 5,
                        Target.WATCHPOINT_WRITE: 6,
                        Target.WATCHPOINT_READ_WRITE: 7
                        }
# Only sizes that are powers of 2 are supported
# Breakpoint size = MASK**2
WATCH_SIZE_TO_MASK = dict((2 ** i, i) for i in range(0, 32))


# Maps the fault code found in the IPSR to a GDB signal value.
FAULT = [
            signals.SIGSTOP,
            signals.SIGSTOP,    # Reset
            signals.SIGINT,     # NMI
            signals.SIGSEGV,    # HardFault
            signals.SIGSEGV,    # MemManage
            signals.SIGBUS,     # BusFault
            signals.SIGILL,     # UsageFault
                                                # The rest are not faults
         ]


# Map from register name to DCRSR register index.
#
# The CONTROL, FAULTMASK, BASEPRI, and PRIMASK registers are special in that they share the
# same DCRSR register index and are returned as a single value. In this dict, these registers
# have negative values to signal to the register read/write functions that special handling
# is necessary. The values are the byte number containing the register value, plus 1 and then
# negated. So -1 means a mask of 0xff, -2 is 0xff00, and so on. The actual DCRSR register index
# for these combined registers has the key of 'cfbp'.
CORE_REGISTER = {
                 'r0': 0,
                 'r1': 1,
                 'r2': 2,
                 'r3': 3,
                 'r4': 4,
                 'r5': 5,
                 'r6': 6,
                 'r7': 7,
                 'r8': 8,
                 'r9': 9,
                 'r10': 10,
                 'r11': 11,
                 'r12': 12,
                 'sp': 13,
                 'r13': 13,
                 'lr': 14,
                 'r14': 14,
                 'pc': 15,
                 'r15': 15,
                 'xpsr': 16,
                 'msp': 17,
                 'psp': 18,
                 'cfbp': 20,
                 'control':-4,
                 'faultmask':-3,
                 'basepri':-2,
                 'primask':-1,
                 'fpscr': 33,
                 's0': 0x40,
                 's1': 0x41,
                 's2': 0x42,
                 's3': 0x43,
                 's4': 0x44,
                 's5': 0x45,
                 's6': 0x46,
                 's7': 0x47,
                 's8': 0x48,
                 's9': 0x49,
                 's10': 0x4a,
                 's11': 0x4b,
                 's12': 0x4c,
                 's13': 0x4d,
                 's14': 0x4e,
                 's15': 0x4f,
                 's16': 0x50,
                 's17': 0x51,
                 's18': 0x52,
                 's19': 0x53,
                 's20': 0x54,
                 's21': 0x55,
                 's22': 0x56,
                 's23': 0x57,
                 's24': 0x58,
                 's25': 0x59,
                 's26': 0x5a,
                 's27': 0x5b,
                 's28': 0x5c,
                 's29': 0x5d,
                 's30': 0x5e,
                 's31': 0x5f,
                 }

class Breakpoint(object):
    def __init__(self, comp_register_addr):
        self.type = Target.BREAKPOINT_HW
        self.comp_register_addr = comp_register_addr
        self.enabled = False
        self.addr = 0
        self.original_instr = 0


class Watchpoint():
    def __init__(self, comp_register_addr):
        self.comp_register_addr = comp_register_addr
        self.addr = 0
        self.size = 0
        self.func = 0


class CortexM(Target):

    """
    This class has basic functions to access a Cortex M core:
       - init
       - read/write memory
       - read/write core registers
       - set/remove hardware breakpoints
    """

    # Debug Fault Status Register
    DFSR = 0xE000ED30
    DFSR_EXTERNAL = (1 << 4)
    DFSR_VCATCH = (1 << 3)
    DFSR_DWTTRAP = (1 << 2)
    DFSR_BKPT = (1 << 1)
    DFSR_HALTED = (1 << 0)

    # Debug Exception and Monitor Control Register
    DEMCR = 0xE000EDFC
    # DWTENA in armv6 architecture reference manual
    DEMCR_TRCENA = (1 << 24)
    DEMCR_VC_HARDERR = (1 << 10)
    DEMCR_VC_BUSERR = (1 << 8)
    DEMCR_VC_CORERESET = (1 << 0)

    # CPUID Register
    CPUID = 0xE000ED00

    # CPUID masks
    CPUID_IMPLEMENTER_MASK = 0xff000000
    CPUID_IMPLEMENTER_POS = 24
    CPUID_VARIANT_MASK = 0x00f00000
    CPUID_VARIANT_POS = 20
    CPUID_ARCHITECTURE_MASK = 0x000f0000
    CPUID_ARCHITECTURE_POS = 16
    CPUID_PARTNO_MASK = 0x0000fff0
    CPUID_PARTNO_POS = 4
    CPUID_REVISION_MASK = 0x0000000f
    CPUID_REVISION_POS = 0

    CPUID_IMPLEMENTER_ARM = 0x41
    ARMv6M = 0xC
    ARMv7M = 0xF

    # Debug Core Register Selector Register
    DCRSR = 0xE000EDF4
    DCRSR_REGWnR = (1 << 16)
    DCRSR_REGSEL = 0x1F

    # Debug Halting Control and Status Register
    DHCSR = 0xE000EDF0
    C_DEBUGEN = (1 << 0)
    C_HALT = (1 << 1)
    C_STEP = (1 << 2)
    C_MASKINTS = (1 << 3)
    C_SNAPSTALL = (1 << 5)
    S_REGRDY = (1 << 16)
    S_HALT = (1 << 17)
    S_SLEEP = (1 << 18)
    S_LOCKUP = (1 << 19)

    # Debug Core Register Data Register
    DCRDR = 0xE000EDF8

    # Coprocessor Access Control Register
    CPACR = 0xE000ED88
    CPACR_CP10_CP11_MASK = (3 << 20) | (3 << 22)

    NVIC_AIRCR = (0xE000ED0C)
    NVIC_AIRCR_VECTKEY = (0x5FA << 16)
    NVIC_AIRCR_VECTRESET = (1 << 0)
    NVIC_AIRCR_SYSRESETREQ = (1 << 2)

    CSYSPWRUPACK = 0x80000000
    CDBGPWRUPACK = 0x20000000
    CSYSPWRUPREQ = 0x40000000
    CDBGPWRUPREQ = 0x10000000

    TRNNORMAL = 0x00000000
    MASKLANE = 0x00000f00


    DBGKEY = (0xA05F << 16)

    # FPB (breakpoint)
    FP_CTRL = (0xE0002000)
    FP_CTRL_KEY = (1 << 1)
    FP_COMP0 = (0xE0002008)

    # DWT (data watchpoint & trace)
    DWT_CTRL = 0xE0001000
    DWT_COMP_BASE = 0xE0001020
    DWT_MASK_OFFSET = 4
    DWT_FUNCTION_OFFSET = 8
    DWT_COMP_BLOCK_SIZE = 0x10

    class RegisterInfo(object):
        def __init__(self, name, bitsize, reg_type, reg_group):
            self.name = name
            self.reg_num = CORE_REGISTER[name]
            self.gdb_xml_attrib = {}
            self.gdb_xml_attrib['name'] = str(name)
            self.gdb_xml_attrib['bitsize'] = str(bitsize)
            self.gdb_xml_attrib['type'] = str(reg_type)
            self.gdb_xml_attrib['group'] = str(reg_group)

    regs_general = [
        #            Name       bitsize     type            group
        RegisterInfo('r0',      32,         'int',          'general'),
        RegisterInfo('r1',      32,         'int',          'general'),
        RegisterInfo('r2',      32,         'int',          'general'),
        RegisterInfo('r3',      32,         'int',          'general'),
        RegisterInfo('r4',      32,         'int',          'general'),
        RegisterInfo('r5',      32,         'int',          'general'),
        RegisterInfo('r6',      32,         'int',          'general'),
        RegisterInfo('r7',      32,         'int',          'general'),
        RegisterInfo('r8',      32,         'int',          'general'),
        RegisterInfo('r9',      32,         'int',          'general'),
        RegisterInfo('r10',     32,         'int',          'general'),
        RegisterInfo('r11',     32,         'int',          'general'),
        RegisterInfo('r12',     32,         'int',          'general'),
        RegisterInfo('sp',      32,         'data_ptr',     'general'),
        RegisterInfo('lr',      32,         'int',          'general'),
        RegisterInfo('pc',      32,         'code_ptr',     'general'),
        RegisterInfo('xpsr',    32,         'int',          'general'),
        RegisterInfo('msp',     32,         'int',          'general'),
        RegisterInfo('psp',     32,         'int',          'general'),
        RegisterInfo('primask', 32,         'int',          'general'),
        RegisterInfo('control', 32,         'int',          'general'),
        ]

    regs_system_armv7_only = [
        #            Name       bitsize     type            group
        RegisterInfo('basepri',     32,     'int',          'general'),
        RegisterInfo('faultmask',   32,     'int',          'general'),
        ]

    regs_float = [
        #            Name       bitsize     type            group
        RegisterInfo('fpscr',   32,         'int',          'float'),
        RegisterInfo('s0' ,     32,         'float',        'float'),
        RegisterInfo('s1' ,     32,         'float',        'float'),
        RegisterInfo('s2' ,     32,         'float',        'float'),
        RegisterInfo('s3' ,     32,         'float',        'float'),
        RegisterInfo('s4' ,     32,         'float',        'float'),
        RegisterInfo('s5' ,     32,         'float',        'float'),
        RegisterInfo('s6' ,     32,         'float',        'float'),
        RegisterInfo('s7' ,     32,         'float',        'float'),
        RegisterInfo('s8' ,     32,         'float',        'float'),
        RegisterInfo('s9' ,     32,         'float',        'float'),
        RegisterInfo('s10',     32,         'float',        'float'),
        RegisterInfo('s11',     32,         'float',        'float'),
        RegisterInfo('s12',     32,         'float',        'float'),
        RegisterInfo('s13',     32,         'float',        'float'),
        RegisterInfo('s14',     32,         'float',        'float'),
        RegisterInfo('s15',     32,         'float',        'float'),
        RegisterInfo('s16',     32,         'float',        'float'),
        RegisterInfo('s17',     32,         'float',        'float'),
        RegisterInfo('s18',     32,         'float',        'float'),
        RegisterInfo('s19',     32,         'float',        'float'),
        RegisterInfo('s20',     32,         'float',        'float'),
        RegisterInfo('s21',     32,         'float',        'float'),
        RegisterInfo('s22',     32,         'float',        'float'),
        RegisterInfo('s23',     32,         'float',        'float'),
        RegisterInfo('s24',     32,         'float',        'float'),
        RegisterInfo('s25',     32,         'float',        'float'),
        RegisterInfo('s26',     32,         'float',        'float'),
        RegisterInfo('s27',     32,         'float',        'float'),
        RegisterInfo('s28',     32,         'float',        'float'),
        RegisterInfo('s29',     32,         'float',        'float'),
        RegisterInfo('s30',     32,         'float',        'float'),
        RegisterInfo('s31',     64,         'float',        'float'),
        ]

    def __init__(self, link, memoryMap=None):
        super(CortexM, self).__init__(link, memoryMap)

        self.idcode = 0
        self.hw_breakpoints = []
        self.breakpoints = {}
        self.nb_code = 0
        self.nb_lit = 0
        self.num_hw_breakpoint_used = 0
        self.nb_lit = 0
        self.fpb_enabled = False
        self.watchpoints = []
        self.watchpoint_used = 0
        self.dwt_configured = False
        self.arch = 0
        self.core_type = 0
        self.has_fpu = False
        self.part_number = self.__class__.__name__
        self.dap = Dap(link)

    def init(self, initial_setup=True, bus_accessible=True):
        """
        Cortex M initialization
        """
        if initial_setup:
            self.link.connect()
            self.idcode = self.readIDCode()
            self.dap.init()

            # select bank 0 (to access DRW and TAR)
            self.dap.writeDP(DP_REG['SELECT'], 0)
            self.dap.writeDP(DP_REG['CTRL_STAT'], CortexM.CSYSPWRUPREQ | CortexM.CDBGPWRUPREQ)

            while True:
                r = self.dap.readDP(DP_REG['CTRL_STAT'])
                if (r & (CortexM.CDBGPWRUPACK | CortexM.CSYSPWRUPACK)) == (CortexM.CDBGPWRUPACK | CortexM.CSYSPWRUPACK):
                    break

            self.dap.writeDP(DP_REG['CTRL_STAT'], CortexM.CSYSPWRUPREQ | CortexM.CDBGPWRUPREQ | CortexM.TRNNORMAL | CortexM.MASKLANE)
            self.dap.writeDP(DP_REG['SELECT'], 0)

            ahb_idr = self.dap.readAP(AP_REG['IDR'])
            if ahb_idr in AHB_IDR_TO_WRAP_SIZE:
                self.auto_increment_page_size = AHB_IDR_TO_WRAP_SIZE[ahb_idr]
            else:
                # If unknown use the smallest size supported by all targets.
                # A size smaller than the supported size will decrease performance
                # due to the extra address writes, but will not create any
                # read/write errors.
                self.auto_increment_page_size = 0x400
                logging.warning("Unknown AHB IDR: 0x%x" % ahb_idr)

        if bus_accessible:
            if self.halt_on_connect:
                self.halt()
            self.setupFPB()
            self.readCoreType()
            self.checkForFPU()
            self.setupDWT()
            self.buildTargetXML()

    def buildTargetXML(self):
        # Build register_list and targetXML
        self.register_list = []
        xml_root = Element('target')
        xml_regs_general = SubElement(xml_root, "feature", name="org.gnu.gdb.arm.m-profile")
        for reg in self.regs_general:
            self.register_list.append(reg)
            SubElement(xml_regs_general, 'reg', **reg.gdb_xml_attrib)
        # Check if target has ARMv7 registers
        if self.core_type in  (ARM_CortexM3, ARM_CortexM4):
            for reg in self.regs_system_armv7_only:
                self.register_list.append(reg)
                SubElement(xml_regs_general, 'reg', **reg.gdb_xml_attrib)
        # Check if target has FPU registers
        if self.has_fpu:
            #xml_regs_fpu = SubElement(xml_root, "feature", name="org.gnu.gdb.arm.vfp")
            for reg in self.regs_float:
                self.register_list.append(reg)
                SubElement(xml_regs_general, 'reg', **reg.gdb_xml_attrib)
        self.targetXML = '<?xml version="1.0"?><!DOCTYPE feature SYSTEM "gdb-target.dtd">' + tostring(xml_root)

    ## @brief Read the CPUID register and determine core type.
    def readCoreType(self):
        # Read CPUID register
        cpuid = self.read32(CortexM.CPUID)

        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        if implementer != CortexM.CPUID_IMPLEMENTER_ARM:
            logging.warning("CPU implementer is not ARM!")

        self.arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        logging.info("CPU core is %s", CORE_TYPE_NAME[self.core_type])

    ## @brief Determine if a Cortex-M4 has an FPU.
    #
    # The core type must have been identified prior to calling this function.
    def checkForFPU(self):
        if self.core_type != ARM_CortexM4:
            self.has_fpu = False
            return

        originalCpacr = self.read32(CortexM.CPACR)
        cpacr = originalCpacr | CortexM.CPACR_CP10_CP11_MASK
        self.write32(CortexM.CPACR, cpacr)

        cpacr = self.read32(CortexM.CPACR)
        self.has_fpu = (cpacr & CortexM.CPACR_CP10_CP11_MASK) != 0

        # Restore previous value.
        self.write32(CortexM.CPACR, originalCpacr)

        if self.has_fpu:
            logging.info("FPU present")


    def setupFPB(self):
        """
        Reads the number of hardware breakpoints available on the core
        and disable the FPB (Flash Patch and Breakpoint Unit)
        which will be enabled when a first breakpoint will be set
        """
        # setup FPB (breakpoint)
        fpcr = self.readMemory(CortexM.FP_CTRL)
        self.nb_code = ((fpcr >> 8) & 0x70) | ((fpcr >> 4) & 0xF)
        self.nb_lit = (fpcr >> 7) & 0xf
        logging.info("%d hardware breakpoints, %d literal comparators", self.nb_code, self.nb_lit)
        for i in range(self.nb_code):
            self.hw_breakpoints.append(Breakpoint(CortexM.FP_COMP0 + 4 * i))

        # disable FPB (will be enabled on first bp set)
        self.disableFPB()
        for bp in self.hw_breakpoints:
            self.writeMemory(bp.comp_register_addr, 0)

    def setupDWT(self):
        """
        Reads the number of hardware watchpoints available on the core
        and makes sure that they are all disabled and ready for future
        use
        """
        demcr = self.readMemory(CortexM.DEMCR)
        demcr = demcr | CortexM.DEMCR_TRCENA
        self.writeMemory(CortexM.DEMCR, demcr)
        dwt_ctrl = self.readMemory(CortexM.DWT_CTRL)
        watchpoint_count = (dwt_ctrl >> 28) & 0xF
        logging.info("%d hardware watchpoints", watchpoint_count)
        for i in range(watchpoint_count):
            self.watchpoints.append(Watchpoint(CortexM.DWT_COMP_BASE + CortexM.DWT_COMP_BLOCK_SIZE * i))
            self.writeMemory(CortexM.DWT_COMP_BASE + CortexM.DWT_COMP_BLOCK_SIZE * i + CortexM.DWT_FUNCTION_OFFSET, 0)
        self.dwt_configured = True

    def info(self, request):
        return self.link.info(request)

    def flush(self):
        self.link.flush()

    def readIDCode(self):
        """
        return the IDCODE of the core
        """
        self.idcode = self.dap.readDP(DP_REG['IDCODE'])
        return self.idcode

    def writeMemory(self, addr, value, transfer_size=32):
        """
        write a memory location.
        By default the transfer size is a word
        """
        self.dap.writeMem(addr, value, transfer_size)
        return

    def write32(self, addr, value):
        """
        Shorthand to write a 32-bit word.
        """
        self.writeMemory(addr, value, 32)

    def write16(self, addr, value):
        """
        Shorthand to write a 16-bit halfword.
        """
        self.writeMemory(addr, value, 16)

    def write8(self, addr, value):
        """
        Shorthand to write a byte.
        """
        self.writeMemory(addr, value, 8)

    def readMemory(self, addr, transfer_size=32, now=True):
        """
        read a memory location. By default, a word will
        be read
        """
        return self.dap.readMem(addr, transfer_size, now=now)

    def read32(self, addr):
        """
        Shorthand to read a 32-bit word.
        """
        return self.readMemory(addr, 32)

    def read16(self, addr):
        """
        Shorthand to read a 16-bit halfword.
        """
        return self.readMemory(addr, 16)

    def read8(self, addr):
        """
        Shorthand to read a byte.
        """
        return self.readMemory(addr, 8)

    def readBlockMemoryUnaligned8(self, addr, size):
        """
        read a block of unaligned bytes in memory. Returns
        an array of byte values
        """
        res = []

        # try to read 8bits data
        if (size > 0) and (addr & 0x01):
            mem = self.readMemory(addr, 8)
#             logging.debug("get 1 byte at %s: 0x%X", hex(addr), mem)
            res.append(mem)
            size -= 1
            addr += 1

        # try to read 16bits data
        if (size > 1) and (addr & 0x02):
            mem = self.readMemory(addr, 16)
#             logging.debug("get 2 bytes at %s: 0x%X", hex(addr), mem)
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        # try to read aligned block of 32bits
        if (size >= 4):
            #logging.debug("read blocks aligned at 0x%X, size: 0x%X", addr, (size/4)*4)
            mem = self.readBlockMemoryAligned32(addr, size / 4)
            res += conversion.u32leListToByteList(mem)
            size -= 4 * len(mem)
            addr += 4 * len(mem)

        if (size > 1):
            mem = self.readMemory(addr, 16)
#             logging.debug("get 2 bytes at %s: 0x%X", hex(addr), mem)
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        if (size > 0):
            mem = self.readMemory(addr, 8)
#             logging.debug("get 1 byte remaining at %s: 0x%X", hex(addr), mem)
            res.append(mem)
            size -= 1
            addr += 1

        return res


    def writeBlockMemoryUnaligned8(self, addr, data):
        """
        write a block of unaligned bytes in memory.
        """
        size = len(data)
        idx = 0

        #try to write 8 bits data
        if (size > 0) and (addr & 0x01):
#             logging.debug("write 1 byte at 0x%X: 0x%X", addr, data[idx])
            self.writeMemory(addr, data[idx], 8)
            size -= 1
            addr += 1
            idx += 1

        # try to write 16 bits data
        if (size > 1) and (addr & 0x02):
#             logging.debug("write 2 bytes at 0x%X: 0x%X", addr, data[idx] | (data[idx+1] << 8))
            self.writeMemory(addr, data[idx] | (data[idx + 1] << 8), 16)
            size -= 2
            addr += 2
            idx += 2

        # write aligned block of 32 bits
        if (size >= 4):
            #logging.debug("write blocks aligned at 0x%X, size: 0x%X", addr, (size/4)*4)
            data32 = conversion.byteListToU32leList(data[idx:idx + (size & ~0x03)])
            self.writeBlockMemoryAligned32(addr, data32)
            addr += size & ~0x03
            idx += size & ~0x03
            size -= size & ~0x03

        # try to write 16 bits data
        if (size > 1):
#             logging.debug("write 2 bytes at 0x%X: 0x%X", addr, data[idx] | (data[idx+1] << 8))
            self.writeMemory(addr, data[idx] | (data[idx + 1] << 8), 16)
            size -= 2
            addr += 2
            idx += 2

        #try to write 8 bits data
        if (size > 0):
#             logging.debug("write 1 byte at 0x%X: 0x%X", addr, data[idx])
            self.writeMemory(addr, data[idx], 8)
            size -= 1
            addr += 1
            idx += 1

        return

    def writeBlockMemoryAligned32(self, addr, data):
        """
        write a block of aligned words in memory.
        """
        size = len(data)
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size * 4 < n:
                n = (size * 4) & 0xfffffffc
            self.dap.writeBlock32(addr, data[:n / 4])
            data = data[n / 4:]
            size -= n / 4
            addr += n
        return

    def readBlockMemoryAligned32(self, addr, size):
        """
        read a block of aligned words in memory. Returns
        an array of word values
        """
        resp = []
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size * 4 < n:
                n = (size * 4) & 0xfffffffc
            resp += self.dap.readBlock32(addr, n / 4)
            size -= n / 4
            addr += n
        return resp

    def halt(self):
        """
        halt the core
        """
        self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)
        self.flush()
        return

    def step(self, disable_interrupts=True):
        """
        perform an instruction level step.  This function preserves the previous
        interrupt mask state
        """
        # Was 'if self.getState() != TARGET_HALTED:'
        # but now value of dhcsr is saved
        dhcsr = self.readMemory(CortexM.DHCSR)
        if not (dhcsr & (CortexM.C_STEP | CortexM.C_HALT)):
            logging.error('cannot step: target not halted')
            return

        self.clearDebugCauseBits()

        # Save previous interrupt mask state
        interrupts_masked = (CortexM.C_MASKINTS & dhcsr) != 0

        # Mask interrupts - C_HALT must be set when changing to C_MASKINTS
        if not interrupts_masked and disable_interrupts:
            self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT | CortexM.C_MASKINTS)

        # Single step using current C_MASKINTS setting
        if disable_interrupts or interrupts_masked:
            self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_MASKINTS | CortexM.C_STEP)
        else:
            self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_STEP)

        # Wait for halt to auto set (This should be done before the first read)
        while not self.readMemory(CortexM.DHCSR) & CortexM.C_HALT:
            pass

        # Restore interrupt mask state
        if not interrupts_masked and disable_interrupts:
            # Unmask interrupts - C_HALT must be set when changing to C_MASKINTS
            self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)

        self.flush()
        return

    def clearDebugCauseBits(self):
        self.writeMemory(CortexM.DFSR, CortexM.DFSR_DWTTRAP | CortexM.DFSR_BKPT | CortexM.DFSR_HALTED)

    def reset(self, software_reset=None):
        """
        reset a core. After a call to this function, the core
        is running
        """
        if software_reset == None:
            # Default to software reset if nothing is specified
            software_reset = True

        if software_reset:
            self.writeMemory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | CortexM.NVIC_AIRCR_SYSRESETREQ)
            # Without a flush a transfer error can occur
            self.flush()
        else:
            self.link.reset()

    def resetStopOnReset(self, software_reset=None):
        """
        perform a reset and stop the core on the reset handler
        """
        logging.debug("reset stop on Reset")

        # halt the target
        self.halt()

        # Save CortexM.DEMCR
        demcr = self.readMemory(CortexM.DEMCR)

        # enable the vector catch
        self.writeMemory(CortexM.DEMCR, demcr | CortexM.DEMCR_VC_CORERESET)

        self.reset(software_reset)

        # wait until the unit resets
        while (self.getState() == Target.TARGET_RUNNING):
            pass

        # restore vector catch setting
        self.writeMemory(CortexM.DEMCR, demcr)

    def setTargetState(self, state):
        if state == "PROGRAM":
            self.resetStopOnReset(True)
            # Write the thumb bit in case the reset handler
            # points to an ARM address
            self.writeCoreRegister('xpsr', 0x1000000)

    def getState(self):
        dhcsr = self.readMemory(CortexM.DHCSR)
        if dhcsr & (CortexM.C_STEP | CortexM.C_HALT):
            return Target.TARGET_HALTED
        return Target.TARGET_RUNNING

    def resume(self):
        """
        resume the execution
        """
        if self.getState() != Target.TARGET_HALTED:
            logging.debug('cannot resume: target not halted')
            return
        self.clearDebugCauseBits()
        self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)
        self.flush()
        return

    def findBreakpoint(self, addr):
        return self.breakpoints.get(addr, None)

    def readCoreRegister(self, reg):
        """
        read CPU register
        Unpack floating point register values
        """
        regIndex = self.registerNameToIndex(reg)
        regValue = self.readCoreRegisterRaw(regIndex)
        # Convert int to float.
        if regIndex >= 0x40:
            regValue = conversion.u32BEToFloat32BE(regValue)
        return regValue

    def registerNameToIndex(self, reg):
        """
        return register index based on name.
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        if isinstance(reg, str):
            try:
                reg = CORE_REGISTER[reg.lower()]
            except KeyError:
                logging.error('cannot find %s core register', reg)
                return
        return reg

    def readCoreRegisterRaw(self, reg):
        """
        read a core register (r0 .. r16).
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        vals = self.readCoreRegistersRaw([reg])
        return vals[0]

    def readCoreRegistersRaw(self, reg_list):
        """
        Read one or more core registers

        Read core registers in reg_list and return a list of values.
        If any register in reg_list is a string, find the number
        associated to this register in the lookup table CORE_REGISTER.
        """
        # convert to index only
        reg_list = [self.registerNameToIndex(reg) for reg in reg_list]

        # Sanity check register values
        for reg in reg_list:
            if reg not in CORE_REGISTER.values():
                raise ValueError("unknown reg: %d" % reg)
            elif ((reg >= 128) or (reg == 33)) and (not self.has_fpu):
                raise ValueError("attempt to read FPU register without FPU")

        # Begin all reads and writes
        dhcsr_cb_list = []
        reg_cb_list = []
        for reg in reg_list:
            if (reg < 0) and (reg >= -4):
                reg = CORE_REGISTER['cfbp']

            # write id in DCRSR
            self.writeMemory(CortexM.DCRSR, reg)

            # Technically, we need to poll S_REGRDY in DHCSR here before reading DCRDR. But
            # we're running so slow compared to the target that it's not necessary.
            # Read it and assert that S_REGRDY is set

            dhcsr_cb = self.readMemory(CortexM.DHCSR, now=False)
            reg_cb = self.readMemory(CortexM.DCRDR, now=False)
            dhcsr_cb_list.append(dhcsr_cb)
            reg_cb_list.append(reg_cb)

        # Read all results
        reg_vals = []
        for reg, reg_cb, dhcsr_cb in zip(reg_list, reg_cb_list, dhcsr_cb_list):
            dhcsr_val = dhcsr_cb()
            assert dhcsr_val & CortexM.S_REGRDY
            val = reg_cb()

            # Special handling for registers that are combined
            # into a single DCRSR number.
            if (reg < 0) and (reg >= -4):
                val = (val >> ((-reg - 1) * 8)) & 0xff

            reg_vals.append(val)

        return reg_vals

    def writeCoreRegister(self, reg, data):
        """
        write a CPU register.
        Will need to pack floating point register values before writing.
        """
        regIndex = self.registerNameToIndex(reg)
        # Convert float to int.
        if regIndex >= 0x40:
            data = conversion.float32beToU32be(data)
        self.writeCoreRegisterRaw(regIndex, data)

    def writeCoreRegisterRaw(self, reg, data):
        """
        write a core register (r0 .. r16)
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        self.writeCoreRegistersRaw([reg], [data])

    def writeCoreRegistersRaw(self, reg_list, data_list):
        """
        Write one or more core registers

        Write core registers in reg_list with the associated value in
        data_list.  If any register in reg_list is a string, find the number
        associated to this register in the lookup table CORE_REGISTER.
        """
        assert len(reg_list) == len(data_list)
        # convert to index only
        reg_list = [self.registerNameToIndex(reg) for reg in reg_list]

        # Sanity check register values
        for reg in reg_list:
            if reg not in CORE_REGISTER.values():
                raise ValueError("unknown reg: %d" % reg)
            elif ((reg >= 128) or (reg == 33)) and (not self.has_fpu):
                raise ValueError("attempt to write FPU register without FPU")

        # Read special register if it is present in the list
        for reg in reg_list:
            if (reg < 0) and (reg >= -4):
                specialRegValue = self.readCoreRegister(CORE_REGISTER['cfbp'])
                break

        # Write out registers
        dhcsr_cb_list = []
        for reg, data in zip(reg_list, data_list):
            if (reg < 0) and (reg >= -4):
                # Mask in the new special register value so we don't modify the other register
                # values that share the same DCRSR number.
                shift = (-reg - 1) * 8
                mask = 0xffffffff ^ (0xff << shift)
                data = (specialRegValue & mask) | ((data & 0xff) << shift)
                specialRegValue = data # update special register for other writes that might be in the list
                reg = CORE_REGISTER['cfbp']

            # write DCRDR
            self.writeMemory(CortexM.DCRDR, data)

            # write id in DCRSR and flag to start write transfer
            self.writeMemory(CortexM.DCRSR, reg | CortexM.DCRSR_REGWnR)

            # Technically, we need to poll S_REGRDY in DHCSR here to ensure the
            # register write has completed.
            # Read it and assert that S_REGRDY is set
            dhcsr_cb = self.readMemory(CortexM.DHCSR, now=False)
            dhcsr_cb_list.append(dhcsr_cb)

        # Make sure S_REGRDY was set for all register
        # writes
        for dhcsr_cb in dhcsr_cb_list:
            dhcsr_val = dhcsr_cb()
            assert dhcsr_val & CortexM.S_REGRDY

    ## @brief Set a hardware or software breakpoint at a specific location in memory.
    #
    # @retval True Breakpoint was set.
    # @retval False Breakpoint could not be set.
    def setBreakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        logging.debug("set bkpt type %d at 0x%x", type, addr)

        # Clear Thumb bit in case it is set.
        addr = addr & ~1

        # Check for an existing breakpoint at this address.
        bp = self.findBreakpoint(addr)
        if bp is not None:
            return True

        # Look up the memory region for the requested address. If there is no region,
        # then we can't set a breakpoint.
        region = self.memory_map.getRegionForAddress(addr)
        if region is None:
            return False

        # Determine best type to use if auto.
        if type == Target.BREAKPOINT_AUTO:
            # Use sw breaks for:
            #  1. Addresses outside the supported FPBv1 range of 0-0x1fffffff
            #  2. RAM regions by default.
            #  3. No hw breaks are left.
            #
            # Otherwise use hw.
            if (addr >= 0x20000000) or (region.isRam) or (self.availableBreakpoint() == 0):
                type = Target.BREAKPOINT_SW
            else:
                type = Target.BREAKPOINT_HW

            logging.debug("using type %d for auto bp", type)

        # Revert to sw bp above 0x2000_0000.
        if (type == Target.BREAKPOINT_HW) and (addr >= 0x20000000):
            logging.debug("using sw bp instead because of unsupported addr")
            type = Target.BREAKPOINT_SW

        # Revert to hw bp if region is flash.
        if region.isFlash:
            logging.debug("using hw bp instead because addr is flash")
            type = Target.BREAKPOINT_HW

        # Set the bp.
        if type == Target.BREAKPOINT_HW:
            return self.setHardwareBreakpoint(addr)
        elif type == Target.BREAKPOINT_SW:
            return self.setSoftwareBreakpoint(addr)
        else:
            raise RuntimeError("Unknown breakpoint type %d" % type)

    ## @brief Remove a breakpoint at a specific location.
    def removeBreakpoint(self, addr):
        try:
            logging.debug("remove bkpt at 0x%x", addr)

            # Clear Thumb bit in case it is set.
            addr = addr & ~1

            # Get bp and remove from dict.
            bp = self.breakpoints.pop(addr)

            # Remove bp by type.
            if bp.type == Target.BREAKPOINT_SW:
                self.removeSoftwareBreakpoint(bp)
            elif bp.type == Target.BREAKPOINT_HW:
                self.removeHardwareBreakpoint(bp.addr)
            else:
                raise RuntimeError("Unknown breakpoint type %d" % bp.type)

        except KeyError:
            logging.debug("Tried to remove breakpoint 0x%08x that wasn't set" % addr)

    def getBreakpointType(self, addr):
        bp = self.findBreakpoint(addr)
        return bp.type if (bp is not None) else None

    def setSoftwareBreakpoint(self, addr):
        assert self.memory_map.getRegionForAddress(addr).isRam
        assert (addr & 1) == 0

        try:
            # Read original instruction.
            instr = self.read16(addr)

            # Insert BKPT #0 instruction.
            self.write16(addr, 0xbe00)

            # Create bp object.
            bp = Breakpoint(0)
            bp.type = Target.BREAKPOINT_SW
            bp.enabled = True
            bp.addr = addr
            bp.original_instr = instr

            self.breakpoints[addr] = bp
            return True
        except DAPAccess.TransferError:
            logging.debug("Failed to set sw bp at 0x%x" % addr)
            return False

    def removeSoftwareBreakpoint(self, bp):
        assert bp is not None and isinstance(bp, Breakpoint)

        try:
            # Restore original instruction.
            self.write16(bp.addr, bp.original_instr)
        except DAPAccess.TransferError:
            logging.debug("Failed to set sw bp at 0x%x" % bp.addr)

    def setHardwareBreakpoint(self, addr):
        """
        set a hardware breakpoint at a specific location in flash
        """
        if self.fpb_enabled is False:
            self.enableFPB()

        if addr >= 0x20000000:
            # Hardware breakpoints are only supported in the range
            # 0x00000000 - 0x1fffffff on cortex-m devices
            logging.error('Breakpoint out of range 0x%X', addr)
            return False

        if self.availableBreakpoint() == 0:
            logging.error('No more available breakpoint!!, dropped bp at 0x%X', addr)
            return False

        for bp in self.hw_breakpoints:
            if not bp.enabled:
                bp.enabled = True
                bp_match = (1 << 30)
                if addr & 0x2:
                    bp_match = (2 << 30)
                self.writeMemory(bp.comp_register_addr, addr & 0x1ffffffc | bp_match | 1)
                bp.addr = addr
                self.num_hw_breakpoint_used += 1
                self.breakpoints[addr] = bp
                return True
        return False

    def availableBreakpoint(self):
        return len(self.hw_breakpoints) - self.num_hw_breakpoint_used

    def enableFPB(self):
        self.writeMemory(CortexM.FP_CTRL, CortexM.FP_CTRL_KEY | 1)
        self.fpb_enabled = True
        logging.debug('fpb has been enabled')
        return

    def disableFPB(self):
        self.writeMemory(CortexM.FP_CTRL, CortexM.FP_CTRL_KEY | 0)
        self.fpb_enabled = False
        logging.debug('fpb has been disabled')
        return

    def removeHardwareBreakpoint(self, addr):
        """
        remove a hardware breakpoint at a specific location in flash
        """
        for bp in self.hw_breakpoints:
            if bp.enabled and bp.addr == addr:
                bp.enabled = False
                self.writeMemory(bp.comp_register_addr, 0)
                bp.addr = addr
                self.num_hw_breakpoint_used -= 1
                return
        return

    def findWatchpoint(self, addr, size, type):
        for watch in self.watchpoints:
            if watch.addr == addr and watch.size == size and watch.func == WATCH_TYPE_TO_FUNCT[type]:
                return watch
        return None

    def setWatchpoint(self, addr, size, type):
        """
        set a hardware watchpoint
        """
        if self.dwt_configured is False:
            self.setupDWT()

        watch = self.findWatchpoint(addr, size, type)
        if watch != None:
            return True

        if type not in WATCH_TYPE_TO_FUNCT:
            logging.error("Invalid watchpoint type %i", type)
            return False

        for watch in self.watchpoints:
            if watch.func == 0:
                watch.addr = addr
                watch.func = WATCH_TYPE_TO_FUNCT[type]
                watch.size = size

                if size not in WATCH_SIZE_TO_MASK:
                    logging.error('Watchpoint of size %d not supported by device', size)
                    return False

                mask = WATCH_SIZE_TO_MASK[size]
                self.writeMemory(watch.comp_register_addr + CortexM.DWT_MASK_OFFSET, mask)
                if self.readMemory(watch.comp_register_addr + CortexM.DWT_MASK_OFFSET) != mask:
                    logging.error('Watchpoint of size %d not supported by device', size)
                    return False

                self.writeMemory(watch.comp_register_addr, addr)
                self.writeMemory(watch.comp_register_addr + CortexM.DWT_FUNCTION_OFFSET, watch.func)
                self.watchpoint_used += 1
                return True

        logging.error('No more available watchpoint!!, dropped watch at 0x%X', addr)
        return False

    def removeWatchpoint(self, addr, size, type):
        """
        remove a hardware watchpoint
        """
        watch = self.findWatchpoint(addr, size, type)
        if watch is None:
            return

        watch.func = 0
        self.writeMemory(watch.comp_register_addr + CortexM.DWT_FUNCTION_OFFSET, 0)
        self.watchpoint_used -= 1
        return

    def setVectorCatchFault(self, enable):
        demcr = self.readMemory(CortexM.DEMCR)
        if enable:
            demcr = demcr | CortexM.DEMCR_VC_HARDERR
        else:
            demcr = demcr & ~CortexM.DEMCR_VC_HARDERR
        self.writeMemory(CortexM.DEMCR, demcr)

    def getVectorCatchFault(self):
        return bool(self.readMemory(CortexM.DEMCR) & CortexM.DEMCR_VC_HARDERR)

    def setVectorCatchReset(self, enable):
        demcr = self.readMemory(CortexM.DEMCR)
        if enable:
            demcr = demcr | CortexM.DEMCR_VC_CORERESET
        else:
            demcr = demcr & ~CortexM.DEMCR_VC_CORERESET
        self.writeMemory(CortexM.DEMCR, demcr)

    def getVectorCatchReset(self):
        return bool(self.readMemory(CortexM.DEMCR) & CortexM.DEMCR_VC_CORERESET)

    # GDB functions
    def getTargetXML(self):
        return self.targetXML

    def getRegisterContext(self):
        """
        return hexadecimal dump of registers as expected by GDB
        """
        logging.debug("GDB getting register context")
        resp = ''
        reg_num_list = map(lambda reg:reg.reg_num, self.register_list)
        vals = self.readCoreRegistersRaw(reg_num_list)
        #print("Vals: %s" % vals)
        for reg, regValue in zip(self.register_list, vals):
            resp += conversion.u32beToHex8le(regValue)
            logging.debug("GDB reg: %s = 0x%X", reg.name, regValue)

        return resp

    def setRegisterContext(self, data):
        """
        Set registers from GDB hexadecimal string.
        """
        logging.debug("GDB setting register context")
        reg_num_list = []
        reg_data_list = []
        for reg in self.register_list:
            regValue = conversion.hex8leToU32be(data)
            reg_num_list.append(reg.reg_num)
            reg_data_list.append(regValue)
            logging.debug("GDB reg: %s = 0x%X", reg.name, regValue)
            data = data[8:]
        self.writeCoreRegistersRaw(reg_num_list, reg_data_list)

    def setRegister(self, reg, data):
        """
        Set single register from GDB hexadecimal string.
        reg parameter is the index of register in targetXML sent to GDB.
        """
        if reg < 0:
            return
        elif reg < len(self.register_list):
            regName = self.register_list[reg].name
            value = conversion.hex8leToU32be(data)
            logging.debug("GDB: write reg %s: 0x%X", regName, value)
            self.writeCoreRegisterRaw(regName, value)

    def gdbGetRegister(self, reg):
        resp = ''
        if reg < len(self.register_list):
            regName = self.register_list[reg].name
            regValue = self.readCoreRegisterRaw(regName)
            resp = conversion.u32beToHex8le(regValue)
            logging.debug("GDB reg: %s = 0x%X", regName, regValue)
        return resp

    def getTResponse(self, forceSignal=None):
        """
        Returns a GDB T response string.  This includes:
            The signal encountered.
            The current value of the important registers (sp, lr, pc).
        """
        if forceSignal is not None:
            response = 'T' + conversion.byteToHex2(forceSignal)
        else:
            response = 'T' + conversion.byteToHex2(self.getSignalValue())

        # Append fp(r7), sp(r13), lr(r14), pc(r15)
        response += self.getRegIndexValuePairs([7, 13, 14, 15])

        # Append thread and core
        response += "thread:1;core:0;"

        return response

    def getSignalValue(self):
        if self.isDebugTrap():
            return signals.SIGTRAP

        fault = self.readCoreRegister('xpsr') & 0xff
        try:
            signal = FAULT[fault]
        except:
            # If not a fault then default to SIGSTOP
            signal = signals.SIGSTOP
        logging.debug("GDB lastSignal: %d", signal)
        return signal

    def isDebugTrap(self):
        debugEvents = self.readMemory(CortexM.DFSR) & (CortexM.DFSR_DWTTRAP | CortexM.DFSR_BKPT | CortexM.DFSR_HALTED)
        return debugEvents != 0

    def getRegIndexValuePairs(self, regIndexList):
        """
        Returns a string like NN:MMMMMMMM;NN:MMMMMMMM;...
            for the T response string.  NN is the index of the
            register to follow MMMMMMMM is the value of the register.
        """
        str = ''
        regList = self.readCoreRegistersRaw(regIndexList)
        for regIndex, reg in zip(regIndexList, regList):
            str += conversion.byteToHex2(regIndex) + ':' + conversion.u32beToHex8le(reg) + ';'
        return str

    def getThreadsXML(self):
        root = Element('threads')
        t = SubElement(root, 'thread', id="1", core="0")
        t.text = "Thread mode"
        return '<?xml version="1.0"?><!DOCTYPE feature SYSTEM "threads.dtd">' + tostring(root)
