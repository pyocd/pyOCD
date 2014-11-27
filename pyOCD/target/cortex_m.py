"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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

from pyOCD.target.target import Target
from pyOCD.target.target import TARGET_RUNNING, TARGET_HALTED, WATCHPOINT_READ, WATCHPOINT_WRITE, WATCHPOINT_READ_WRITE
from pyOCD.transport.cmsis_dap import DP_REG
import logging
import struct

# Debug Halting Control and Status Register
DHCSR = 0xE000EDF0
# Debug Core Register Selector Register
DCRSR = 0xE000EDF4
REGWnR = (1 << 16)
# Debug Core Register Data Register
DCRDR = 0xE000EDF8
# Debug Exception and Monitor Control Register
DEMCR = 0xE000EDFC

TRACE_ENA = (1 << 24) # DWTENA in armv6 architecture reference manual
VC_HARDERR = (1 << 9)
VC_BUSERR = (1 << 8)
VC_CORERESET = (1 << 0)

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

# DHCSR bit masks
C_DEBUGEN = (1 << 0)
C_HALT = (1 << 1)
C_STEP = (1 << 2)
C_MASKINTS = (1 << 3)
C_SNAPSTALL = (1 << 5)
S_REGRDY = (1 << 16)
S_HALT = (1 << 17)
S_SLEEP = (1 << 18)
S_LOCKUP = (1 << 19)
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
WATCH_TYPE_TO_FUNCT = {
                        WATCHPOINT_READ: 5,
                        WATCHPOINT_WRITE: 6,
                        WATCHPOINT_READ_WRITE: 7
                        }
# Only sizes that are powers of 2 are supported
# Breakpoint size = MASK**2
WATCH_SIZE_TO_MASK = dict((2**i, i) for i in range(0,32))

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
                 'lr': 14,
                 'pc': 15,
                 'xpsr': 16,
                 'msp': 17,
                 'psp': 18,
                 'cfbp': 20,
                 'control': -4,
                 'faultmask': -3,
                 'basepri': -2,
                 'primask': -1,
                 'fpscr': 33,
                 's0': 128,
                 's1': 129,
                 's2': 130,
                 's3': 131,
                 's4': 132,
                 's5': 133,
                 's6': 134,
                 's7': 135,
                 's8': 136,
                 's9': 137,
                 's10': 138,
                 's11': 139,
                 's12': 140,
                 's13': 141,
                 's14': 142,
                 's15': 143,
                 's16': 144,
                 's17': 145,
                 's18': 146,
                 's19': 147,
                 's20': 148,
                 's21': 149,
                 's22': 150,
                 's23': 151,
                 's24': 152,
                 's25': 153,
                 's26': 154,
                 's27': 155,
                 's28': 156,
                 's29': 157,
                 's30': 158,
                 's31': 159,
                 }

"""
convert a byte array into a word array
"""
def byte2word(data):
    res = []
    for i in range(len(data)/4):
        res.append(data[i*4 + 0] << 0  |
                   data[i*4 + 1] << 8  |
                   data[i*4 + 2] << 16 |
                   data[i*4 + 3] << 24)
    return res

"""
convert a word array into a byte array
"""
def word2byte(data):
    res = []
    for x in data:
        res.append((x >> 0) & 0xff)
        res.append((x >> 8) & 0xff)
        res.append((x >> 16) & 0xff)
        res.append((x >> 24) & 0xff)
    return res

## @brief Convert a 32-bit int to an IEEE754 float.
def int2float(data):
    d = struct.pack("@I", data)
    return struct.unpack("@f", d)[0]
## @brief Convert an IEEE754 float to a 32-bit int.
def float2int(data):
    d = struct.pack("@f", data)
    return struct.unpack("@I", d)[0]


class Breakpoint(object):
    def __init__(self, comp_register_addr):
        self.comp_register_addr = comp_register_addr
        self.enabled = False
        self.addr = 0


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

    targetXML = """<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<target>
    <feature name="org.gnu.gdb.arm.m-profile">
        <reg name="r0" bitsize="32"/>
        <reg name="r1" bitsize="32"/>
        <reg name="r2" bitsize="32"/>
        <reg name="r3" bitsize="32"/>
        <reg name="r4" bitsize="32"/>
        <reg name="r5" bitsize="32"/>
        <reg name="r6" bitsize="32"/>
        <reg name="r7" bitsize="32"/>
        <reg name="r8" bitsize="32"/>
        <reg name="r9" bitsize="32"/>
        <reg name="r10" bitsize="32"/>
        <reg name="r11" bitsize="32"/>
        <reg name="r12" bitsize="32"/>
        <reg name="sp" bitsize="32" type="data_ptr"/>
        <reg name="lr" bitsize="32"/>
        <reg name="pc" bitsize="32" type="code_ptr"/>
        <reg name="xpsr" bitsize="32" regnum="16"/>
    </feature>
</target>
"""

    def __init__(self, transport):
        super(CortexM, self).__init__(transport)

        self.auto_increment_page_size = 0
        self.idcode = 0
        self.breakpoints = []
        self.nb_code = 0
        self.nb_lit = 0
        self.num_breakpoint_used = 0
        self.nb_lit = 0
        self.fpb_enabled = False
        self.watchpoints = []
        self.watchpoint_used = 0
        self.dwt_configured = False
        self.arch = 0
        self.core_type = 0
        self.has_fpu = False
        self.part_number = self.__class__.__name__

    def init(self, setup_fpb = True, setup_dwt = True):
        """
        Cortex M initialization
        """
        self.idcode = self.readIDCode()
        # select bank 0 (to access DRW and TAR)
        self.transport.writeDP(DP_REG['SELECT'], 0)
        self.transport.writeDP(DP_REG['CTRL_STAT'], CSYSPWRUPREQ | CDBGPWRUPREQ)

        while True:
            r = self.transport.readDP(DP_REG['CTRL_STAT'])
            if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == (CDBGPWRUPACK | CSYSPWRUPACK):
                break

        self.transport.writeDP(DP_REG['CTRL_STAT'], CSYSPWRUPREQ | CDBGPWRUPREQ | TRNNORMAL | MASKLANE)
        self.transport.writeDP(DP_REG['SELECT'], 0)

        if setup_fpb:
            self.halt()
            self.setupFPB()
            self.readCoreType()
            self.checkForFPU()

        if setup_dwt:
            self.halt()
            self.setupDWT()

    ## @brief Read the CPUID register and determine core type.
    def readCoreType(self):
        # Read CPUID register
        cpuid = self.read32(CPUID)

        implementer = (cpuid & CPUID_IMPLEMENTER_MASK) >> CPUID_IMPLEMENTER_POS
        if implementer != CPUID_IMPLEMENTER_ARM:
            logging.warning("CPU implementer is not ARM!")

        self.arch = (cpuid & CPUID_ARCHITECTURE_MASK) >> CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CPUID_PARTNO_MASK) >> CPUID_PARTNO_POS
        logging.info("CPU core is %s", CORE_TYPE_NAME[self.core_type])

    ## @brief Determine if a Cortex-M4 has an FPU.
    #
    # The core type must have been identified prior to calling this function.
    def checkForFPU(self):
        if self.core_type != ARM_CortexM4:
            self.has_fpu = False
            return

        originalCpacr = self.read32(CPACR)
        cpacr = originalCpacr | CPACR_CP10_CP11_MASK
        self.write32(CPACR, cpacr)

        cpacr = self.read32(CPACR)
        self.has_fpu = (cpacr & CPACR_CP10_CP11_MASK) != 0

        # Restore previous value.
        self.write32(CPACR, originalCpacr)

        if self.has_fpu:
            logging.info("FPU present")


    def setupFPB(self):
        """
        Reads the number of hardware breakpoints available on the core
        and disable the FPB (Flash Patch and Breakpoint Unit)
        which will be enabled when a first breakpoint will be set
        """
        # setup FPB (breakpoint)
        fpcr = self.readMemory(FP_CTRL)
        self.nb_code = ((fpcr >> 8) & 0x70) | ((fpcr >> 4) & 0xF)
        self.nb_lit = (fpcr >> 7) & 0xf
        logging.info("%d hardware breakpoints, %d literal comparators", self.nb_code, self.nb_lit)
        for i in range(self.nb_code):
            self.breakpoints.append(Breakpoint(FP_COMP0 + 4*i))

        # disable FPB (will be enabled on first bp set)
        self.disableFPB()
        for bp in self.breakpoints:
            self.writeMemory(bp.comp_register_addr, 0)

    def setupDWT(self):
        """
        Reads the number of hardware watchpoints available on the core
        and makes sure that they are all disabled and ready for future
        use
        """
        self.writeMemory(DEMCR, TRACE_ENA)
        dwt_ctrl = self.readMemory(DWT_CTRL)
        watchpoint_count = (dwt_ctrl >> 28) & 0xF
        logging.info("%d hardware watchpoints", watchpoint_count)
        for i in range(watchpoint_count):
            self.watchpoints.append(Watchpoint(DWT_COMP_BASE + DWT_COMP_BLOCK_SIZE*i))
            self.writeMemory(DWT_COMP_BASE + DWT_COMP_BLOCK_SIZE*i + DWT_FUNCTION_OFFSET, 0)
        self.dwt_configured = True

    def info(self, request):
        return self.transport.info(request)

    def readIDCode(self):
        """
        return the IDCODE of the core
        """
        if self.idcode == 0:
            self.idcode = self.transport.readDP(DP_REG['IDCODE'])
        return self.idcode

    def writeMemory(self, addr, value, transfer_size = 32):
        """
        write a memory location.
        By default the transfer size is a word
        """
        self.transport.writeMem(addr, value, transfer_size)
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

    def readMemory(self, addr, transfer_size = 32):
        """
        read a memory location. By default, a word will
        be read
        """
        return self.transport.readMem(addr, transfer_size)

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
            logging.debug("get 1 byte at %s: 0x%X", hex(addr), mem)
            res.append(mem)
            size -= 1
            addr += 1

        # try to read 16bits data
        if (size > 1) and (addr & 0x02):
            mem = self.readMemory(addr, 16)
            logging.debug("get 2 bytes at %s: 0x%X", hex(addr), mem)
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        # try to read aligned block of 32bits
        if (size >= 4):
            logging.debug("read blocks aligned at 0x%X, size: 0x%X", addr, (size/4)*4)
            mem = self.readBlockMemoryAligned32(addr, size/4)
            res += word2byte(mem)
            size -= 4*len(mem)
            addr += 4*len(mem)

        if (size > 1):
            mem = self.readMemory(addr, 16)
            logging.debug("get 2 bytes at %s: 0x%X", hex(addr), mem)
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        if (size > 0):
            mem = self.readMemory(addr, 8)
            logging.debug("get 1 byte remaining at %s: 0x%X", hex(addr), mem)
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
            logging.debug("write 1 byte at 0x%X: 0x%X", addr, data[idx])
            self.writeMemory(addr, data[idx], 8)
            size -= 1
            addr += 1
            idx += 1

        # try to write 16 bits data
        if (size > 1) and (addr & 0x02):
            logging.debug("write 2 bytes at 0x%X: 0x%X", addr, data[idx] | (data[idx+1] << 8))
            self.writeMemory(addr, data[idx] | (data[idx+1] << 8), 16)
            size -= 2
            addr += 2
            idx += 2

        # write aligned block of 32 bits
        if (size >= 4):
            logging.debug("write blocks aligned at 0x%X, size: 0x%X", addr, (size/4)*4)
            data32 = byte2word(data[idx:idx + (size & ~0x03)])
            self.writeBlockMemoryAligned32(addr, data32)
            addr += size & ~0x03
            idx += size & ~0x03
            size -= size & ~0x03

        # try to write 16 bits data
        if (size > 1):
            logging.debug("write 2 bytes at 0x%X: 0x%X", addr, data[idx] | (data[idx+1] << 8))
            self.writeMemory(addr, data[idx] | (data[idx+1] << 8), 16)
            size -= 2
            addr += 2
            idx += 2

        #try to write 8 bits data
        if (size > 0):
            logging.debug("write 1 byte at 0x%X: 0x%X", addr, data[idx])
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
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            self.transport.writeBlock32(addr, data[:n/4])
            data = data[n/4:]
            size -= n/4
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
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            resp += self.transport.readBlock32(addr, n/4)
            size -= n/4
            addr += n
        return resp

    def halt(self):
        """
        halt the core
        """
        self.writeMemory(DHCSR, DBGKEY | C_DEBUGEN | C_HALT)
        return

    def step(self):
        """
        perform an instruction level step
        """
        if self.getState() != TARGET_HALTED:
            logging.debug('cannot step: target not halted')
            return
        if self.maybeSkipBreakpoint() is None:
            self.writeMemory(DHCSR, DBGKEY | C_DEBUGEN | C_STEP)
        return

    def reset(self, software_reset = False):
        """
        reset a core. After a call to this function, the core
        is running
        """
        if software_reset:
            self.writeMemory(NVIC_AIRCR, NVIC_AIRCR_VECTKEY | NVIC_AIRCR_SYSRESETREQ)
        else:
            self.transport.reset()

    def resetStopOnReset(self, software_reset = False):
        """
        perform a reset and stop the core on the reset handler
        """
        logging.debug("reset stop on Reset")

        # halt the target
        self.halt()

        # enable the vector catch
        self.writeMemory(DEMCR, VC_CORERESET | TRACE_ENA)

        self.reset(software_reset)

        # wait until the unit resets
        while (self.getState() == TARGET_RUNNING):
            pass

        # disable vector catch
        self.writeMemory(DEMCR, TRACE_ENA)

    def setTargetState(self, state):
        if state == "PROGRAM":
            self.resetStopOnReset(software_reset = True)

    def getState(self):
        dhcsr = self.readMemory(DHCSR)
        if dhcsr & (C_STEP | C_HALT):
            return TARGET_HALTED
        return TARGET_RUNNING

    def resume(self):
        """
        resume the execution
        """
        if self.getState() != TARGET_HALTED:
            logging.debug('cannot resume: target not halted')
            return
        self.maybeSkipBreakpoint()
        self.writeMemory(DHCSR, DBGKEY | C_DEBUGEN)
        return

    def maybeSkipBreakpoint(self):
        pc = self.readCoreRegister('pc')
        bp = self.findBreakpoint(pc)
        if bp is not None:
            logging.debug('skip/resume breakpoint: pc 0x%X', pc)
            self.removeBreakpoint(pc)
            self.writeMemory(DHCSR, DBGKEY | C_DEBUGEN | C_STEP)
            self.setBreakpoint(pc)
            logging.debug('step over breakpoint: now pc0x%X', self.readCoreRegister('pc'))
            return bp
        return None

    def findBreakpoint(self, addr):
        for bp in self.breakpoints:
            if bp.enabled and bp.addr == addr:
                return bp
        return None

    def readCoreRegister(self, reg):
        """
        read a core register (r0 .. r16).
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        if isinstance(reg, str):
            try:
                reg = CORE_REGISTER[reg.lower()]
            except KeyError:
                logging.error('cannot find %s core register', reg)
                return

        if (reg < 0) and (reg >= -4):
            specialReg = reg
            reg = CORE_REGISTER['cfbp']
        else:
            specialReg = 0

        if reg not in CORE_REGISTER.values():
            logging.error("unknown reg: %d", reg)
            return
        elif ((reg >= 128) or (reg == 33)) and (not self.has_fpu):
            logging.error("attempt to read FPU register without FPU")
            return

        # write id in DCRSR
        self.writeMemory(DCRSR, reg)

        # Technically, we need to poll S_REGRDY in DHCSR here before reading DCRDR. But
        # we're running so slow compared to the target that it's not necessary.

        # read DCRDR
        val = self.readMemory(DCRDR)

        # Special handling for registers that are combined into a single DCRSR number.
        if specialReg:
            val = (val >> ((-specialReg - 1) * 4)) & 0xff
        # Convert int to float.
        elif reg >= 128:
            val = int2float(val)

        return val


    def writeCoreRegister(self, reg, data):
        """
        write a core register (r0 .. r16)
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        if isinstance(reg, str):
            try:
                reg = CORE_REGISTER[reg.lower()]
            except KeyError:
                logging.error('cannot find %s core register', reg)
                return

        if (reg < 0) and (reg >= -4):
            specialReg = reg
            reg = CORE_REGISTER['cfbp']

            # Mask in the new special register value so we don't modify the other register
            # values that share the same DCRSR number.
            specialRegValue = self.readCoreRegister(reg)
            shift = (-specialReg - 1) * 4
            mask = 0xffffffff ^ (0xff << shift)
            data = (specialRegValue & mask) | ((data & 0xff) << shift)
        else:
            specialReg = 0

        if reg not in CORE_REGISTER.values():
            logging.error("unknown reg: %d", reg)
            return
        elif ((reg >= 128) or (reg == 33)) and (not self.has_fpu):
            logging.error("attempt to read FPU register without FPU")
            return

        # Convert float to int.
        if reg >= 128:
            data = float2int(data)

        # write id in DCRSR
        self.writeMemory(DCRDR, data)

        # write DCRDR
        self.writeMemory(DCRSR, reg | REGWnR)


    def setBreakpoint(self, addr):
        """
        set a hardware breakpoint at a specific location in flash
        """
        if self.fpb_enabled is False:
            self.enableFPB()

        if self.availableBreakpoint() == 0:
            logging.error('No more available breakpoint!!, dropped bp at 0x%X', addr)
            return False

        for bp in self.breakpoints:
            if not bp.enabled:
                bp.enabled = True
                bp_match = (1 << 30)
                if addr & 0x2:
                    bp_match = (2 << 30)
                self.writeMemory(bp.comp_register_addr, addr & 0x1ffffffc | bp_match | 1)
                bp.addr = addr
                self.num_breakpoint_used += 1
                return True
        return False


    def availableBreakpoint(self):
        return len(self.breakpoints) - self.num_breakpoint_used

    def enableFPB(self):
        self.writeMemory(FP_CTRL, FP_CTRL_KEY | 1)
        self.fpb_enabled = True
        logging.debug('fpb has been enabled')
        return

    def disableFPB(self):
        self.writeMemory(FP_CTRL, FP_CTRL_KEY | 0)
        self.fpb_enabled = False
        logging.debug('fpb has been disabled')
        return

    def removeBreakpoint(self, addr):
        """
        remove a hardware breakpoint at a specific location in flash
        """
        for bp in self.breakpoints:
            if bp.enabled and bp.addr == addr:
                bp.enabled = False
                self.writeMemory(bp.comp_register_addr, 0)
                bp.addr = addr
                self.num_breakpoint_used -= 1
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
                self.writeMemory(watch.comp_register_addr + DWT_MASK_OFFSET, mask)
                if self.readMemory(watch.comp_register_addr + DWT_MASK_OFFSET) != mask:
                    logging.error('Watchpoint of size %d not supported by device', size)
                    return False

                self.writeMemory(watch.comp_register_addr, addr)
                self.writeMemory(watch.comp_register_addr + DWT_FUNCTION_OFFSET, watch.func)
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
        self.writeMemory(watch.comp_register_addr + DWT_FUNCTION_OFFSET, 0)
        self.watchpoint_used -= 1
        return

    # GDB functions
    def getTargetXML(self):
        return self.targetXML, len(self.targetXML)


    def getRegisterName(self, compare_val):
        for key in CORE_REGISTER:
            if (compare_val == CORE_REGISTER[key]):
                return key
