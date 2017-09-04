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

from ..core.target import Target
from pyOCD.pyDAPAccess import DAPAccess
from ..utility import conversion
from .fpb import FPB
from .dwt import DWT
from ..debug.breakpoints.manager import BreakpointManager
from ..debug.breakpoints.software import SoftwareBreakpointProvider
from . import (dap, ap)
import logging
import struct
from time import (time, sleep)

# CPUID PARTNO values
ARM_CortexA7 = 0xC07
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
                 ARM_CortexM0p : "Cortex-M0+",
                 ARM_CortexA7 : "Cortex-A7"
               }

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

class CortexTarget(Target):

    """
    This class has basic functions to access a Cortex M core:
       - init
       - read/write memory
       - read/write core registers
       - set/remove hardware breakpoints
    """

    DEBUG_BASE = 0xE000E000

    # CPUID Register
    CPUID = 0xD00

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
        RegisterInfo('s31',     32,         'float',        'float'),
        ]

    def __init__(self, link, dp, ap, memoryMap=None, core_num=0):
        super(CortexTarget, self).__init__(link, memoryMap)

        self.arch = 0
        self.core_type = 0
        self.has_fpu = False
        self.dp = dp
        self.ap = ap
        self.core_number = core_num
        self._run_token = 0
        self._target_context = None

        # Set up breakpoints manager.
        self.fpb = FPB(self.ap)
        self.dwt = DWT(self.ap)
        self.sw_bp = SoftwareBreakpointProvider(self)
        self.bp_manager = BreakpointManager(self)
        self.bp_manager.add_provider(self.fpb, Target.BREAKPOINT_HW)
        self.bp_manager.add_provider(self.sw_bp, Target.BREAKPOINT_SW)

    def init(self):
        """
        Cortex M initialization. The bus must be accessible when this method is called.
        """
        # if self.halt_on_connect:
        # self.halt()
        self.readCoreType()
        self.checkForFPU()
        self.buildTargetXML()
        self.fpb.init()
        self.dwt.init()
        self.sw_bp.init()

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
        self.targetXML = b'<?xml version="1.0"?><!DOCTYPE feature SYSTEM "gdb-target.dtd">' + tostring(xml_root)

    ## @brief Read the CPUID register and determine core type.
    def readCoreType(self):
        # Read CPUID register
        cpuid = self.readMemory(self.DEBUG_BASE + CortexTarget.CPUID)

        implementer = (cpuid & CortexTarget.CPUID_IMPLEMENTER_MASK) >> CortexTarget.CPUID_IMPLEMENTER_POS
        if implementer != CortexTarget.CPUID_IMPLEMENTER_ARM:
            logging.warning("CPU implementer is not ARM!")

        self.arch = (cpuid & CortexTarget.CPUID_ARCHITECTURE_MASK) >> CortexTarget.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexTarget.CPUID_PARTNO_MASK) >> CortexTarget.CPUID_PARTNO_POS
        logging.info("CPU core is %s" % CORE_TYPE_NAME[self.core_type])

    def readIDCode(self):
        """
        return the IDCODE of the core
        """
        return self.dp.read_id_code()

    def flush(self):
        self.dp.flush()

    def writeMemory(self, addr, value, transfer_size=32):
        """
        write a memory location.
        By default the transfer size is a word
        """
        self.ap.writeMemory(addr, value, transfer_size)

    def readMemory(self, addr, transfer_size=32, now=True):
        """
        read a memory location. By default, a word will
        be read
        """
        result = self.ap.readMemory(addr, transfer_size, now)

        # Read callback returned for async reads.
        def readMemoryCb():
            return self.bp_manager.filter_memory(addr, transfer_size, result())

        if now:
            return self.bp_manager.filter_memory(addr, transfer_size, result)
        else:
            return readMemoryCb

    def readBlockMemoryUnaligned8(self, addr, size):
        """
        read a block of unaligned bytes in memory. Returns
        an array of byte values
        """
        data = self.ap.readBlockMemoryUnaligned8(addr, size)
        return self.bp_manager.filter_memory_unaligned_8(addr, size, data)

    def writeBlockMemoryUnaligned8(self, addr, data):
        """
        write a block of unaligned bytes in memory.
        """
        self.ap.writeBlockMemoryUnaligned8(addr, data)

    def writeBlockMemoryAligned32(self, addr, data):
        """
        write a block of aligned words in memory.
        """
        self.ap.writeBlockMemoryAligned32(addr, data)

    def readBlockMemoryAligned32(self, addr, size):
        """
        read a block of aligned words in memory. Returns
        an array of word values
        """
        data = self.ap.readBlockMemoryAligned32(addr, size)
        return self.bp_manager.filter_memory_aligned_32(addr, size, data)

    @property
    def run_token(self):
        return self._run_token

    def isRunning(self):
        return self.getState() == Target.TARGET_RUNNING

    def isHalted(self):
        return self.getState() == Target.TARGET_HALTED

    def resume(self):
        """
        resume the execution
        """
        if self.getState() != Target.TARGET_HALTED:
            logging.debug('cannot resume: target not halted')
            return
        self._run_token += 1
        self.clearDebugCauseBits()
        self.writeMemory(CortexTarget.DHCSR, CortexTarget.DBGKEY | CortexTarget.C_DEBUGEN)
        self.dp.flush()

    def findBreakpoint(self, addr):
        return self.bp_manager.find_breakpoint(addr)

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

    ## @brief Set a hardware or software breakpoint at a specific location in memory.
    #
    # @retval True Breakpoint was set.
    # @retval False Breakpoint could not be set.
    def setBreakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        return self.bp_manager.set_breakpoint(addr, type)

    ## @brief Remove a breakpoint at a specific location.
    def removeBreakpoint(self, addr):
        self.bp_manager.remove_breakpoint(addr)

    def getBreakpointType(self, addr):
        return self.bp_manager.get_breakpoint_type(addr)

    def availableBreakpoint(self):
        return self.fpb.available_breakpoints()

    def findWatchpoint(self, addr, size, type):
        return self.dwt.find_watchpoint(addr, size, type)

    def setWatchpoint(self, addr, size, type):
        """
        set a hardware watchpoint
        """
        return self.dwt.set_watchpoint(addr, size, type)

    def removeWatchpoint(self, addr, size, type):
        """
        remove a hardware watchpoint
        """
        return self.dwt.remove_watchpoint(addr, size, type)

    # GDB functions
    def getTargetXML(self):
        return self.targetXML

    def getTargetContext(self, core=None):
        return self._target_context

    def setTargetContext(self, context):
        self._target_context = context
