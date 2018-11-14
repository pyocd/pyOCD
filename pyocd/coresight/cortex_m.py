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

from ..core.target import Target
from ..core import exceptions
from ..utility import conversion
from ..utility.notification import Notification
from .component import CoreSightComponent
from .fpb import FPB
from .dwt import DWT
from ..debug.breakpoints.manager import BreakpointManager
from ..debug.breakpoints.software import SoftwareBreakpointProvider
import logging
from time import (time, sleep)
from xml.etree.ElementTree import (Element, SubElement, tostring)

# pylint: disable=invalid_name

# CPUID PARTNO values
ARM_CortexM0 = 0xC20
ARM_CortexM1 = 0xC21
ARM_CortexM3 = 0xC23
ARM_CortexM4 = 0xC24
ARM_CortexM0p = 0xC60

# pylint: enable=invalid_name

# User-friendly names for core types.
CORE_TYPE_NAME = {
                 ARM_CortexM0 : "Cortex-M0",
                 ARM_CortexM1 : "Cortex-M1",
                 ARM_CortexM3 : "Cortex-M3",
                 ARM_CortexM4 : "Cortex-M4",
                 ARM_CortexM0p : "Cortex-M0+"
               }

# Map from register name to DCRSR register index.
#
# The CONTROL, FAULTMASK, BASEPRI, and PRIMASK registers are special in that they share the
# same DCRSR register index and are returned as a single value. In this dict, these registers
# have negative values to signal to the register read/write functions that special handling
# is necessary. The values are the byte number containing the register value, plus 1 and then
# negated. So -1 means a mask of 0xff, -2 is 0xff00, and so on. The actual DCRSR register index
# for these combined registers has the key of 'cfbp'.
#
# XPSR is always read in its entirety via the debug interface, but we also provide
# aliases for the submasks APSR, IPSR and EPSR. These are encoded as 0x10000 plus 3 lower bits
# indicating which parts of the PSR we're interested in - encoded the same way as MRS's SYSm.
# (Note that 'XPSR' continues to denote the raw 32 bits of the register, as per previous versions,
# not the union of the three APSR+IPSR+EPSR masks which don't cover the entire register).
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
                 'apsr': 0x10000,
                 'iapsr': 0x10001,
                 'eapsr': 0x10002,
                 'ipsr': 0x10005,
                 'epsr': 0x10006,
                 'iepsr': 0x10007,
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

def register_name_to_index(reg):
    if isinstance(reg, str):
        try:
            reg = CORE_REGISTER[reg.lower()]
        except KeyError:
            raise KeyError('cannot find %s core register' % reg)
    return reg

# Returns true for registers holding single-precision float values
def is_float_register(index):
    return 0x40 <= index <= 0x5f

def is_fpu_register(index):
    return index == 33 or is_float_register(index)

def is_cfbp_subregister(index):
    return -4 <= index <= -1

def is_psr_subregister(index):
    return 0x10000 <= index <= 0x10007

# Generate a PSR mask based on bottom 3 bits of a MRS SYSm value
def sysm_to_psr_mask(sysm):
    mask = 0
    if (sysm & 1) != 0:
        mask |= CortexM.IPSR_MASK
    if (sysm & 2) != 0:
        mask |= CortexM.EPSR_MASK
    if (sysm & 4) == 0:
        mask |= CortexM.APSR_MASK
    return mask

class CortexM(Target, CoreSightComponent):

    """
    This class has basic functions to access a Cortex M core:
       - init
       - read/write memory
       - read/write core registers
       - set/remove hardware breakpoints
    """

    # Program Status Register
    APSR_MASK = 0xF80F0000
    EPSR_MASK = 0x0700FC00
    IPSR_MASK = 0x000001FF

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
    DEMCR_VC_INTERR = (1 << 9)
    DEMCR_VC_BUSERR = (1 << 8)
    DEMCR_VC_STATERR = (1 << 7)
    DEMCR_VC_CHKERR = (1 << 6)
    DEMCR_VC_NOCPERR = (1 << 5)
    DEMCR_VC_MMERR = (1 << 4)
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
    S_RETIRE_ST = (1 << 24)
    S_RESET_ST = (1 << 25)

    # Debug Core Register Data Register
    DCRDR = 0xE000EDF8

    # Coprocessor Access Control Register
    CPACR = 0xE000ED88
    CPACR_CP10_CP11_MASK = (3 << 20) | (3 << 22)

    NVIC_AIRCR = (0xE000ED0C)
    NVIC_AIRCR_VECTKEY = (0x5FA << 16)
    NVIC_AIRCR_VECTRESET = (1 << 0)
    NVIC_AIRCR_SYSRESETREQ = (1 << 2)

    DBGKEY = (0xA05F << 16)

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

    @classmethod
    def factory(cls, ap, cmpid, address):
        # Create a new core instance.
        root = ap.dp.target
        core = cls(root, ap, root.memory_map, root._new_core_num, cmpid, address)
        
        # Associate this core with the AP.
        if ap.core is not None:
            raise RuntimeError("AP#%d has multiple cores associated with it" % ap.ap_num)
        ap.core = core
        
        # Add the new core to the root target.
        root.add_core(core)
        
        root._new_core_num += 1
        
        return core

    def __init__(self, rootTarget, ap, memoryMap=None, core_num=0, cmpid=None, address=None):
        Target.__init__(self, rootTarget.session, memoryMap)
        CoreSightComponent.__init__(self, ap, cmpid, address)

        self.root_target = rootTarget
        self.arch = 0
        self.core_type = 0
        self.has_fpu = False
        self.core_number = core_num
        self._run_token = 0
        self._target_context = None
        self._elf = None
        self.target_xml = None

        # Set up breakpoints manager.
        self.sw_bp = SoftwareBreakpointProvider(self)
        self.bp_manager = BreakpointManager(self)
        self.bp_manager.add_provider(self.sw_bp, Target.BREAKPOINT_SW)

    ## @brief Connect related CoreSight components.
    def connect(self, cmp):
        if isinstance(cmp, FPB):
            self.fpb = cmp
            self.bp_manager.add_provider(cmp, Target.BREAKPOINT_HW)
        elif isinstance(cmp, DWT):
            self.dwt = cmp

    @property
    def elf(self):
        return self._elf

    @elf.setter
    def elf(self, elffile):
        self._elf = elffile

    def init(self):
        """
        Cortex M initialization. The bus must be accessible when this method is called.
        """
        if self.halt_on_connect:
            self.halt()
        self._read_core_type()
        self._check_for_fpu()
        self.build_target_xml()
        self.sw_bp.init()

    def disconnect(self, resume=True):
        # Remove breakpoints.
        self.bp_manager.remove_all_breakpoints()

        # Disable other debug blocks.
        self.write32(CortexM.DEMCR, 0)

        # Disable core debug.
        if resume:
            self.resume()
            self.write32(CortexM.DHCSR, CortexM.DBGKEY | 0x0000)

    def build_target_xml(self):
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
        self.target_xml = b'<?xml version="1.0"?><!DOCTYPE feature SYSTEM "gdb-target.dtd">' + tostring(xml_root)

    ## @brief Read the CPUID register and determine core type.
    def _read_core_type(self):
        # Read CPUID register
        cpuid = self.read32(CortexM.CPUID)

        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        if implementer != CortexM.CPUID_IMPLEMENTER_ARM:
            logging.warning("CPU implementer is not ARM!")

        self.arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        
        self.cpu_revision = (cpuid & CortexM.CPUID_VARIANT_MASK) >> CortexM.CPUID_VARIANT_POS
        self.cpu_patch = (cpuid & CortexM.CPUID_REVISION_MASK) >> CortexM.CPUID_REVISION_POS
        
        if self.core_type in CORE_TYPE_NAME:
            logging.info("CPU core is %s r%dp%d", CORE_TYPE_NAME[self.core_type], self.cpu_revision, self.cpu_patch)
        else:
            logging.info("CPU core is unknown")

    ## @brief Determine if a Cortex-M4 has an FPU.
    #
    # The core type must have been identified prior to calling this function.
    def _check_for_fpu(self):
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

    def write_memory(self, addr, value, transfer_size=32):
        """
        write a memory location.
        By default the transfer size is a word
        """
        self.ap.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        """
        read a memory location. By default, a word will
        be read
        """
        result = self.ap.read_memory(addr, transfer_size, now)

        # Read callback returned for async reads.
        def read_memory_cb():
            return self.bp_manager.filter_memory(addr, transfer_size, result())

        if now:
            return self.bp_manager.filter_memory(addr, transfer_size, result)
        else:
            return read_memory_cb

    def read_memory_block8(self, addr, size):
        """
        read a block of unaligned bytes in memory. Returns
        an array of byte values
        """
        data = self.ap.read_memory_block8(addr, size)
        return self.bp_manager.filter_memory_unaligned_8(addr, size, data)

    def write_memory_block8(self, addr, data):
        """
        write a block of unaligned bytes in memory.
        """
        self.ap.write_memory_block8(addr, data)

    def write_memory_block32(self, addr, data):
        """
        write a block of aligned words in memory.
        """
        self.ap.write_memory_block32(addr, data)

    def read_memory_block32(self, addr, size):
        """
        read a block of aligned words in memory. Returns
        an array of word values
        """
        data = self.ap.read_memory_block32(addr, size)
        return self.bp_manager.filter_memory_aligned_32(addr, size, data)

    def halt(self):
        """
        halt the core
        """
        self.notify(Notification(event=Target.EVENT_PRE_HALT, source=self, data=Target.HALT_REASON_USER))
        self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)
        self.flush()
        self.notify(Notification(event=Target.EVENT_POST_HALT, source=self, data=Target.HALT_REASON_USER))

    def step(self, disable_interrupts=True):
        """
        perform an instruction level step.  This function preserves the previous
        interrupt mask state
        """
        # Was 'if self.get_state() != TARGET_HALTED:'
        # but now value of dhcsr is saved
        dhcsr = self.read_memory(CortexM.DHCSR)
        if not (dhcsr & (CortexM.C_STEP | CortexM.C_HALT)):
            logging.error('cannot step: target not halted')
            return

        self.notify(Notification(event=Target.EVENT_PRE_RUN, source=self, data=Target.RUN_TYPE_STEP))

        self.clear_debug_cause_bits()

        # Save previous interrupt mask state
        interrupts_masked = (CortexM.C_MASKINTS & dhcsr) != 0

        # Mask interrupts - C_HALT must be set when changing to C_MASKINTS
        if not interrupts_masked and disable_interrupts:
            self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT | CortexM.C_MASKINTS)

        # Single step using current C_MASKINTS setting
        if disable_interrupts or interrupts_masked:
            self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_MASKINTS | CortexM.C_STEP)
        else:
            self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_STEP)

        # Wait for halt to auto set (This should be done before the first read)
        while not self.read_memory(CortexM.DHCSR) & CortexM.C_HALT:
            pass

        # Restore interrupt mask state
        if not interrupts_masked and disable_interrupts:
            # Unmask interrupts - C_HALT must be set when changing to C_MASKINTS
            self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)

        self.flush()

        self._run_token += 1

        self.notify(Notification(event=Target.EVENT_POST_RUN, source=self, data=Target.RUN_TYPE_STEP))

    def clear_debug_cause_bits(self):
        self.write_memory(CortexM.DFSR, CortexM.DFSR_DWTTRAP | CortexM.DFSR_BKPT | CortexM.DFSR_HALTED)

    def reset(self, software_reset=None):
        """
        reset a core. After a call to this function, the core
        is running
        """
        self.notify(Notification(event=Target.EVENT_PRE_RESET, source=self))

        if software_reset == None:
            # Default to software reset if nothing is specified
            software_reset = True

        self._run_token += 1

        if software_reset:
            # Perform the reset.
            try:
                self.write_memory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | CortexM.NVIC_AIRCR_SYSRESETREQ)
                # Without a flush a transfer error can occur
                self.flush()
            except exceptions.TransferError:
                self.flush()

        else:
            self.session.probe.reset()

        # Now wait for the system to come out of reset. Keep reading the DHCSR until
        # we get a good response with S_RESET_ST cleared, or we time out.
        startTime = time()
        while time() - startTime < 2.0:
            try:
                dhcsr = self.read32(CortexM.DHCSR)
                if (dhcsr & CortexM.S_RESET_ST) == 0:
                    break
            except exceptions.TransferError:
                self.flush()
                sleep(0.01)

        self.notify(Notification(event=Target.EVENT_POST_RESET, source=self))

    def reset_stop_on_reset(self, software_reset=None):
        """
        perform a reset and stop the core on the reset handler
        """
        logging.debug("reset stop on Reset")

        # halt the target
        self.halt()

        # Save CortexM.DEMCR
        demcr = self.read_memory(CortexM.DEMCR)

        # enable the vector catch
        self.write_memory(CortexM.DEMCR, demcr | CortexM.DEMCR_VC_CORERESET)

        self.reset(software_reset)

        # wait until the unit resets
        while (self.is_running()):
            pass

        # restore vector catch setting
        self.write_memory(CortexM.DEMCR, demcr)

    def set_target_state(self, state):
        if state == "PROGRAM":
            self.reset_stop_on_reset(True)
            # Write the thumb bit in case the reset handler
            # points to an ARM address
            self.write_core_register('xpsr', 0x1000000)

    def get_state(self):
        dhcsr = self.read_memory(CortexM.DHCSR)
        if dhcsr & CortexM.S_RESET_ST:
            # Reset is a special case because the bit is sticky and really means
            # "core was reset since last read of DHCSR". We have to re-read the
            # DHCSR, check if S_RESET_ST is still set and make sure no instructions
            # were executed by checking S_RETIRE_ST.
            newDhcsr = self.read_memory(CortexM.DHCSR)
            if (newDhcsr & CortexM.S_RESET_ST) and not (newDhcsr & CortexM.S_RETIRE_ST):
                return Target.TARGET_RESET
        if dhcsr & CortexM.S_LOCKUP:
            return Target.TARGET_LOCKUP
        elif dhcsr & CortexM.S_SLEEP:
            return Target.TARGET_SLEEPING
        elif dhcsr & CortexM.S_HALT:
            return Target.TARGET_HALTED
        else:
            return Target.TARGET_RUNNING

    @property
    def run_token(self):
        return self._run_token

    def is_running(self):
        return self.get_state() == Target.TARGET_RUNNING

    def is_halted(self):
        return self.get_state() == Target.TARGET_HALTED

    def resume(self):
        """
        resume the execution
        """
        if self.get_state() != Target.TARGET_HALTED:
            logging.debug('cannot resume: target not halted')
            return
        self.notify(Notification(event=Target.EVENT_PRE_RUN, source=self, data=Target.RUN_TYPE_RESUME))
        self._run_token += 1
        self.clear_debug_cause_bits()
        self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)
        self.flush()
        self.notify(Notification(event=Target.EVENT_POST_RUN, source=self, data=Target.RUN_TYPE_RESUME))

    def find_breakpoint(self, addr):
        return self.bp_manager.find_breakpoint(addr)

    def read_core_register(self, reg):
        """
        read CPU register
        Unpack floating point register values
        """
        regIndex = register_name_to_index(reg)
        regValue = self.read_core_register(regIndex)
        # Convert int to float.
        if is_float_register(regIndex):
            regValue = conversion.u32_to_float32(regValue)
        return regValue

    def read_core_register(self, reg):
        """
        read a core register (r0 .. r16).
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        vals = self.read_core_registers_raw([reg])
        return vals[0]

    def read_core_registers_raw(self, reg_list):
        """
        Read one or more core registers

        Read core registers in reg_list and return a list of values.
        If any register in reg_list is a string, find the number
        associated to this register in the lookup table CORE_REGISTER.
        """
        # convert to index only
        reg_list = [register_name_to_index(reg) for reg in reg_list]

        # Sanity check register values
        for reg in reg_list:
            if reg not in CORE_REGISTER.values():
                raise ValueError("unknown reg: %d" % reg)
            elif is_fpu_register(reg) and (not self.has_fpu):
                raise ValueError("attempt to read FPU register without FPU")

        # Begin all reads and writes
        dhcsr_cb_list = []
        reg_cb_list = []
        for reg in reg_list:
            if is_cfbp_subregister(reg):
                reg = CORE_REGISTER['cfbp']

            if is_psr_subregister(reg):
                reg = CORE_REGISTER['xpsr']

            # write id in DCRSR
            self.write_memory(CortexM.DCRSR, reg)

            # Technically, we need to poll S_REGRDY in DHCSR here before reading DCRDR. But
            # we're running so slow compared to the target that it's not necessary.
            # Read it and assert that S_REGRDY is set

            dhcsr_cb = self.read_memory(CortexM.DHCSR, now=False)
            reg_cb = self.read_memory(CortexM.DCRDR, now=False)
            dhcsr_cb_list.append(dhcsr_cb)
            reg_cb_list.append(reg_cb)

        # Read all results
        reg_vals = []
        for reg, reg_cb, dhcsr_cb in zip(reg_list, reg_cb_list, dhcsr_cb_list):
            dhcsr_val = dhcsr_cb()
            assert dhcsr_val & CortexM.S_REGRDY
            val = reg_cb()

            # Special handling for registers that are combined into a single DCRSR number.
            if is_cfbp_subregister(reg):
                val = (val >> ((-reg - 1) * 8)) & 0xff

            if is_psr_subregister(reg):
                val &= sysm_to_psr_mask(reg)

            reg_vals.append(val)

        return reg_vals

    def write_core_register(self, reg, data):
        """
        write a CPU register.
        Will need to pack floating point register values before writing.
        """
        regIndex = register_name_to_index(reg)
        # Convert float to int.
        if is_float_register(regIndex):
            data = conversion.float32_to_u32(data)
        self.write_core_register(regIndex, data)

    def write_core_register(self, reg, data):
        """
        write a core register (r0 .. r16)
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        self.write_core_registers_raw([reg], [data])

    def write_core_registers_raw(self, reg_list, data_list):
        """
        Write one or more core registers

        Write core registers in reg_list with the associated value in
        data_list.  If any register in reg_list is a string, find the number
        associated to this register in the lookup table CORE_REGISTER.
        """
        assert len(reg_list) == len(data_list)
        # convert to index only
        reg_list = [register_name_to_index(reg) for reg in reg_list]

        # Sanity check register values
        for reg in reg_list:
            if reg not in CORE_REGISTER.values():
                raise ValueError("unknown reg: %d" % reg)
            elif is_fpu_register(reg) and (not self.has_fpu):
                raise ValueError("attempt to write FPU register without FPU")

        # Read special register if it is present in the list
        for reg in reg_list:
            if is_cfbp_subregister(reg):
                cfbpValue = self.read_core_register(CORE_REGISTER['cfbp'])
                break

            if is_psr_subregister(reg):
                xpsrValue = self.read_core_register(CORE_REGISTER['xpsr'])
                break

        # Write out registers
        dhcsr_cb_list = []
        for reg, data in zip(reg_list, data_list):
            if is_cfbp_subregister(reg):
                # Mask in the new special register value so we don't modify the other register
                # values that share the same DCRSR number.
                shift = (-reg - 1) * 8
                mask = 0xffffffff ^ (0xff << shift)
                data = (cfbpValue & mask) | ((data & 0xff) << shift)
                cfbpValue = data # update special register for other writes that might be in the list
                reg = CORE_REGISTER['cfbp']

            if is_psr_subregister(reg):
                mask = sysm_to_psr_mask(reg)
                data = (xpsrValue & (0xffffffff ^ mask)) | (data & mask)
                xpsrValue = data
                reg = CORE_REGISTER['xpsr']

            # write DCRDR
            self.write_memory(CortexM.DCRDR, data)

            # write id in DCRSR and flag to start write transfer
            self.write_memory(CortexM.DCRSR, reg | CortexM.DCRSR_REGWnR)

            # Technically, we need to poll S_REGRDY in DHCSR here to ensure the
            # register write has completed.
            # Read it and assert that S_REGRDY is set
            dhcsr_cb = self.read_memory(CortexM.DHCSR, now=False)
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
    def set_breakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        return self.bp_manager.set_breakpoint(addr, type)

    ## @brief Remove a breakpoint at a specific location.
    def remove_breakpoint(self, addr):
        self.bp_manager.remove_breakpoint(addr)

    def get_breakpoint_type(self, addr):
        return self.bp_manager.get_breakpoint_type(addr)

    @property
    def available_breakpoint_count(self):
        return self.fpb.available_breakpoints()

    def find_watchpoint(self, addr, size, type):
        return self.dwt.find_watchpoint(addr, size, type)

    def set_watchpoint(self, addr, size, type):
        """
        set a hardware watchpoint
        """
        return self.dwt.set_watchpoint(addr, size, type)

    def remove_watchpoint(self, addr, size, type):
        """
        remove a hardware watchpoint
        """
        return self.dwt.remove_watchpoint(addr, size, type)

    @staticmethod
    def _map_to_vector_catch_mask(mask):
        result = 0
        if mask & Target.CATCH_HARD_FAULT:
            result |= CortexM.DEMCR_VC_HARDERR
        if mask & Target.CATCH_BUS_FAULT:
            result |= CortexM.DEMCR_VC_BUSERR
        if mask & Target.CATCH_MEM_FAULT:
            result |= CortexM.DEMCR_VC_MMERR
        if mask & Target.CATCH_INTERRUPT_ERR:
            result |= CortexM.DEMCR_VC_INTERR
        if mask & Target.CATCH_STATE_ERR:
            result |= CortexM.DEMCR_VC_STATERR
        if mask & Target.CATCH_CHECK_ERR:
            result |= CortexM.DEMCR_VC_CHKERR
        if mask & Target.CATCH_COPROCESSOR_ERR:
            result |= CortexM.DEMCR_VC_NOCPERR
        if mask & Target.CATCH_CORE_RESET:
            result |= CortexM.DEMCR_VC_CORERESET
        return result

    @staticmethod
    def _map_from_vector_catch_mask(mask):
        result = 0
        if mask & CortexM.DEMCR_VC_HARDERR:
            result |= Target.CATCH_HARD_FAULT
        if mask & CortexM.DEMCR_VC_BUSERR:
            result |= Target.CATCH_BUS_FAULT
        if mask & CortexM.DEMCR_VC_MMERR:
            result |= Target.CATCH_MEM_FAULT
        if mask & CortexM.DEMCR_VC_INTERR:
            result |= Target.CATCH_INTERRUPT_ERR
        if mask & CortexM.DEMCR_VC_STATERR:
            result |= Target.CATCH_STATE_ERR
        if mask & CortexM.DEMCR_VC_CHKERR:
            result |= Target.CATCH_CHECK_ERR
        if mask & CortexM.DEMCR_VC_NOCPERR:
            result |= Target.CATCH_COPROCESSOR_ERR
        if mask & CortexM.DEMCR_VC_CORERESET:
            result |= Target.CATCH_CORE_RESET
        return result

    def set_vector_catch(self, enableMask):
        demcr = self.read_memory(CortexM.DEMCR)
        demcr |= CortexM._map_to_vector_catch_mask(enableMask)
        demcr &= ~CortexM._map_to_vector_catch_mask(~enableMask)
        self.write_memory(CortexM.DEMCR, demcr)

    def get_vector_catch(self):
        demcr = self.read_memory(CortexM.DEMCR)
        return CortexM._map_from_vector_catch_mask(demcr)

    # GDB functions
    def get_target_xml(self):
        return self.target_xml

    def is_debug_trap(self):
        debugEvents = self.read_memory(CortexM.DFSR) & (CortexM.DFSR_DWTTRAP | CortexM.DFSR_BKPT | CortexM.DFSR_HALTED)
        return debugEvents != 0

    def get_target_context(self, core=None):
        return self._target_context

    def set_target_context(self, context):
        self._target_context = context

    # Names for built-in Exception numbers found in IPSR
    CORE_EXCEPTION = [
           "Thread",
           "Reset",
           "NMI",
           "HardFault",
           "MemManage",
           "BusFault",
           "UsageFault",
           "SecureFault",
           "Exception 8",
           "Exception 9",
           "Exception 10",
           "SVCall",
           "DebugMonitor",
           "Exception 13",
           "PendSV",
           "SysTick",
    ]

    def exception_number_to_name(self, exc_num, name_thread=False):
        if exc_num < len(self.CORE_EXCEPTION):
            if exc_num == 0 and not name_thread:
                return None
            else:
                return self.CORE_EXCEPTION[exc_num]
        else:
            irq_num = exc_num - len(self.CORE_EXCEPTION)
            name = None
            if self.root_target.irq_table:
                name = self.root_target.irq_table.get(irq_num)
            if name is not None:
                return "Interrupt[%s]" % name
            else:
                return "Interrupt %d" % irq_num
