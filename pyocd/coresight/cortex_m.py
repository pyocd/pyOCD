# pyOCD debugger
# Copyright (c) 2006-2019 Arm Limited
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ..core.target import Target
from ..core import exceptions
from ..utility import (cmdline, conversion, timeout)
from ..utility.notification import Notification
from .component import CoreSightCoreComponent
from .fpb import FPB
from .dwt import DWT
from ..debug.breakpoints.manager import BreakpointManager
from ..debug.breakpoints.software import SoftwareBreakpointProvider
import logging
from time import (time, sleep)
from xml.etree.ElementTree import (Element, SubElement, tostring)

LOG = logging.getLogger(__name__)

# pylint: disable=invalid_name

# CPUID PARTNO values
ARM_CortexM0 = 0xC20
ARM_CortexM1 = 0xC21
ARM_CortexM3 = 0xC23
ARM_CortexM4 = 0xC24
ARM_CortexM7 = 0xC27
ARM_CortexM0p = 0xC60

# pylint: enable=invalid_name

## @brief User-friendly names for core types.
CORE_TYPE_NAME = {
                 ARM_CortexM0 : "Cortex-M0",
                 ARM_CortexM1 : "Cortex-M1",
                 ARM_CortexM3 : "Cortex-M3",
                 ARM_CortexM4 : "Cortex-M4",
                 ARM_CortexM7 : "Cortex-M7",
                 ARM_CortexM0p : "Cortex-M0+",
               }

## @brief Map from register name to DCRSR register index.
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
#
# The double-precision floating point registers (D0-D15) are composed of two single-precision
# floating point registers (S0-S31). The value for double-precision registers in this dict is
# the negated value of the first associated single-precision register.
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
                 'd0': -0x40,
                 'd1': -0x42,
                 'd2': -0x44,
                 'd3': -0x46,
                 'd4': -0x48,
                 'd5': -0x4a,
                 'd6': -0x4c,
                 'd7': -0x4e,
                 'd8': -0x50,
                 'd9': -0x52,
                 'd10': -0x54,
                 'd11': -0x56,
                 'd12': -0x58,
                 'd13': -0x5a,
                 'd14': -0x5c,
                 'd15': -0x5e,
                 }

def register_name_to_index(reg):
    if isinstance(reg, str):
        try:
            reg = CORE_REGISTER[reg.lower()]
        except KeyError:
            raise KeyError('cannot find %s core register' % reg)
    return reg

def is_float_register(index):
    return is_single_float_register(index) or is_double_float_register(index)

def is_single_float_register(index):
    """! @brief Returns true for registers holding single-precision float values"""
    return 0x40 <= index <= 0x5f

def is_double_float_register(index):
    """! Returns true for registers holding double-precision float values"""
    return -0x40 >= index > -0x60

def is_fpu_register(index):
    return index == 33 or is_single_float_register(index) or is_double_float_register(index)

def is_cfbp_subregister(index):
    return -4 <= index <= -1

def is_psr_subregister(index):
    return 0x10000 <= index <= 0x10007

def sysm_to_psr_mask(sysm):
    """! Generate a PSR mask based on bottom 3 bits of a MRS SYSm value"""
    mask = 0
    if (sysm & 1) != 0:
        mask |= CortexM.IPSR_MASK
    if (sysm & 2) != 0:
        mask |= CortexM.EPSR_MASK
    if (sysm & 4) == 0:
        mask |= CortexM.APSR_MASK
    return mask

class CortexM(Target, CoreSightCoreComponent):
    """! @brief CoreSight component for a v6-M or v7-M Cortex-M core.
    
    This class has basic functions to access a Cortex-M core:
       - init
       - read/write memory
       - read/write core registers
       - set/remove hardware breakpoints
    """

    # Program Status Register
    APSR_MASK = 0xF80F0000
    EPSR_MASK = 0x0700FC00
    IPSR_MASK = 0x000001FF
    
    # Thumb bit in XPSR.
    XPSR_THUMB = 0x01000000

    # Control Register
    CONTROL_FPCA = (1 << 2)
    CONTROL_SPSEL = (1 << 1)
    CONTROL_nPRIV = (1 << 0)

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
    ARMv6M = 0xC # also ARMv8-M without Main Extension
    ARMv7M = 0xF # also ARMv8-M with Main Extension

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
    
    # Interrupt Control and State Register
    ICSR = 0xE000ED04
    ICSR_PENDSVCLR = (1 << 27)
    ICSR_PENDSTCLR = (1 << 25)
    
    VTOR = 0xE000ED08
    SCR = 0xE000ED10
    SHPR1 = 0xE000ED18
    SHPR2 = 0xE000ED1C
    SHPR3 = 0xE000ED20
    SHCSR = 0xE000ED24
    FPCCR = 0xE000EF34
    FPCAR = 0xE000EF38
    FPDSCR = 0xE000EF3C
    ICTR = 0xE000E004

    NVIC_AIRCR = (0xE000ED0C)
    NVIC_AIRCR_VECTKEY = (0x5FA << 16)
    NVIC_AIRCR_VECTRESET = (1 << 0)
    NVIC_AIRCR_VECTCLRACTIVE = (1 << 1)
    NVIC_AIRCR_SYSRESETREQ = (1 << 2)
    NVIC_AIRCR_PRIGROUP_MASK = 0x700
    NVIC_AIRCR_PRIGROUP_SHIFT = 8
    
    NVIC_ICER0 = 0xE000E180 # NVIC Clear-Enable Register 0
    NVIC_ICPR0 = 0xE000E280 # NVIC Clear-Pending Register 0
    NVIC_IPR0 = 0xE000E400 # NVIC Interrupt Priority Register 0
    
    SYSTICK_CSR = 0xE000E010

    DBGKEY = (0xA05F << 16)

    # Media and FP Feature Register 0
    MVFR0 = 0xE000EF40
    MVFR0_DOUBLE_PRECISION_MASK = 0x00000f00
    MVFR0_DOUBLE_PRECISION_SHIFT = 8

    # Media and FP Feature Register 2
    MVFR2 = 0xE000EF48
    MVFR2_VFP_MISC_MASK = 0x000000f0
    MVFR2_VFP_MISC_SHIFT = 4

    class RegisterInfo(object):
        def __init__(self, name, bitsize, reg_type, reg_group):
            self.name = name
            self.reg_num = CORE_REGISTER[name]
            self.bitsize = bitsize
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
        RegisterInfo('msp',     32,         'data_ptr',     'system'),
        RegisterInfo('psp',     32,         'data_ptr',     'system'),
        RegisterInfo('primask', 32,         'int',          'system'),
        RegisterInfo('control', 32,         'int',          'system'),
        ]

    regs_system_armv7_only = [
        #            Name       bitsize     type            group
        RegisterInfo('basepri',     32,     'int',          'system'),
        RegisterInfo('faultmask',   32,     'int',          'system'),
        ]

    regs_float = [
        #            Name       bitsize     type            group
        RegisterInfo('fpscr',   32,         'int',          'float'),
        RegisterInfo('d0' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d1' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d2' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d3' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d4' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d5' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d6' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d7' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d8' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d9' ,     64,         'ieee_double',  'float'),
        RegisterInfo('d10',     64,         'ieee_double',  'float'),
        RegisterInfo('d11',     64,         'ieee_double',  'float'),
        RegisterInfo('d12',     64,         'ieee_double',  'float'),
        RegisterInfo('d13',     64,         'ieee_double',  'float'),
        RegisterInfo('d14',     64,         'ieee_double',  'float'),
        RegisterInfo('d15',     64,         'ieee_double',  'float'),
        ]

    @classmethod
    def factory(cls, ap, cmpid, address):
        # Create a new core instance.
        root = ap.dp.target
        core = cls(root.session, ap, root.memory_map, root._new_core_num, cmpid, address) 
        
        # Associate this core with the AP.
        if ap.core is not None:
            raise exceptions.TargetError("AP#%d has multiple cores associated with it" % ap.ap_num)
        ap.core = core
        
        # Add the new core to the root target.
        root.add_core(core)
        
        root._new_core_num += 1
        
        return core

    def __init__(self, session, ap, memoryMap=None, core_num=0, cmpid=None, address=None):
        Target.__init__(self, session, memoryMap)
        CoreSightCoreComponent.__init__(self, ap, cmpid, address)

        self.arch = 0
        self.core_type = 0
        self.has_fpu = False
        self.core_number = core_num
        self._run_token = 0
        self._target_context = None
        self._elf = None
        self.target_xml = None
        self._supports_vectreset = False
        self._reset_catch_delegate_result = False
        self._reset_catch_saved_demcr = 0
        
        # Default to software reset using the default software reset method.
        self._default_reset_type = Target.ResetType.SW
        
        # Select default sw reset type based on whether multicore debug is enabled and which core
        # this is.
        self._default_software_reset_type = Target.ResetType.SW_SYSRESETREQ \
                    if (not self.session.options.get('enable_multicore_debug')) or (self.core_number == 0) \
                    else Target.ResetType.SW_VECTRESET

        # Set up breakpoints manager.
        self.sw_bp = SoftwareBreakpointProvider(self)
        self.bp_manager = BreakpointManager(self)
        self.bp_manager.add_provider(self.sw_bp)

    def add_child(self, cmp):
        """! @brief Connect related CoreSight components."""
        super(CortexM, self).add_child(cmp)
        
        if isinstance(cmp, FPB):
            self.fpb = cmp
            self.bp_manager.add_provider(cmp)
        elif isinstance(cmp, DWT):
            self.dwt = cmp

    @property
    def elf(self):
        return self._elf

    @elf.setter
    def elf(self, elffile):
        self._elf = elffile
    
    @property
    def default_reset_type(self):
        return self._default_reset_type
    
    @default_reset_type.setter
    def default_reset_type(self, reset_type):
        assert isinstance(reset_type, Target.ResetType)
        self._default_reset_type = reset_type
    
    @property
    def default_software_reset_type(self):
        return self._default_software_reset_type
    
    @default_software_reset_type.setter
    def default_software_reset_type(self, reset_type):
        """! @brief Modify the default software reset method.
        @param self
        @param reset_type Must be one of the software reset types: Target.ResetType.SW_SYSRESETREQ,
            Target.ResetType.SW_VECTRESET, or Target.ResetType.SW_EMULATED.
        """
        assert isinstance(reset_type, Target.ResetType)
        assert reset_type in (Target.ResetType.SW_SYSRESETREQ, Target.ResetType.SW_VECTRESET,
                                Target.ResetType.SW_EMULATED)
        self._default_software_reset_type = reset_type
    
    @property
    def supported_security_states(self):
        """! @brief Tuple of security states supported by the processor.
        
        @return Tuple of @ref pyocd.core.target.Target.SecurityState "Target.SecurityState". For
            v6-M and v7-M cores, the return value only contains SecurityState.NONSECURE.
        """
        return (Target.SecurityState.NONSECURE,)

    def init(self):
        """! @brief Cortex M initialization.
        
        The bus must be accessible when this method is called.
        """
        if not self.call_delegate('will_start_debug_core', core=self):
            self._read_core_type()
            self._check_for_fpu()
            self.build_target_xml()
            self.sw_bp.init()

        self.call_delegate('did_start_debug_core', core=self)

    def disconnect(self, resume=True):
        if not self.call_delegate('will_stop_debug_core', core=self):
            # Remove breakpoints and watchpoints.
            self.bp_manager.remove_all_breakpoints()
            self.dwt.remove_all_watchpoints()

            # Disable other debug blocks.
            self.write32(CortexM.DEMCR, 0)

            # Disable core debug.
            if resume:
                self.resume()
                self.write32(CortexM.DHCSR, CortexM.DBGKEY | 0x0000)

        self.call_delegate('did_stop_debug_core', core=self)

    def build_target_xml(self):
        """! @brief Build register_list and targetXML"""
        self.register_list = []
        xml_root = Element('target')
        xml_regs_general = SubElement(xml_root, "feature", name="org.gnu.gdb.arm.m-profile")

        def append_regs(regs, xml_element):
            for reg in regs:
                self.register_list.append(reg)
                SubElement(xml_element, 'reg', **reg.gdb_xml_attrib)

        append_regs(self.regs_general, xml_regs_general)
        # Check if target has ARMv7 registers
        if self.arch == CortexM.ARMv7M:
            append_regs(self.regs_system_armv7_only, xml_regs_general)
        # Check if target has FPU registers
        if self.has_fpu:
            # GDB understands the double/single separation so we don't need
            # to separately pass the single regs, just the double
            xml_regs_fpu = SubElement(xml_root, "feature", name="org.gnu.gdb.arm.vfp")
            append_regs(self.regs_float, xml_regs_fpu)

        self.target_xml = b'<?xml version="1.0"?><!DOCTYPE feature SYSTEM "gdb-target.dtd">' + tostring(xml_root)

    def _read_core_type(self):
        """! @brief Read the CPUID register and determine core type and architecture."""
        # Read CPUID register
        cpuid = self.read32(CortexM.CPUID)

        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        if implementer != CortexM.CPUID_IMPLEMENTER_ARM:
            LOG.warning("CPU implementer is not ARM!")

        self.arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        
        self.cpu_revision = (cpuid & CortexM.CPUID_VARIANT_MASK) >> CortexM.CPUID_VARIANT_POS
        self.cpu_patch = (cpuid & CortexM.CPUID_REVISION_MASK) >> CortexM.CPUID_REVISION_POS
        
        # Only v7-M supports VECTRESET.
        if self.arch == CortexM.ARMv7M:
            self._supports_vectreset = True
        
        if self.core_type in CORE_TYPE_NAME:
            LOG.info("CPU core #%d is %s r%dp%d", self.core_number, CORE_TYPE_NAME[self.core_type], self.cpu_revision, self.cpu_patch)
        else:
            LOG.warning("CPU core #%d type is unrecognized", self.core_number)

    def _check_for_fpu(self):
        """! @brief Determine if a core has an FPU.
        
        The core architecture must have been identified prior to calling this function.
        """
        if self.arch != CortexM.ARMv7M:
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
            # Now check whether double-precision is supported.
            # (Minimal tests to distinguish current permitted ARMv7-M and
            # ARMv8-M FPU types; used for printing only).
            mvfr0 = self.read32(CortexM.MVFR0)
            dp_val = (mvfr0 & CortexM.MVFR0_DOUBLE_PRECISION_MASK) >> CortexM.MVFR0_DOUBLE_PRECISION_SHIFT

            mvfr2 = self.read32(CortexM.MVFR2)
            vfp_misc_val = (mvfr2 & CortexM.MVFR2_VFP_MISC_MASK) >> CortexM.MVFR2_VFP_MISC_SHIFT

            if dp_val >= 2:
                fpu_type = "FPv5"
            elif vfp_misc_val >= 4:
                fpu_type = "FPv5-SP"
            else:
                fpu_type = "FPv4-SP"
            LOG.info("FPU present: " + fpu_type)

    def write_memory(self, addr, value, transfer_size=32):
        """! @brief Write a single memory location.
        
        By default the transfer size is a word."""
        self.ap.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        """! @brief Read a memory location.
        
        By default, a word will be read."""
        result = self.ap.read_memory(addr, transfer_size, now)

        # Read callback returned for async reads.
        def read_memory_cb():
            return self.bp_manager.filter_memory(addr, transfer_size, result())

        if now:
            return self.bp_manager.filter_memory(addr, transfer_size, result)
        else:
            return read_memory_cb

    def read_memory_block8(self, addr, size):
        """! @brief Read a block of unaligned bytes in memory.
        @return an array of byte values
        """
        data = self.ap.read_memory_block8(addr, size)
        return self.bp_manager.filter_memory_unaligned_8(addr, size, data)

    def write_memory_block8(self, addr, data):
        """! @brief Write a block of unaligned bytes in memory."""
        self.ap.write_memory_block8(addr, data)

    def write_memory_block32(self, addr, data):
        """! @brief Write an aligned block of 32-bit words."""
        self.ap.write_memory_block32(addr, data)

    def read_memory_block32(self, addr, size):
        """! @brief Read an aligned block of 32-bit words."""
        data = self.ap.read_memory_block32(addr, size)
        return self.bp_manager.filter_memory_aligned_32(addr, size, data)

    def halt(self):
        """! @brief Halt the core
        """
        self.session.notify(Target.EVENT_PRE_HALT, self, Target.HALT_REASON_USER)
        self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)
        self.flush()
        self.session.notify(Target.EVENT_POST_HALT, self, Target.HALT_REASON_USER)

    def step(self, disable_interrupts=True, start=0, end=0):
        """! @brief Perform an instruction level step.
        
        This function preserves the previous interrupt mask state.
        """
        # Was 'if self.get_state() != TARGET_HALTED:'
        # but now value of dhcsr is saved
        dhcsr = self.read_memory(CortexM.DHCSR)
        if not (dhcsr & (CortexM.C_STEP | CortexM.C_HALT)):
            LOG.error('cannot step: target not halted')
            return

        self.session.notify(Target.EVENT_PRE_RUN, self, Target.RUN_TYPE_STEP)

        self.clear_debug_cause_bits()

        # Save previous interrupt mask state
        interrupts_masked = (CortexM.C_MASKINTS & dhcsr) != 0

        # Mask interrupts - C_HALT must be set when changing to C_MASKINTS
        if not interrupts_masked and disable_interrupts:
            self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT | CortexM.C_MASKINTS)

        # Single step using current C_MASKINTS setting
        while True:
            if disable_interrupts or interrupts_masked:
                self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_MASKINTS | CortexM.C_STEP)
            else:
                self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_STEP)

            # Wait for halt to auto set (This should be done before the first read)
            while not self.read_memory(CortexM.DHCSR) & CortexM.C_HALT:
                pass

            # Range is empty, 'range step' will degenerate to 'step'
            if start == end:
                break

            # Read program counter and compare to [start, end)
            program_counter = self.read_core_register(CORE_REGISTER['pc'])
            if program_counter < start or end <= program_counter:
                break

            # Check other stop reasons
            if self.read_memory(CortexM.DFSR) & (CortexM.DFSR_DWTTRAP | CortexM.DFSR_BKPT):
                break
	
        # Restore interrupt mask state
        if not interrupts_masked and disable_interrupts:
            # Unmask interrupts - C_HALT must be set when changing to C_MASKINTS
            self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)

        self.flush()

        self._run_token += 1

        self.session.notify(Target.EVENT_POST_RUN, self, Target.RUN_TYPE_STEP)

    def clear_debug_cause_bits(self):
        self.write_memory(CortexM.DFSR, CortexM.DFSR_VCATCH | CortexM.DFSR_DWTTRAP | CortexM.DFSR_BKPT | CortexM.DFSR_HALTED)
    
    def _perform_emulated_reset(self):
        """! @brief Emulate a software reset by writing registers.
        
        All core registers are written to reset values. This includes setting the initial PC and SP
        to values read from the vector table, which is assumed to be located at the based of the
        boot memory region.
        
        If the memory map does not provide a boot region, then the current value of the VTOR register
        is reused, as it should at least point to a valid vector table.
        
        The current value of DEMCR.VC_CORERESET determines whether the core will be resumed or
        left halted.
        
        Note that this reset method will not set DHCSR.S_RESET_ST or DFSR.VCATCH.
        """
        # Halt the core before making changes.
        self.halt()
        
        bootMemory = self.memory_map.get_boot_memory()
        if bootMemory is None:
            # Reuse current VTOR value if we don't know the boot memory region.
            vectorBase = self.read32(self.VTOR)
        else:
            vectorBase = bootMemory.start
        
        # Read initial SP and PC.
        initialSp = self.read32(vectorBase)
        initialPc = self.read32(vectorBase + 4)
        
        # Init core registers.
        regList = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12',
                    'psp', 'msp', 'lr', 'pc', 'xpsr', 'cfbp']
        valueList = [0] * 13 + \
                    [
                        0,          # PSP
                        initialSp,  # MSP
                        0xffffffff, # LR
                        initialPc,  # PC
                        0x01000000, # XPSR
                        0,          # CFBP
                    ]
        
        if self.has_fpu:
            regList += [('s%d' % n) for n in range(32)] + ['fpscr']
            valueList += [0] * 33
        
        self.write_core_registers_raw(regList, valueList)
        
        # "Reset" SCS registers.
        data = [
                (self.ICSR_PENDSVCLR | self.ICSR_PENDSTCLR),  # ICSR
                vectorBase,                   # VTOR
                (self.NVIC_AIRCR_VECTKEY | self.NVIC_AIRCR_VECTCLRACTIVE),    # AIRCR
                0,  # SCR
                0,  # CCR
                0,  # SHPR1
                0,  # SHPR2
                0,  # SHPR3
                0,  # SHCSR
                0,  # CFSR
                ]
        self.write_memory_block32(self.ICSR, data)
        self.write32(self.CPACR, 0)
        
        if self.has_fpu:
            data = [
                    0,  # FPCCR
                    0,  # FPCAR
                    0,  # FPDSCR
                    ]
            self.write_memory_block32(self.FPCCR, data)
        
        # "Reset" SysTick.
        self.write_memory_block32(self.SYSTICK_CSR, [0] * 3)
        
        # "Reset" NVIC registers.
        numregs = (self.read32(self.ICTR) & 0xf) + 1
        self.write_memory_block32(self.NVIC_ICER0, [0xffffffff] * numregs)
        self.write_memory_block32(self.NVIC_ICPR0, [0xffffffff] * numregs)
        self.write_memory_block32(self.NVIC_IPR0, [0xffffffff] * (numregs * 8))

    def _get_actual_reset_type(self, reset_type):
        """! @brief Determine the reset type to use given defaults and passed in type."""
        
        # Default to reset_type session option if reset_type parameter is None. If the session
        # option isn't set, then use the core's default reset type.
        if reset_type is None:
            if self.session.options.get('reset_type') is None:
                reset_type = self.default_reset_type
            else:
                try:
                    # Convert session option value to enum.
                    resetOption = self.session.options.get('reset_type')
                    reset_type = cmdline.convert_reset_type(resetOption)
                    
                    # The converted option will be None if the option value is 'default'.
                    if reset_type is None:
                        reset_type = self.default_reset_type
                except ValueError:
                    reset_type = self.default_reset_type
        else:
            assert isinstance(reset_type, Target.ResetType)
        
        # If the reset type is just SW, then use our default software reset type.
        if reset_type is Target.ResetType.SW:
            reset_type = self.default_software_reset_type
        
        # Fall back to emulated sw reset if the vectreset is specified and the core doesn't support it.
        if (reset_type is Target.ResetType.SW_VECTRESET) and (not self._supports_vectreset):
            reset_type = Target.ResetType.SW_EMULATED
        
        return reset_type

    def _perform_reset(self, reset_type):
        """! @brief Perform a reset of the specified type."""
        assert isinstance(reset_type, Target.ResetType)
        if reset_type is Target.ResetType.HW:
            self.session.probe.reset()
        elif reset_type is Target.ResetType.SW_EMULATED:
            self._perform_emulated_reset()
        else:
            if reset_type is Target.ResetType.SW_SYSRESETREQ:
                mask = CortexM.NVIC_AIRCR_SYSRESETREQ
            elif reset_type is Target.ResetType.SW_VECTRESET:
                mask = CortexM.NVIC_AIRCR_VECTRESET
            else:
                raise exceptions.InternalError("unhandled reset type")
        
            try:
                self.write_memory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | mask)
                # Without a flush a transfer error can occur
                self.flush()
            except exceptions.TransferError:
                self.flush()

    def reset(self, reset_type=None):
        """! @brief Reset the core.
        
        The reset method is selectable via the reset_type parameter as well as the reset_type
        session option. If the reset_type parameter is not specified or None, then the reset_type
        option will be used. If the option is not set, or if it is set to a value of 'default', the
        the core's default_reset_type property value is used. So, the session option overrides the
        core's default, while the parameter overrides everything.
        
        Note that only v7-M cores support the `VECTRESET` software reset method. If this method
        is chosen but the core doesn't support it, the the reset method will fall back to an
        emulated software reset.
        
        After a call to this function, the core is running.
        """
        self.session.notify(Target.EVENT_PRE_RESET, self)

        reset_type = self._get_actual_reset_type(reset_type)

        self._run_token += 1

        # Give the delegate a chance to overide reset. If the delegate returns True, then it
        # handled the reset on its own.
        if not self.call_delegate('will_reset', core=self, reset_type=reset_type):
            self._perform_reset(reset_type)

        self.call_delegate('did_reset', core=self, reset_type=reset_type)
        
        # Now wait for the system to come out of reset. Keep reading the DHCSR until
        # we get a good response with S_RESET_ST cleared, or we time out.
        with timeout.Timeout(2.0) as t_o:
            while t_o.check():
                try:
                    dhcsr = self.read32(CortexM.DHCSR)
                    if (dhcsr & CortexM.S_RESET_ST) == 0:
                        break
                except exceptions.TransferError:
                    self.flush()
                    sleep(0.01)

        self.session.notify(Target.EVENT_POST_RESET, self)

    def set_reset_catch(self, reset_type=None):
        """! @brief Prepare to halt core on reset."""
        self._reset_catch_delegate_result = self.call_delegate('set_reset_catch', core=self, reset_type=reset_type)
        
        # Default behaviour if the delegate didn't handle it.
        if not self._reset_catch_delegate_result:
            # Halt the target.
            self.halt()

            # Save CortexM.DEMCR.
            self._reset_catch_saved_demcr = self.read_memory(CortexM.DEMCR)

            # Enable reset vector catch if needed.
            if (self._reset_catch_saved_demcr & CortexM.DEMCR_VC_CORERESET) == 0:
                self.write_memory(CortexM.DEMCR, self._reset_catch_saved_demcr | CortexM.DEMCR_VC_CORERESET)
    
    def clear_reset_catch(self, reset_type=None):
        """! @brief Disable halt on reset."""
        self.call_delegate('clear_reset_catch', core=self, reset_type=reset_type)

        if self._reset_catch_delegate_result:
            # restore vector catch setting
            self.write_memory(CortexM.DEMCR, self._reset_catch_saved_demcr)

    def reset_and_halt(self, reset_type=None):
        """! @brief Perform a reset and stop the core on the reset handler."""
        # Set up reset catch.
        self.set_reset_catch(reset_type)

        # Perform the reset.
        self.reset(reset_type)

        # wait until the unit resets
        with timeout.Timeout(2.0) as t_o:
            while t_o.check():
                if self.get_state() not in (Target.TARGET_RESET, Target.TARGET_RUNNING):
                    break
                sleep(0.01)

        # Make sure the thumb bit is set in XPSR in case the reset handler
        # points to an invalid address.
        xpsr = self.read_core_register('xpsr')
        if xpsr & self.XPSR_THUMB == 0:
            self.write_core_register('xpsr', xpsr | self.XPSR_THUMB)

        # Restore to original state.
        self.clear_reset_catch(reset_type)

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
    
    def get_security_state(self):
        """! @brief Returns the current security state of the processor.
        
        @return @ref pyocd.core.target.Target.SecurityState "Target.SecurityState" enumerator. For
            v6-M and v7-M cores, SecurityState.NONSECURE is always returned.
        """
        return Target.SecurityState.NONSECURE

    @property
    def run_token(self):
        return self._run_token

    def is_running(self):
        return self.get_state() == Target.TARGET_RUNNING

    def is_halted(self):
        return self.get_state() == Target.TARGET_HALTED

    def resume(self):
        """! @brief Resume execution of the core.
        """
        if self.get_state() != Target.TARGET_HALTED:
            LOG.debug('cannot resume: target not halted')
            return
        self.session.notify(Target.EVENT_PRE_RUN, self, Target.RUN_TYPE_RESUME)
        self._run_token += 1
        self.clear_debug_cause_bits()
        self.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)
        self.flush()
        self.session.notify(Target.EVENT_POST_RUN, self, Target.RUN_TYPE_RESUME)

    def find_breakpoint(self, addr):
        return self.bp_manager.find_breakpoint(addr)

    def read_core_register(self, reg):
        """! @brief Read CPU register.
        
        Unpack floating point register values
        """
        regIndex = register_name_to_index(reg)
        regValue = self.read_core_register_raw(regIndex)
        # Convert int to float.
        if is_single_float_register(regIndex):
            regValue = conversion.u32_to_float32(regValue)
        elif is_double_float_register(regIndex):
            regValue = conversion.u64_to_float64(regValue)
        return regValue

    def read_core_register_raw(self, reg):
        """! @brief Read a core register.
        
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        vals = self.read_core_registers_raw([reg])
        return vals[0]

    def read_core_registers_raw(self, reg_list):
        """! @brief Read one or more core registers.

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

        # Handle doubles.
        doubles = [reg for reg in reg_list if is_double_float_register(reg)]
        hasDoubles = len(doubles) > 0
        if hasDoubles:
            originalRegList = reg_list
            
            # Strip doubles from reg_list.
            reg_list = [reg for reg in reg_list if not is_double_float_register(reg)]
            
            # Read float regs required to build doubles.
            singleRegList = []
            for reg in doubles:
                singleRegList += (-reg, -reg + 1)
            singleValues = self.read_core_registers_raw(singleRegList)

        # Begin all reads and writes
        dhcsr_cb_list = []
        reg_cb_list = []
        for reg in reg_list:
            if is_cfbp_subregister(reg):
                reg = CORE_REGISTER['cfbp']
            elif is_psr_subregister(reg):
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
            elif is_psr_subregister(reg):
                val &= sysm_to_psr_mask(reg)

            reg_vals.append(val)
        
        # Merge double regs back into result list.
        if hasDoubles:
            results = []
            for reg in originalRegList:
                # Double
                if is_double_float_register(reg):
                    doubleIndex = doubles.index(reg)
                    singleLow = singleValues[doubleIndex * 2]
                    singleHigh = singleValues[doubleIndex * 2 + 1]
                    double = (singleHigh << 32) | singleLow
                    results.append(double)
                # Other register
                else:
                    results.append(reg_vals[reg_list.index(reg)])
            reg_vals = results

        return reg_vals

    def write_core_register(self, reg, data):
        """! @brief Write a CPU register.
        
        Will need to pack floating point register values before writing.
        """
        regIndex = register_name_to_index(reg)
        # Convert float to int.
        if is_single_float_register(regIndex) and type(data) is float:
            data = conversion.float32_to_u32(data)
        elif is_double_float_register(regIndex) and type(data) is float:
            data = conversion.float64_to_u64(data)
        self.write_core_register_raw(regIndex, data)

    def write_core_register_raw(self, reg, data):
        """! @brief Write a core register.
        
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        self.write_core_registers_raw([reg], [data])

    def write_core_registers_raw(self, reg_list, data_list):
        """! @brief Write one or more core registers.

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

        # Read special register if it is present in the list and
        # convert doubles to single float register writes.
        cfbpValue = None
        xpsrValue = None
        reg_data_list = []
        for reg, data in zip(reg_list, data_list):
            if is_double_float_register(reg):
                # Replace double with two single float register writes. For instance,
                # a write of D2 gets converted to writes to S4 and S5.
                singleLow = data & 0xffffffff
                singleHigh = (data >> 32) & 0xffffffff
                reg_data_list += [(-reg, singleLow), (-reg + 1, singleHigh)]
            elif is_cfbp_subregister(reg) and cfbpValue is None:
                cfbpValue = self.read_core_register_raw(CORE_REGISTER['cfbp'])
            elif is_psr_subregister(reg) and xpsrValue is None:
                xpsrValue = self.read_core_register_raw(CORE_REGISTER['xpsr'])
            else:
                # Other register, just copy directly.
                reg_data_list.append((reg, data))
        
        # Write out registers
        dhcsr_cb_list = []
        for reg, data in reg_data_list:
            if is_cfbp_subregister(reg):
                # Mask in the new special register value so we don't modify the other register
                # values that share the same DCRSR number.
                shift = (-reg - 1) * 8
                mask = 0xffffffff ^ (0xff << shift)
                data = (cfbpValue & mask) | ((data & 0xff) << shift)
                cfbpValue = data # update special register for other writes that might be in the list
                reg = CORE_REGISTER['cfbp']
            elif is_psr_subregister(reg):
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

    def set_breakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        """! @brief Set a hardware or software breakpoint at a specific location in memory.
        
        @retval True Breakpoint was set.
        @retval False Breakpoint could not be set.
        """
        return self.bp_manager.set_breakpoint(addr, type)

    def remove_breakpoint(self, addr):
        """! @brief Remove a breakpoint at a specific location."""
        self.bp_manager.remove_breakpoint(addr)

    def get_breakpoint_type(self, addr):
        return self.bp_manager.get_breakpoint_type(addr)

    @property
    def available_breakpoint_count(self):
        return self.fpb.available_breakpoints

    def find_watchpoint(self, addr, size, type):
        return self.dwt.find_watchpoint(addr, size, type)

    def set_watchpoint(self, addr, size, type):
        """! @brief Set a hardware watchpoint.
        """
        return self.dwt.set_watchpoint(addr, size, type)

    def remove_watchpoint(self, addr, size, type):
        """! @brief Remove a hardware watchpoint.
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

    def is_vector_catch(self):
        debugEvents = self.read_memory(CortexM.DFSR) & CortexM.DFSR_VCATCH
        return debugEvents != 0

    def get_target_context(self, core=None):
        return self._target_context

    def set_target_context(self, context):
        self._target_context = context

    ## @brief Names for built-in Exception numbers found in IPSR
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
            if self.session.target.irq_table:
                name = self.session.target.irq_table.get(irq_num)
            if name is not None:
                return "Interrupt[%s]" % name
            else:
                return "Interrupt %d" % irq_num

    def in_thread_mode_on_main_stack(self):
        return (self._target_context.read_core_register('ipsr') == 0 and
                (self._target_context.read_core_register('control') & CortexM.CONTROL_SPSEL) == 0)
