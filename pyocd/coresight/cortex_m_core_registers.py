# pyOCD debugger
# Copyright (c) 2019-2020,2025 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import logging
from typing import TYPE_CHECKING, cast

from ..core.core_registers import CoreRegisterInfo

if TYPE_CHECKING:
    from ..core.core_registers import CoreRegisterNameOrNumberType

LOG = logging.getLogger(__name__)

# Program Status Register
APSR_MASK = 0xF80F0000
EPSR_MASK = 0x0700FC00
IPSR_MASK = 0x000001FF

class CortexMCoreRegisterInfo(CoreRegisterInfo):
    """@brief Core register subclass for Cortex-M registers.

    For most registers, the index is the value written to the DCRSR register to read or write the
    core register. Other core registers not directly supported by DCRSR have special index values that
    are interpreted by the helper methods on this class and the core register read/write code in CortexM
    and its subclasses. These artificial register index values and how they are interpreted are documented
    in the register definitions in CoreRegisterGroups.
    """

    ## Map of register name to info.
    _NAME_MAP = {}

    ## Map of register index to info.
    _INDEX_MAP = {}

    @classmethod
    def register_name_to_index(cls, reg: "CoreRegisterNameOrNumberType") -> int:
        """@brief Convert a register name to integer register index.
        @param reg Either a register name or internal register number.
        @return Internal register number.
        @exception KeyError
        """
        if isinstance(reg, str):
            try:
                reg = cls._NAME_MAP[reg.lower()].index
            except KeyError as err:
                raise KeyError('unknown core register name %s' % reg) from err
        return reg

    @classmethod
    def get(cls, reg: "CoreRegisterNameOrNumberType") -> "CortexMCoreRegisterInfo":
        """@brief Return the CoreRegisterInfo instance for a register.
        @param reg Either a register name or internal register number.
        @return CoreRegisterInfo
        @exception KeyError
        """
        return cast(CortexMCoreRegisterInfo, super().get(reg))

    @property
    def is_fpu_register(self) -> bool:
        """@brief Returns true for FPSCR, SP, or DP registers."""
        return self.index == 33 or self.is_float_register

    @property
    def is_cfbp_subregister(self) -> bool:
        """@brief Whether the register is one of those combined into CFBP by the DCSR."""
        return self.index > 0 and (self.index >> 8) in (20, 34, 35)

    @property
    def is_psr_subregister(self) -> bool:
        """@brief Whether the register is a combination of xPSR fields."""
        return 0x10000 <= self.index <= 0x10007

    @property
    def psr_mask(self) -> int:
        """@brief Generate a PSR mask based on bottom 3 bits of a MRS SYSm value"""
        mask = 0
        if (self.index & 1) != 0:
            mask |= IPSR_MASK
        if (self.index & 2) != 0:
            mask |= EPSR_MASK
        if (self.index & 4) == 0:
            mask |= APSR_MASK
        return mask

class CoreRegisterGroups:
    """@brief Namespace for lists of Cortex-M core register information."""

    _I = CortexMCoreRegisterInfo # Reduce table width.

    # For most registers, the index is the DCRSR register selector value. Those registers not directly
    # supported by the DCRSR have special values that are interpreted by the register read/write methods.

    ## @brief Registers common to all M-profile cores.
    M_PROFILE_COMMON = [
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('r0',            0,        32,     'uint32',       'general',  0,      "org.gnu.gdb.arm.m-profile"),
        _I('r1',            1,        32,     'uint32',       'general',  1,      "org.gnu.gdb.arm.m-profile"),
        _I('r2',            2,        32,     'uint32',       'general',  2,      "org.gnu.gdb.arm.m-profile"),
        _I('r3',            3,        32,     'uint32',       'general',  3,      "org.gnu.gdb.arm.m-profile"),
        _I('r4',            4,        32,     'uint32',       'general',  4,      "org.gnu.gdb.arm.m-profile"),
        _I('r5',            5,        32,     'uint32',       'general',  5,      "org.gnu.gdb.arm.m-profile"),
        _I('r6',            6,        32,     'uint32',       'general',  6,      "org.gnu.gdb.arm.m-profile"),
        _I('r7',            7,        32,     'uint32',       'general',  7,      "org.gnu.gdb.arm.m-profile"),
        _I('r8',            8,        32,     'uint32',       'general',  8,      "org.gnu.gdb.arm.m-profile"),
        _I('r9',            9,        32,     'uint32',       'general',  9,      "org.gnu.gdb.arm.m-profile"),
        _I('r10',           10,       32,     'uint32',       'general',  10,     "org.gnu.gdb.arm.m-profile"),
        _I('r11',           11,       32,     'uint32',       'general',  11,     "org.gnu.gdb.arm.m-profile"),
        _I('r12',           12,       32,     'uint32',       'general',  12,     "org.gnu.gdb.arm.m-profile"),
        _I('sp',            13,       32,     'data_ptr',     'general',  13,     "org.gnu.gdb.arm.m-profile"),
        _I('lr',            14,       32,     'code_ptr',     'general',  14,     "org.gnu.gdb.arm.m-profile"),
        _I('pc',            15,       32,     'code_ptr',     'general',  15,     "org.gnu.gdb.arm.m-profile"),
        _I('xpsr',          16,       32,     'uint32',       'general',  16,     "org.gnu.gdb.arm.m-profile"),
        _I('msp',           17,       32,     'data_ptr',     'system',   17,     "org.gnu.gdb.arm.m-system"),
        _I('psp',           18,       32,     'data_ptr',     'system',   18,     "org.gnu.gdb.arm.m-system"),
        _I('control',      (20<<8)+3, 32,     'uint32',       'system',   19,     "org.gnu.gdb.arm.m-system"),
        _I('primask',      (20<<8)+0, 32,     'uint32',       'system',   20,     "org.gnu.gdb.arm.m-system"),

        # The CONTROL, FAULTMASK, BASEPRI, and PRIMASK registers are special in that they share the
        # same DCRSR register selector and are returned as a single value. In this dict, these registers
        # have an index which encodes the selector value together with the byte number.
        # The actual DCRSR register index for these combined registers has the key of 'cfbp'.
        _I('cfbp',          20,       32,     'uint32',       'system'),

        # Variants of XPSR.
        #
        # XPSR is always read in its entirety via the debug interface, but we also provide
        # aliases for the submasks APSR, IPSR and EPSR. These are encoded as 0x10000 plus 3 lower bits
        # indicating which parts of the PSR we're interested in - encoded the same way as MRS's SYSm.
        # (Note that 'XPSR' continues to denote the raw 32 bits of the register, as per previous versions,
        # not the union of the three APSR+IPSR+EPSR masks which don't cover the entire register).
        #
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('apsr',          0x10000,  32,     'uint32',       'system'),
        _I('iapsr',         0x10001,  32,     'uint32',       'system'),
        _I('eapsr',         0x10002,  32,     'uint32',       'system'),
        _I('ipsr',          0x10005,  32,     'uint32',       'system'),
        _I('epsr',          0x10006,  32,     'uint32',       'system'),
        _I('iepsr',         0x10007,  32,     'uint32',       'system'),
        ]

    ## @brief Registers available only on v7-M and v8-M.ML.
    V7M_v8M_ML_ONLY = [
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('basepri',      (20<<8)+1, 32,     'uint32',       'system',   21,     "org.gnu.gdb.arm.m-system"),
        _I('faultmask',    (20<<8)+2, 32,     'uint32',       'system',   22,     "org.gnu.gdb.arm.m-system"),
        ]

    ## @brief Extra registers available with only with the Security extension.
    V8M_SEC_ONLY = [
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('msp_ns',        24,       32,     'data_ptr',     'system',   24,     "org.gnu.gdb.arm.secext"),
        _I('psp_ns',        25,       32,     'data_ptr',     'system',   25,     "org.gnu.gdb.arm.secext"),
        _I('msp_s',         26,       32,     'data_ptr',     'system',   26,     "org.gnu.gdb.arm.secext"),
        _I('psp_s',         27,       32,     'data_ptr',     'system',   27,     "org.gnu.gdb.arm.secext"),
        _I('msplim_s',      28,       32,     'uint32',       'system',   28,     "org.gnu.gdb.arm.secext"),
        _I('psplim_s',      29,       32,     'uint32',       'system',   29,     "org.gnu.gdb.arm.secext"),
        _I('control_s',    (34<<8)+3, 32,     'uint32',       'system',   34,     "org.gnu.gdb.arm.secext"),
        _I('primask_s',    (34<<8)+0, 32,     'uint32',       'system',   35,     "org.gnu.gdb.arm.secext"),
        _I('control_ns',   (35<<8)+3, 32,     'uint32',       'system',   38,     "org.gnu.gdb.arm.secext"),
        _I('primask_ns',   (35<<8)+0, 32,     'uint32',       'system',   39,     "org.gnu.gdb.arm.secext"),
        _I('cfbp_s',        34,       32,     'uint32',       'system'),
        _I('cfbp_ns',       35,       32,     'uint32',       'system'),
        ]

    ## @brief The NS stack limits are only available when both Main and Security extensions are present.
    V8M_ML_SEC_ONLY = [
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('msplim_ns',     30,       32,     'uint32',       'system',   30,     "org.gnu.gdb.arm.secext"),
        _I('psplim_ns',     31,       32,     'uint32',       'system',   31,     "org.gnu.gdb.arm.secext"),
        _I('basepri_s',    (34<<8)+1, 32,     'uint32',       'system',   36,     "org.gnu.gdb.arm.secext"),
        _I('faultmask_s',  (34<<8)+2, 32,     'uint32',       'system',   37,     "org.gnu.gdb.arm.secext"),
        _I('basepri_ns',   (35<<8)+1, 32,     'uint32',       'system',   40,     "org.gnu.gdb.arm.secext"),
        _I('faultmask_ns', (35<<8)+2, 32,     'uint32',       'system',   41,     "org.gnu.gdb.arm.secext"),
        ]

    ## @brief Registers only available with the MVE extension.
    V81M_MVE_ONLY = [
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('vpr',           36,       32,     'uint32',       'mve',      32,     "org.gnu.gdb.arm.m-profile-mve"),
        ]

    ## @brief VFPv5 floating point registers.
    #
    # GDB understands the double/single separation so we don't need to separately pass the single regs,
    # just the double regs; thus only the double regs have a gdb regnum and feature.
    VFP_V5 = [
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('fpscr',         33,       32,     'uint32',       'float',    33,     "org.gnu.gdb.arm.vfp"),

        # Single-precision float registers.
        #
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('s0',            0x40,     32,     'ieee_single',  'float'),
        _I('s1',            0x41,     32,     'ieee_single',  'float'),
        _I('s2',            0x42,     32,     'ieee_single',  'float'),
        _I('s3',            0x43,     32,     'ieee_single',  'float'),
        _I('s4',            0x44,     32,     'ieee_single',  'float'),
        _I('s5',            0x45,     32,     'ieee_single',  'float'),
        _I('s6',            0x46,     32,     'ieee_single',  'float'),
        _I('s7',            0x47,     32,     'ieee_single',  'float'),
        _I('s8',            0x48,     32,     'ieee_single',  'float'),
        _I('s9',            0x49,     32,     'ieee_single',  'float'),
        _I('s10',           0x4a,     32,     'ieee_single',  'float'),
        _I('s11',           0x4b,     32,     'ieee_single',  'float'),
        _I('s12',           0x4c,     32,     'ieee_single',  'float'),
        _I('s13',           0x4d,     32,     'ieee_single',  'float'),
        _I('s14',           0x4e,     32,     'ieee_single',  'float'),
        _I('s15',           0x4f,     32,     'ieee_single',  'float'),
        _I('s16',           0x50,     32,     'ieee_single',  'float'),
        _I('s17',           0x51,     32,     'ieee_single',  'float'),
        _I('s18',           0x52,     32,     'ieee_single',  'float'),
        _I('s19',           0x53,     32,     'ieee_single',  'float'),
        _I('s20',           0x54,     32,     'ieee_single',  'float'),
        _I('s21',           0x55,     32,     'ieee_single',  'float'),
        _I('s22',           0x56,     32,     'ieee_single',  'float'),
        _I('s23',           0x57,     32,     'ieee_single',  'float'),
        _I('s24',           0x58,     32,     'ieee_single',  'float'),
        _I('s25',           0x59,     32,     'ieee_single',  'float'),
        _I('s26',           0x5a,     32,     'ieee_single',  'float'),
        _I('s27',           0x5b,     32,     'ieee_single',  'float'),
        _I('s28',           0x5c,     32,     'ieee_single',  'float'),
        _I('s29',           0x5d,     32,     'ieee_single',  'float'),
        _I('s30',           0x5e,     32,     'ieee_single',  'float'),
        _I('s31',           0x5f,     32,     'ieee_single',  'float'),

        # Double-precision float registers.
        #
        # The double-precision floating point registers (D0-D15) are composed of two single-precision
        # floating point registers (S0-S31). The index for double-precision registers is the negated
        # value of the first associated single-precision register.
        #
        #  Name             index     bits    type            group       gdbnum  gdb_feature
        _I('d0',           -0x40,     64,     'ieee_double',  'double',   48,     "org.gnu.gdb.arm.vfp"),
        _I('d1',           -0x42,     64,     'ieee_double',  'double',   49,     "org.gnu.gdb.arm.vfp"),
        _I('d2',           -0x44,     64,     'ieee_double',  'double',   50,     "org.gnu.gdb.arm.vfp"),
        _I('d3',           -0x46,     64,     'ieee_double',  'double',   51,     "org.gnu.gdb.arm.vfp"),
        _I('d4',           -0x48,     64,     'ieee_double',  'double',   52,     "org.gnu.gdb.arm.vfp"),
        _I('d5',           -0x4a,     64,     'ieee_double',  'double',   53,     "org.gnu.gdb.arm.vfp"),
        _I('d6',           -0x4c,     64,     'ieee_double',  'double',   54,     "org.gnu.gdb.arm.vfp"),
        _I('d7',           -0x4e,     64,     'ieee_double',  'double',   55,     "org.gnu.gdb.arm.vfp"),
        _I('d8',           -0x50,     64,     'ieee_double',  'double',   56,     "org.gnu.gdb.arm.vfp"),
        _I('d9',           -0x52,     64,     'ieee_double',  'double',   57,     "org.gnu.gdb.arm.vfp"),
        _I('d10',          -0x54,     64,     'ieee_double',  'double',   58,     "org.gnu.gdb.arm.vfp"),
        _I('d11',          -0x56,     64,     'ieee_double',  'double',   59,     "org.gnu.gdb.arm.vfp"),
        _I('d12',          -0x58,     64,     'ieee_double',  'double',   60,     "org.gnu.gdb.arm.vfp"),
        _I('d13',          -0x5a,     64,     'ieee_double',  'double',   61,     "org.gnu.gdb.arm.vfp"),
        _I('d14',          -0x5c,     64,     'ieee_double',  'double',   62,     "org.gnu.gdb.arm.vfp"),
        _I('d15',          -0x5e,     64,     'ieee_double',  'double',   63,     "org.gnu.gdb.arm.vfp"),
        ]

    del _I # Cleanup namespace.

# Build info map.
CortexMCoreRegisterInfo.add_to_map(CoreRegisterGroups.M_PROFILE_COMMON
            + CoreRegisterGroups.V7M_v8M_ML_ONLY
            + CoreRegisterGroups.V8M_SEC_ONLY
            + CoreRegisterGroups.V8M_ML_SEC_ONLY
            + CoreRegisterGroups.V81M_MVE_ONLY
            + CoreRegisterGroups.VFP_V5)

def index_for_reg(name: str) -> int:
    """@brief Utility to easily convert register name to index."""
    return CortexMCoreRegisterInfo.get(name).index
