# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
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

"""
RISC-V core register definitions for pyOCD.

Maps RISC-V register names to RiscvRegno indices, compatible with
pyOCD's CoreRegisterInfo infrastructure and GDB target.xml generation.

Register numbers follow RISC-V Debug Spec v0.13.2 Table 3.11.
GDB feature names follow GDB RISC-V target description standard.
"""

from ...core.core_registers import CoreRegisterInfo
from ..dm.registers import RiscvRegno

## GDB feature names for target.xml
RISCV_GDB_FEATURE_CPU = "org.gnu.gdb.riscv.cpu"
RISCV_GDB_FEATURE_CSR = "org.gnu.gdb.riscv.csr"
RISCV_GDB_FEATURE_CUSTOM = "org.gnu.gdb.riscv.custom"


class RiscvCoreRegisterInfo(CoreRegisterInfo):
    """RISC-V core register information.

    Extends CoreRegisterInfo with RISC-V specific register definitions.
    Index values match RiscvRegno for direct use with DebugModule.read_register().
    """

    _NAME_MAP = {}
    _INDEX_MAP = {}

    @classmethod
    def register_name_to_index(cls, reg):
        """Convert register name or number to RiscvRegno index.

        Args:
            reg: Register name (str) or index (int)

        Returns:
            Integer register index (RiscvRegno value)
        """
        info = cls.get(reg)
        return info.index


def _build_register_list():
    """Build the complete RISC-V register list."""
    regs = []

    # GPR x0-x31 with GDB register numbers 0-31
    for i in range(32):
        regs.append(RiscvCoreRegisterInfo(
            name=f'x{i}',
            index=RiscvRegno.X0 + i,
            bitsize=32,
            reg_type='uint32',
            reg_group='general',
            reg_num=i,
            feature=RISCV_GDB_FEATURE_CPU,
        ))

    # PC (mapped to DPC) - GDB register number 32
    regs.append(RiscvCoreRegisterInfo(
        name='pc',
        index=RiscvRegno.DPC,
        bitsize=32,
        reg_type='uint32',
        reg_group='general',
        reg_num=32,
        feature=RISCV_GDB_FEATURE_CPU,
    ))

    # ABI name aliases for GPR (same index, no separate GDB regnum)
    _ABI_NAMES = {
        'zero': RiscvRegno.X0,
        'ra': RiscvRegno.X1,
        'sp': RiscvRegno.X2,
        'gp': RiscvRegno.X3,
        'tp': RiscvRegno.X4,
        't0': RiscvRegno.X5,
        't1': RiscvRegno.X6,
        't2': RiscvRegno.X7,
        's0': RiscvRegno.X8,
        'fp': RiscvRegno.X8,
        's1': RiscvRegno.X9,
        'a0': RiscvRegno.X10,
        'a1': RiscvRegno.X11,
        'a2': RiscvRegno.X12,
        'a3': RiscvRegno.X13,
        'a4': RiscvRegno.X14,
        'a5': RiscvRegno.X15,
        'a6': RiscvRegno.X16,
        'a7': RiscvRegno.X17,
        's2': RiscvRegno.X18,
        's3': RiscvRegno.X19,
        's4': RiscvRegno.X20,
        's5': RiscvRegno.X21,
        's6': RiscvRegno.X22,
        's7': RiscvRegno.X23,
        's8': RiscvRegno.X24,
        's9': RiscvRegno.X25,
        's10': RiscvRegno.X26,
        's11': RiscvRegno.X27,
        't3': RiscvRegno.X28,
        't4': RiscvRegno.X29,
        't5': RiscvRegno.X30,
        't6': RiscvRegno.X31,
    }
    for name, regno in _ABI_NAMES.items():
        regs.append(RiscvCoreRegisterInfo(
            name=name,
            index=regno,
            bitsize=32,
            reg_type='uint32',
            reg_group='general',
            feature=RISCV_GDB_FEATURE_CPU,
        ))

    return regs


# Build the register maps on module load
RiscvCoreRegisterInfo.add_to_map(_build_register_list())

# Load standard RISC-V CSRs into name/index maps (unconditional sections).
# Vendor CSRs are loaded per-target at instantiation time.
from .csr import load_csr_configs as _load_csr_configs
_standard_csrs = _load_csr_configs(["riscv_standard_csr.yaml"], phase=1)
RiscvCoreRegisterInfo.add_to_map(_standard_csrs)
