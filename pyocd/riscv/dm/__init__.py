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
RISC-V Debug Module layer.

Provides high-level access to RISC-V Debug Module features:
- Abstract Commands: Register access via data registers
- Program Buffer: Custom instruction execution for CSR/memory access
- System Bus Access: Direct memory access independent of hart state

Architecture: DTM -> DMI -> DebugModule
                              -> AbstractCommands
                              -> ProgramBuffer
                              -> SystemBusAccess

Source: RISC-V Debug Specification v0.13.2
"""

from .registers import (
    DMReg, AbstractCS, AbstractCmdErr, Command, DMControl, DMStatus, SBCS,
    RiscvRegno, RiscvInstr,
)

__all__ = [
    'DMReg', 'AbstractCS', 'AbstractCmdErr', 'Command', 'DMControl', 'DMStatus',
    'SBCS', 'RiscvRegno', 'RiscvInstr',
]
