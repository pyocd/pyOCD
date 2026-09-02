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
RISC-V debug context for pyOCD.

Provides register type conversion using RiscvCoreRegisterInfo
instead of the hardcoded CortexMCoreRegisterInfo in the base DebugContext.
"""

from ...core.core_target import CoreTarget
from ...core.memory_interface import MemoryInterface
from .core_registers import RiscvCoreRegisterInfo


class RiscvDebugContext(MemoryInterface):
    """Debug context for RISC-V cores.

    Replaces the ARM-specific DebugContext with RISC-V register info.
    Forwards raw register and memory access to the parent core,
    while handling name-to-index conversion using RiscvCoreRegisterInfo.

    This follows the same pattern as pyOCD's DebugContext but without
    the CoreSight/CortexM dependencies.
    """

    def __init__(self, parent):
        """Initialize debug context.

        Args:
            parent: The RISCVCore instance (acts as the parent context)
        """
        self._parent = parent
        self._core = parent

    @property
    def parent(self):
        return self._parent

    @property
    def core(self):
        return self._core

    @property
    def session(self):
        return self.core.session

    # ---- Memory access (forward to core) ----

    def write_memory(self, addr, value, transfer_size=32):
        return self._parent.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        return self._parent.read_memory(addr, transfer_size, now)

    def write_memory_block8(self, addr, value):
        return self._parent.write_memory_block8(addr, value)

    def write_memory_block32(self, addr, data):
        return self._parent.write_memory_block32(addr, data)

    def read_memory_block8(self, addr, size):
        return self._parent.read_memory_block8(addr, size)

    def read_memory_block32(self, addr, size):
        return self._parent.read_memory_block32(addr, size)

    # ---- Register access with type conversion ----

    def read_core_register(self, reg):
        """Read register with type conversion.

        Args:
            reg: Register name (str) or index (int)

        Returns:
            Register value (int or float)
        """
        reg_info = RiscvCoreRegisterInfo.get(reg)
        raw = self.read_core_register_raw(reg_info.index)
        return reg_info.from_raw(raw)

    def read_core_register_raw(self, reg):
        """Read register as raw integer.

        Args:
            reg: Register name (str) or index (int)

        Returns:
            Integer register value
        """
        vals = self.read_core_registers_raw([reg])
        return vals[0]

    def read_core_registers_raw(self, reg_list):
        """Read multiple registers as raw integers.

        Args:
            reg_list: List of register names or indices

        Returns:
            List of integer values
        """
        return self._parent.read_core_registers_raw(reg_list)

    def write_core_register(self, reg, data):
        """Write register with type conversion.

        Args:
            reg: Register name (str) or index (int)
            data: Value to write (int or float)
        """
        reg_info = RiscvCoreRegisterInfo.get(reg)
        self.write_core_register_raw(reg_info.index, reg_info.to_raw(data))

    def write_core_register_raw(self, reg, data):
        """Write register as raw integer.

        Args:
            reg: Register name (str) or index (int)
            data: Integer value to write
        """
        self.write_core_registers_raw([reg], [data])

    def write_core_registers_raw(self, reg_list, data_list):
        """Write multiple registers as raw integers.

        Args:
            reg_list: List of register names or indices
            data_list: List of integer values
        """
        self._parent.write_core_registers_raw(reg_list, data_list)

    def flush(self):
        self._core.flush()
