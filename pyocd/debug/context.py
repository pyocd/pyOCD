# pyOCD debugger
# Copyright (c) 2016-2019 Arm Limited
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

from ..core.memory_interface import MemoryInterface
from ..utility import conversion
import logging

## @brief Viewport for inspecting the system being debugged.
#
# A debug context is used to access registers and other target information. It enables these
# accesses to be redirected to different locations. For instance, if you want to read registers
# from a call frame that is not the topmost, then a context would redirect those reads to
# locations on the stack.
#
# A context always has a specific core associated with it, which cannot be changed after the
# context is created.
class DebugContext(MemoryInterface):
    def __init__(self, core):
        self._core = core

    @property
    def core(self):
        return self._core

    def write_memory(self, addr, value, transfer_size=32):
        return self._core.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        return self._core.read_memory(addr, transfer_size, now)

    def write_memory_block8(self, addr, value):
        return self._core.write_memory_block8(addr, value)

    def write_memory_block32(self, addr, data):
        return self._core.write_memory_block32(addr, data)

    def read_memory_block8(self, addr, size):
        return self._core.read_memory_block8(addr, size)

    def read_memory_block32(self, addr, size):
        return self._core.read_memory_block32(addr, size)

    # Utility helper to find registers in stack or task control blocks
    def _do_read_regs_in_memory(self, reg_list, tables, special_cases):
        reg_vals = []

        for reg in reg_list:

            # Allow for special cases like stack pointer
            special = special_cases.get(reg, None)
            if special is not None:
                reg_vals.append(special)
                continue

            isDouble = self.core.is_double_float_register(reg)

            for (base, table) in tables:
                # Look up offset for this register.
                if isDouble:
                    baseOffset = table.get(-reg, None)
                    baseOffset2 = table.get(-reg + 1, None)
                else:
                    baseOffset = table.get(reg, None)

                if baseOffset is not None:
                    break

            # If we don't have an offset, pass to parent context
            if baseOffset is None:
                reg_vals.append(self._parent.read_core_register_raw(reg))
                continue

            try:
                if isDouble:
                    first = self._parent.read_memory(base + baseOffset)
                    second = self._parent.read_memory(base + baseOffset2)
                    reg_vals.append((second << 32) | first)
                else:
                    reg_vals.append(self._parent.read_memory(base + baseOffset))
            except exceptions.TransferError:
                reg_vals.append(0)

        return reg_vals

    def read_core_register(self, reg):
        """
        read CPU register
        Unpack floating point register values
        """
        regIndex = self._core.register_name_to_index(reg)
        regValue = self.read_core_register_raw(regIndex)
        # Convert int to float.
        if self._core.is_single_float_register(regIndex):
            regValue = conversion.u32_to_float32(regValue)
        elif self._core.is_double_float_register(regIndex):
            regValue = conversion.u64_to_float64(regValue)
        return regValue

    def read_core_register_raw(self, reg):
        """
        read a core register (r0 .. r16).
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        vals = self.read_core_registers_raw([reg])
        return vals[0]

    def read_core_registers_raw(self, reg_list):
        return self._core.read_core_registers_raw(reg_list)

    def write_core_register(self, reg, data):
        """
        write a CPU register.
        Will need to pack floating point register values before writing.
        """
        regIndex = self._core.register_name_to_index(reg)
        # Convert float to int.
        if self._core.is_single_float_register(regIndex) and type(data) is float:
            data = conversion.float32_to_u32(data)
        elif self._core.is_double_float_register(regIndex) and type(data) is float:
            data = conversion.float64_to_u64(data)
        self.write_core_register_raw(regIndex, data)

    def write_core_register_raw(self, reg, data):
        """
        write a core register (r0 .. r16)
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        self.write_core_registers_raw([reg], [data])

    def write_core_registers_raw(self, reg_list, data_list):
        self._core.write_core_registers_raw(reg_list, data_list)

    def flush(self):
        self._core.flush()

