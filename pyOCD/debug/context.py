"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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

from ..coresight.cortex_m import (CORE_REGISTER, register_name_to_index)
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
class DebugContext(object):
    def __init__(self, core):
        self._core = core

    @property
    def core(self):
        return self._core

    def writeMemory(self, addr, value, transfer_size=32):
        return self._core.writeMemory(addr, value, transfer_size)

    def readMemory(self, addr, transfer_size=32, now=True):
        return self._core.readMemory(addr, transfer_size, now)

    def writeBlockMemoryUnaligned8(self, addr, value):
        return self._core.writeBlockMemoryUnaligned8(addr, value)

    def writeBlockMemoryAligned32(self, addr, data):
        return self._core.writeBlockMemoryAligned32(addr, data)

    def readBlockMemoryUnaligned8(self, addr, size):
        return self._core.readBlockMemoryUnaligned8(addr, size)

    def readBlockMemoryAligned32(self, addr, size):
        return self._core.readBlockMemoryAligned32(addr, size)

    # @brief Shorthand to write a 32-bit word.
    def write32(self, addr, value):
        self.writeMemory(addr, value, 32)

    # @brief Shorthand to write a 16-bit halfword.
    def write16(self, addr, value):
        self.writeMemory(addr, value, 16)

    # @brief Shorthand to write a byte.
    def write8(self, addr, value):
        self.writeMemory(addr, value, 8)

    # @brief Shorthand to read a 32-bit word.
    def read32(self, addr, now=True):
        return self.readMemory(addr, 32, now)

    # @brief Shorthand to read a 16-bit halfword.
    def read16(self, addr, now=True):
        return self.readMemory(addr, 16, now)

    # @brief Shorthand to read a byte.
    def read8(self, addr, now=True):
        return self.readMemory(addr, 8, now)

    def readCoreRegister(self, reg):
        """
        read CPU register
        Unpack floating point register values
        """
        regIndex = register_name_to_index(reg)
        regValue = self.readCoreRegisterRaw(regIndex)
        # Convert int to float.
        if regIndex >= 0x40:
            regValue = conversion.u32BEToFloat32BE(regValue)
        return regValue

    def readCoreRegisterRaw(self, reg):
        """
        read a core register (r0 .. r16).
        If reg is a string, find the number associated to this register
        in the lookup table CORE_REGISTER
        """
        vals = self.readCoreRegistersRaw([reg])
        return vals[0]

    def readCoreRegistersRaw(self, reg_list):
        return self._core.readCoreRegistersRaw(reg_list)

    def writeCoreRegister(self, reg, data):
        """
        write a CPU register.
        Will need to pack floating point register values before writing.
        """
        regIndex = register_name_to_index(reg)
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
        self._core.writeCoreRegistersRaw(reg_list, data_list)

    def flush(self):
        self._core.flush()

