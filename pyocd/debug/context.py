# pyOCD debugger
# Copyright (c) 2016-2020 Arm Limited
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

from ..core.memory_interface import MemoryInterface
from ..coresight.component import CoreSightCoreComponent
from ..coresight.cortex_m_core_registers import CortexMCoreRegisterInfo

class DebugContext(MemoryInterface):
    """! @brief Viewport for inspecting the system being debugged.
    
    A debug context is used to access target registers and memory. It enables these accesses to be
    redirected to different locations. For instance, if you want to read registers from a call frame
    that is not the topmost, then a context would redirect those reads to locations on the stack.
    
    A context always has both a parent context and a specific core associated with it, neither of
    which can be changed after the context is created. The parent context is passed into the
    constructor. For the top-level debug context, the parent *is* the core. For other contexts that
    have a context as their parent, the core is set to the topmost parent's core.
    
    The DebugContext class itself is meant to be used as a base class. It's primary purpose is to
    provide the default implementation of methods to forward calls up to the parent and eventually
    to the core.
    """
    
    def __init__(self, parent):
        """! @brief Debug context constructor.
        
        @param self
        @param parent The parent of this context. Can be either a core (CoreSightCoreComponent) or
            another DebugContext instance.
        """
        self._parent = parent
        
        if isinstance(self._parent, CoreSightCoreComponent):
            self._core = parent
        else:
            self._core = parent.core

    @property
    def parent(self):
        return self._parent

    @property
    def core(self):
        return self._core
    
    @property
    def session(self):
        return self.core.session

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

    def read_core_register(self, reg):
        """! @brief Read one core register.
        
        @param self The debug context.
        @param reg Either the register's name in lowercase or an integer register index.
        @return The current value of the register. Most core registers return an integer value,
            while the floating point single and double precision register return a float value.
        
        @exception KeyError Invalid or unsupported register was requested.
        @exception @ref pyocd.core.exceptions.CoreRegisterAccessError "CoreRegisterAccessError" Failed to
            read the register.
        """
        reg_info = CortexMCoreRegisterInfo.get(reg)
        regValue = self.read_core_register_raw(reg_info.index)
        return reg_info.from_raw(regValue)

    def read_core_register_raw(self, reg):
        """! @brief Read a core register without type conversion.
        
        @param self The debug context.
        @param reg Either the register's name in lowercase or an integer register index.
        @return The current integer value of the register. Even float register values are returned
            as integers (thus the "raw").
        
        @exception KeyError Invalid or unsupported register was requested.
        @exception @ref pyocd.core.exceptions.CoreRegisterAccessError "CoreRegisterAccessError" Failed to
            read the register.
        """
        vals = self.read_core_registers_raw([reg])
        return vals[0]

    def read_core_registers_raw(self, reg_list):
        """! @brief Read one or more core registers.
        
        @param self The debug context.
        @param reg_list List of registers to read. Each element in the list can be either the
            register's name in lowercase or the integer register index.
        @return List of integer values of the registers requested to be read. The result list will
            be the same length as _reg_list_.
        
        @exception KeyError Invalid or unsupported register was requested.
        @exception @ref pyocd.core.exceptions.CoreRegisterAccessError "CoreRegisterAccessError" Failed to
            read one or more registers.
        """
        return self._parent.read_core_registers_raw(reg_list)

    def write_core_register(self, reg, data):
        """! @brief Write a CPU register.
        
        @param self The debug context.
        @param reg The name of the register to write.
        @param data New value of the register. Float registers accept float values.
        
        @exception KeyError Invalid or unsupported register was requested.
        @exception @ref pyocd.core.exceptions.CoreRegisterAccessError "CoreRegisterAccessError" Failed to
            write the register.
        """
        reg_info = CortexMCoreRegisterInfo.get(reg)
        self.write_core_register_raw(reg_info.index, reg_info.to_raw(data))

    def write_core_register_raw(self, reg, data):
        """! @brief Write a CPU register without type conversion.
        
        @param self The debug context.
        @param reg The name of the register to write.
        @param data New value of the register. Must be an integer, even for float registers.
        
        @exception KeyError Invalid or unsupported register was requested.
        @exception @ref pyocd.core.exceptions.CoreRegisterAccessError "CoreRegisterAccessError" Failed to
            write the register.
        """
        self.write_core_registers_raw([reg], [data])

    def write_core_registers_raw(self, reg_list, data_list):
        """! @brief Write one or more core registers.

        @param self The debug context.
        @param reg_list List of registers to read. Each element in the list can be either the
            register's name in lowercase or the integer register index.
        @param data_list List of values for the registers in the corresponding positions of
            _reg_list_. All values must be integers, even for float registers.
        
        @exception KeyError Invalid or unsupported register was requested.
        @exception @ref pyocd.core.exceptions.CoreRegisterAccessError "CoreRegisterAccessError" Failed to
            write one or more registers.
        """
        self._parent.write_core_registers_raw(reg_list, data_list)

    def flush(self):
        self._core.flush()

