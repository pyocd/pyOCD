# pyOCD debugger
# Copyright (c) 2020 Cypress Semiconductor Corporation
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

from .component import CoreSightCoreComponent
from ..core.target import Target
from ..core.core_registers import CoreRegistersIndex

LOG = logging.getLogger(__name__)

DEAD_VALUE = 0


class GenericMemAPTarget(Target, CoreSightCoreComponent):
    """! @brief This target represents ARM debug Access Port without a CPU
    
    It may be used to access the address space of the target via Access Ports
    without real ARM CPU core behind it. For instance Cypress PSoC64 devices have
    three APs implemented in the hardware:
    * AP #0 -> CPU-less AHB AP
    * AP #1 -> Cortex-M0+ AP
    * AP #2 -> Cortex-M4F AP
    Depending on the protection state, AP #1 and AP #2 can be permanently disabled.
    This class allows to communicate with Secure FW running on the target via AP #0. 
    
    Most of the methods in this class (except memory access methods) are empty/dummy.
    """
    
    def __init__(self, session, ap, memory_map=None, core_num=0, cmpid=None, address=None):
        Target.__init__(self, session, memory_map)
        CoreSightCoreComponent.__init__(self, ap, cmpid, address)
        self.core_number = core_num
        self.core_type = DEAD_VALUE
        self._core_registers = CoreRegistersIndex()
        self._target_context = None

    def add_child(self, cmp):
        pass

    @property
    def core_registers(self):
        return self._core_registers

    @property
    def supported_security_states(self):
        return Target.SecurityState.NONSECURE,

    def init(self):
        pass

    def disconnect(self, resume=True):
        pass

    def write_memory(self, addr, value, transfer_size=32):
        self.ap.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        return self.ap.read_memory(addr, transfer_size, True)

    def read_memory_block8(self, addr, size):
        return self.ap.read_memory_block8(addr, size)

    def write_memory_block8(self, addr, data):
        self.ap.write_memory_block8(addr, data)

    def write_memory_block32(self, addr, data):
        self.ap.write_memory_block32(addr, data)

    def read_memory_block32(self, addr, size):
        return self.ap.read_memory_block32(addr, size)

    def halt(self):
        pass

    def step(self, disable_interrupts=True, start=0, end=0, hook_cb=None):
        pass

    def reset(self, reset_type=None):
        pass

    def reset_and_halt(self, reset_type=None):
        self.reset(reset_type)

    def get_state(self):
        return Target.State.HALTED

    def get_security_state(self):
        return Target.SecurityState.NONSECURE

    def is_running(self):
        return self.get_state() == Target.State.RUNNING

    def is_halted(self):
        return self.get_state() == Target.State.HALTED

    def resume(self):
        pass

    def find_breakpoint(self, addr):
        return None

    def read_core_register(self, reg):
        return DEAD_VALUE

    def read_core_register_raw(self, reg):
        return DEAD_VALUE

    def read_core_registers_raw(self, reg_list):
        return [DEAD_VALUE] * len(reg_list)

    def write_core_register(self, reg, data):
        pass

    def write_core_register_raw(self, reg, data):
        pass

    def write_core_registers_raw(self, reg_list, data_list):
        pass

    def set_breakpoint(self, addr, type=Target.BreakpointType.AUTO):
        return False

    def remove_breakpoint(self, addr):
        pass

    def get_breakpoint_type(self, addr):
        return None

    def set_watchpoint(self, addr, size, type):
        return False

    def remove_watchpoint(self, addr, size, type):
        pass

    def set_vector_catch(self, enable_mask):
        pass

    def get_vector_catch(self):
        return 0

    def get_halt_reason(self):
        return Target.HaltReason.DEBUG

    def get_target_context(self, core=None):
        return self._target_context

    def set_target_context(self, context):
        self._target_context = context

    def create_init_sequence(self):
        pass

    def mass_erase(self):
        pass
