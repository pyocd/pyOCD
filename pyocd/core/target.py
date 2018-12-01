"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2018 ARM Limited

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

from .memory_interface import MemoryInterface
from ..utility.notification import Notifier
from .memory_map import MemoryMap

class Target(MemoryInterface, Notifier):

    TARGET_RUNNING = 1   # Core is executing code.
    TARGET_HALTED = 2    # Core is halted in debug mode.
    TARGET_RESET = 3     # Core is being held in reset.
    TARGET_SLEEPING = 4  # Core is sleeping due to a wfi or wfe instruction.
    TARGET_LOCKUP = 5    # Core is locked up.

    # Types of breakpoints.
    #
    # Auto will select the best type given the
    # address and available breakpoints.
    BREAKPOINT_HW = 1
    BREAKPOINT_SW = 2
    BREAKPOINT_AUTO = 3

    WATCHPOINT_READ = 1
    WATCHPOINT_WRITE = 2
    WATCHPOINT_READ_WRITE = 3

    # Vector catch option masks.
    CATCH_NONE = 0
    CATCH_HARD_FAULT = (1 << 0)
    CATCH_BUS_FAULT = (1 << 1)
    CATCH_MEM_FAULT = (1 << 2)
    CATCH_INTERRUPT_ERR = (1 << 3)
    CATCH_STATE_ERR = (1 << 4)
    CATCH_CHECK_ERR = (1 << 5)
    CATCH_COPROCESSOR_ERR = (1 << 6)
    CATCH_CORE_RESET = (1 << 7)
    CATCH_ALL = (CATCH_HARD_FAULT | CATCH_BUS_FAULT | CATCH_MEM_FAULT | CATCH_INTERRUPT_ERR \
                | CATCH_STATE_ERR | CATCH_CHECK_ERR | CATCH_COPROCESSOR_ERR | CATCH_CORE_RESET)

    # Events
    EVENT_POST_CONNECT = 1
    EVENT_PRE_DISCONNECT = 2
    EVENT_PRE_RUN = 3 # data is run type
    EVENT_POST_RUN = 4 # data is run type
    EVENT_PRE_HALT = 5 # data is halt reason
    EVENT_POST_HALT = 6 # data is halt reason
    EVENT_PRE_RESET = 7
    EVENT_POST_RESET = 8
    EVENT_PRE_FLASH_PROGRAM = 9
    EVENT_POST_FLASH_PROGRAM = 10

    # Run types
    RUN_TYPE_RESUME = 1
    RUN_TYPE_STEP = 2

    # Halt reasons
    HALT_REASON_USER = 1
    HALT_REASON_DEBUG = 2

    def __init__(self, session, memoryMap=None):
        super(Target, self).__init__()
        self._session = session
        self.root_target = None
        self.part_number = ""
        self.memory_map = memoryMap or MemoryMap()
        self.halt_on_connect = session.options.get('halt_on_connect', True)
        self.auto_unlock = session.options.get('auto_unlock', True)
        self.has_fpu = False
        self._svd_location = None
        self._svd_device = None

    @property
    def session(self):
        return self._session

    @property
    def svd_device(self):
        return self._svd_device

    def is_locked(self):
        return False

    def create_init_sequence(self):
        raise NotImplementedError()

    def init(self):
        raise NotImplementedError()

    def disconnect(self, resume=True):
        pass

    def flush(self):
        self.session.probe.flush()

    def halt(self):
        raise NotImplementedError()

    def step(self, disable_interrupts=True):
        raise NotImplementedError()

    def resume(self):
        raise NotImplementedError()

    def mass_erase(self):
        raise NotImplementedError()

    def read_core_register(self, id):
        raise NotImplementedError()

    def write_core_register(self, id, data):
        raise NotImplementedError()

    def read_core_register(self, reg):
        raise NotImplementedError()

    def read_core_registers_raw(self, reg_list):
        raise NotImplementedError()

    def write_core_register(self, reg, data):
        raise NotImplementedError()

    def write_core_registers_raw(self, reg_list, data_list):
        raise NotImplementedError()

    def find_breakpoint(self, addr):
        raise NotImplementedError()

    def set_breakpoint(self, addr, type=BREAKPOINT_AUTO):
        raise NotImplementedError()

    def get_breakpoint_type(self, addr):
        raise NotImplementedError()

    def remove_breakpoint(self, addr):
        raise NotImplementedError()

    def set_watchpoint(self, addr, size, type):
        raise NotImplementedError()

    def remove_watchpoint(self, addr, size, type):
        raise NotImplementedError()

    def reset(self, software_reset=None):
        raise NotImplementedError()

    def reset_stop_on_reset(self, software_reset=None):
        raise NotImplementedError()

    def set_target_state(self, state):
        raise NotImplementedError()

    def get_state(self):
        raise NotImplementedError()

    @property
    def run_token(self):
        return 0

    def is_running(self):
        return self.get_state() == Target.TARGET_RUNNING

    def is_halted(self):
        return self.get_state() == Target.TARGET_HALTED

    def get_memory_map(self):
        return self.memory_map

    def set_vector_catch(self, enableMask):
        raise NotImplementedError()

    def get_vector_catch(self):
        raise NotImplementedError()

    # GDB functions
    def get_target_xml(self):
        raise NotImplementedError()

    def get_target_context(self, core=None):
        raise NotImplementedError()

    def get_root_context(self, core=None):
        raise NotImplementedError()

    def set_root_context(self, context, core=None):
        raise NotImplementedError()
