"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

from ..utility.notification import Notifier
from .memory_map import MemoryMap

class Target(Notifier):

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

    def __init__(self, link, memoryMap=None):
        super(Target, self).__init__()
        self.link = link
        self.flash = None
        self.root_target = None
        self.part_number = ""
        self.memory_map = memoryMap or MemoryMap()
        self.halt_on_connect = True
        self.has_fpu = False
        self._svd_location = None
        self._svd_device = None

    @property
    def svd_device(self):
        return self._svd_device

    def setAutoUnlock(self, doAutoUnlock):
        pass

    def isLocked(self):
        return False

    def setHaltOnConnect(self, halt):
        self.halt_on_connect = halt

    def setFlash(self, flash):
        self.flash = flash

    def init(self):
        raise NotImplementedError()

    def disconnect(self, resume=True):
        pass

    def info(self, request):
        return self.link.info(request)

    def flush(self):
        self.link.flush()

    def readIDCode(self):
        raise NotImplementedError()

    def halt(self):
        raise NotImplementedError()

    def step(self, disable_interrupts=True):
        raise NotImplementedError()

    def resume(self):
        raise NotImplementedError()

    def massErase(self):
        raise NotImplementedError()

    def writeMemory(self, addr, value, transfer_size=32):
        raise NotImplementedError()

    # @brief Shorthand to write a 32-bit word.
    def write32(self, addr, value):
        self.writeMemory(addr, value, 32)

    # @brief Shorthand to write a 16-bit halfword.
    def write16(self, addr, value):
        self.writeMemory(addr, value, 16)

    # @brief Shorthand to write a byte.
    def write8(self, addr, value):
        self.writeMemory(addr, value, 8)

    def readMemory(self, addr, transfer_size=32, now=True):
        raise NotImplementedError()

    # @brief Shorthand to read a 32-bit word.
    def read32(self, addr, now=True):
        return self.readMemory(addr, 32, now)

    # @brief Shorthand to read a 16-bit halfword.
    def read16(self, addr, now=True):
        return self.readMemory(addr, 16, now)

    # @brief Shorthand to read a byte.
    def read8(self, addr, now=True):
        return self.readMemory(addr, 8, now)

    def writeBlockMemoryUnaligned8(self, addr, value):
        raise NotImplementedError()

    def writeBlockMemoryAligned32(self, addr, data):
        raise NotImplementedError()

    def readBlockMemoryUnaligned8(self, addr, size):
        raise NotImplementedError()

    def readBlockMemoryAligned32(self, addr, size):
        raise NotImplementedError()

    def readCoreRegister(self, id):
        raise NotImplementedError()

    def writeCoreRegister(self, id, data):
        raise NotImplementedError()

    def readCoreRegisterRaw(self, reg):
        raise NotImplementedError()

    def readCoreRegistersRaw(self, reg_list):
        raise NotImplementedError()

    def writeCoreRegisterRaw(self, reg, data):
        raise NotImplementedError()

    def writeCoreRegistersRaw(self, reg_list, data_list):
        raise NotImplementedError()

    def findBreakpoint(self, addr):
        raise NotImplementedError()

    def setBreakpoint(self, addr, type=BREAKPOINT_AUTO):
        raise NotImplementedError()

    def getBreakpointType(self, addr):
        raise NotImplementedError()

    def removeBreakpoint(self, addr):
        raise NotImplementedError()

    def setWatchpoint(self, addr, size, type):
        raise NotImplementedError()

    def removeWatchpoint(self, addr, size, type):
        raise NotImplementedError()

    def reset(self, software_reset=None):
        raise NotImplementedError()

    def resetStopOnReset(self, software_reset=None):
        raise NotImplementedError()

    def setTargetState(self, state):
        raise NotImplementedError()

    def getState(self):
        raise NotImplementedError()

    @property
    def run_token(self):
        return 0

    def isRunning(self):
        return self.getState() == Target.TARGET_RUNNING

    def isHalted(self):
        return self.getState() == Target.TARGET_HALTED

    def getMemoryMap(self):
        return self.memory_map

    def setVectorCatch(self, enableMask):
        raise NotImplementedError()

    def getVectorCatch(self):
        raise NotImplementedError()

    # GDB functions
    def getTargetXML(self):
        raise NotImplementedError()

    def getTargetContext(self, core=None):
        raise NotImplementedError()

    def getRootContext(self, core=None):
        raise NotImplementedError()

    def setRootContext(self, context, core=None):
        raise NotImplementedError()
