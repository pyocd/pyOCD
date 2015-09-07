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


class Target(object):

    TARGET_RUNNING = (1 << 0)
    TARGET_HALTED = (1 << 1)

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

    def __init__(self, transport, memoryMap=None):
        self.transport = transport
        self.flash = None
        self.part_number = ""
        self.memory_map = memoryMap
        self.halt_on_connect = True

    def setAutoUnlock(self, doAutoUnlock):
        pass

    def isLocked(self):
        return False

    def setHaltOnConnect(self, halt):
        self.halt_on_connect = halt

    def setFlash(self, flash):
        self.flash = flash

    def init(self):
        return

    def info(self, request):
        return

    def readIDCode(self):
        return

    def halt(self):
        return

    def step(self):
        return

    def resume(self):
        return

    def writeMemory(self, addr, value, transfer_size=32):
        return

    def readMemory(self, addr, transfer_size=32):
        return

    def writeBlockMemoryUnaligned8(self, addr, value):
        return

    def writeBlockMemoryAligned32(self, addr, data):
        return

    def readBlockMemoryUnaligned8(self, addr, size):
        return

    def readBlockMemoryAligned32(self, addr, size):
        return

    def readCoreRegister(self, id):
        return

    def writeCoreRegister(self, id):
        return

    def setBreakpoint(self, addr, type=BREAKPOINT_AUTO):
        return

    def getBreakpointType(self, addr):
        return

    def removeBreakpoint(self, addr):
        return

    def setWatchpoint(self, addr, size, type):
        return

    def removeWatchpoint(self, addr, size, type):
        return

    def reset(self):
        return

    def getState(self):
        return

    def getMemoryMap(self):
        return self.memory_map

    # GDB functions
    def getTargetXML(self):
        return ''

    def getMemoryMapXML(self):
        if self.memory_map:
            return self.memory_map.getXML()
        elif hasattr(self, 'memoryMapXML'):
            return self.memoryMapXML
        else:
            return None

    def getRegisterContext(self):
        return ''

    def setRegisterContext(self, data):
        return

    def setRegister(self, reg, data):
        return

    def getTResponse(self, gdbInterrupt=False):
        return ''
