"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

from .target import Target
from ..coresight import (dap, ap, cortex_m)
from ..svd import (SVDFile, SVDLoader)
import threading
import logging
from xml.etree.ElementTree import (Element, SubElement, tostring)

##
# @brief Debug target that uses CoreSight classes.
class CoreSightTarget(Target):

    def __init__(self, link, memoryMap=None):
        super(CoreSightTarget, self).__init__(link, memoryMap)
        self.part_number = self.__class__.__name__
        self.cores = {}
        self.aps = {}
        self.dp = dap.DebugPort(link)
        self._selected_core = 0
        self._svd_load_thread = None

    @property
    def selected_core(self):
        return self.cores[self._selected_core]

    def select_core(self, num):
        if not self.cores.has_key(num):
            raise ValueError("invalid core number")
        logging.debug("selected core #%d" % num)
        self._selected_core = num

    @property
    ## @brief Waits for SVD file to complete loading before returning.
    def svd_device(self):
        if not self._svd_device and self._svd_load_thread:
            logging.debug("Waiting for SVD load to complete")
            self._svd_device = self._svd_load_thread.device
        return self._svd_device

    def loadSVD(self):
        def svdLoadCompleted(svdDevice):
            logging.debug("Completed loading SVD")
            self._svd_device = svdDevice
            self._svd_load_thread = None

        if not self._svd_device and self._svd_location:
            logging.debug("Started loading SVD")

            # Spawn thread to load SVD in background.
            self._svd_load_thread = SVDLoader(self._svd_location, svdLoadCompleted)
            self._svd_load_thread.load()

    def init(self, bus_accessible=True):
        # Start loading the SVD file
        self.loadSVD()

        # Create the DP and turn on debug.
        self.dp.init()
        self.dp.power_up_debug()

        # Create an AHB-AP for the CPU.
        self.aps[0] = ap.AHB_AP(self.dp, 0)
        self.aps[0].init(bus_accessible)

        # Create CortexM core.
        self.cores[0] = cortex_m.CortexM(self.link, self.dp, self.aps[0], self.memory_map)
        if bus_accessible:
            self.cores[0].init()

    def disconnect(self):
        for core in self.cores.values():
            core.disconnect()
        self.dp.power_down_debug()

    def readIDCode(self):
        return self.dp.dpidr

    def halt(self):
        return self.selected_core.halt()

    def step(self, disable_interrupts=True):
        return self.selected_core.step(disable_interrupts)

    def resume(self):
        return self.selected_core.resume()

    def writeMemory(self, addr, value, transfer_size=32):
        return self.selected_core.writeMemory(addr, value, transfer_size)

    def readMemory(self, addr, transfer_size=32, now=True):
        return self.selected_core.readMemory(addr, transfer_size, now)

    def writeBlockMemoryUnaligned8(self, addr, value):
        return self.selected_core.writeBlockMemoryUnaligned8(addr, value)

    def writeBlockMemoryAligned32(self, addr, data):
        return self.selected_core.writeBlockMemoryAligned32(addr, data)

    def readBlockMemoryUnaligned8(self, addr, size):
        return self.selected_core.readBlockMemoryUnaligned8(addr, size)

    def readBlockMemoryAligned32(self, addr, size):
        return self.selected_core.readBlockMemoryAligned32(addr, size)

    def readCoreRegister(self, id):
        return self.selected_core.readCoreRegister(id)

    def writeCoreRegister(self, id, data):
        return self.selected_core.writeCoreRegister(id, data)

    def readCoreRegisterRaw(self, reg):
        return self.selected_core.readCoreRegisterRaw(reg)

    def readCoreRegistersRaw(self, reg_list):
        return self.selected_core.readCoreRegistersRaw(reg_list)

    def writeCoreRegisterRaw(self, reg, data):
        self.selected_core.writeCoreRegisterRaw(reg, data)

    def writeCoreRegistersRaw(self, reg_list, data_list):
        self.selected_core.writeCoreRegistersRaw(reg_list, data_list)

    def findBreakpoint(self, addr):
        return self.selected_core.findBreakpoint(addr)

    def setBreakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        return self.selected_core.setBreakpoint(addr, type)

    def getBreakpointType(self, addr):
        return self.selected_core.getBreakpointType(addr)

    def removeBreakpoint(self, addr):
        return self.selected_core.removeBreakpoint(addr)

    def setWatchpoint(self, addr, size, type):
        return self.selected_core.setWatchpoint(addr, size, type)

    def removeWatchpoint(self, addr, size, type):
        return self.selected_core.removeWatchpoint(addr, size, type)

    def reset(self, software_reset=None):
        return self.selected_core.reset(software_reset=software_reset)

    def resetStopOnReset(self, software_reset=None):
        return self.selected_core.resetStopOnReset(software_reset)

    def setTargetState(self, state):
        return self.selected_core.setTargetState(state)

    def getState(self):
        return self.selected_core.getState()

    def getMemoryMap(self):
        return self.memory_map

    def setVectorCatchFault(self, enable):
        return self.selected_core.setVectorCatchFault(enable)

    def getVectorCatchFault(self):
        return self.selected_core.getVectorCatchFault()

    def setVectorCatchReset(self, enable):
        return self.selected_core.setVectorCatchReset(enable)

    def getVectorCatchReset(self):
        return self.selected_core.getVectorCatchReset()

    # GDB functions
    def getTargetXML(self):
        return self.selected_core.getTargetXML()

    def getRegisterContext(self):
        return self.selected_core.getRegisterContext()

    def setRegisterContext(self, data):
        return self.selected_core.setRegisterContext(data)

    def setRegister(self, reg, data):
        return self.selected_core.setRegister(reg, data)

    def getTResponse(self, forceSignal=None):
        return self.selected_core.getTResponse(forceSignal)

    def getSignalValue(self):
        return self.selected_core.getSignalValue()

    def getThreadsXML(self):
        root = Element('threads')
        t = SubElement(root, 'thread', id="1", core="0")
        t.text = "Thread mode"
        return '<?xml version="1.0"?><!DOCTYPE feature SYSTEM "threads.dtd">' + tostring(root)

