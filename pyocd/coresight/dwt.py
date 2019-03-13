# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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

from .fpb import HardwareBreakpoint
from ..core.target import Target
from .component import CoreSightComponent
import logging

# Need a local copy to prevent circular import.
# Debug Exception and Monitor Control Register
DEMCR = 0xE000EDFC
# DWTENA in armv6 architecture reference manual
DEMCR_TRCENA = (1 << 24)
DEMCR_VC_HARDERR = (1 << 10)
DEMCR_VC_BUSERR = (1 << 8)
DEMCR_VC_CORERESET = (1 << 0)

class Watchpoint(HardwareBreakpoint):
    def __init__(self, comp_register_addr, provider):
        super(Watchpoint, self).__init__(comp_register_addr, provider)
        self.addr = 0
        self.size = 0
        self.func = 0

class DWT(CoreSightComponent):
    """! @brief Data Watchpoint and Trace unit"""
    
    # DWT registers
    #
    # The addresses are offsets from the base address.
    DWT_CTRL = 0x00000000
    DWT_CYCCNT = 0x00000004
    DWT_CPICNT = 0x00000008
    DWT_EXCCNT = 0x0000000C
    DWT_SLEEPCNT = 0x00000010
    DWT_LSUCNT = 0x00000014
    DWT_FOLDCNT = 0x00000018
    DWT_PCSR = 0x0000001C
    DWT_COMP_BASE = 0x00000020
    DWT_MASK_OFFSET = 4
    DWT_FUNCTION_OFFSET = 8
    DWT_COMP_BLOCK_SIZE = 0x10
    
    DWT_CTRL_NUM_COMP_MASK = (0xF << 28)
    DWT_CTRL_NUM_COMP_SHIFT = 28
    DWT_CTRL_CYCEVTENA_MASK = (1 << 22)
    DWT_CTRL_FOLDEVTENA_MASK = (1 << 21)
    DWT_CTRL_LSUEVTENA_MASK = (1 << 20)
    DWT_CTRL_SLEEPEVTENA_MASK = (1 << 19)
    DWT_CTRL_EXCEVTENA_MASK = (1 << 18)
    DWT_CTRL_CPIEVTENA_MASK = (1 << 17)
    DWT_CTRL_EXCTRCENA_MASK = (1 << 16)
    DWT_CTRL_PCSAMPLENA_MASK = (1 << 12)
    DWT_CTRL_SYNCTAP_MASK = (0x3 << 10)
    DWT_CTRL_SYNCTAP_SHIFT = 10
    DWT_CTRL_CYCTAP_MASK = (1 << 9)
    DWT_CTRL_POSTINIT_MASK = (0xF << 5)
    DWT_CTRL_POSTINIT_SHIFT = 5
    DWT_CTRL_POSTRESET_MASK = (0xF << 1)
    DWT_CTRL_POSTRESET_SHIFT = 1
    DWT_CTRL_CYCCNTENA_MASK = (1 << 0)

    WATCH_TYPE_TO_FUNCT = {
                            Target.WATCHPOINT_READ: 5,
                            Target.WATCHPOINT_WRITE: 6,
                            Target.WATCHPOINT_READ_WRITE: 7,
                            5: Target.WATCHPOINT_READ,
                            6: Target.WATCHPOINT_WRITE,
                            7: Target.WATCHPOINT_READ_WRITE,
                            }

    # Only sizes that are powers of 2 are supported
    # Breakpoint size = MASK**2
    WATCH_SIZE_TO_MASK = dict((2**i, i) for i in range(0,32))

    def __init__(self, ap, cmpid=None, addr=None):
        super(DWT, self).__init__(ap, cmpid, addr)
        self.watchpoints = []
        self.watchpoint_used = 0
        self.dwt_configured = False

    ## @brief Inits the DWT.
    #
    # Reads the number of hardware watchpoints available on the core  and makes sure that they
    # are all disabled and ready for future use.
    def init(self):
        # Make sure trace is enabled.
        demcr = self.ap.read_memory(DEMCR)
        if (demcr & DEMCR_TRCENA) == 0:
            demcr |= DEMCR_TRCENA
            self.ap.write_memory(DEMCR, demcr)
        
        dwt_ctrl = self.ap.read_memory(self.address + DWT.DWT_CTRL)
        watchpoint_count = (dwt_ctrl & DWT.DWT_CTRL_NUM_COMP_MASK) >> DWT.DWT_CTRL_NUM_COMP_SHIFT
        logging.info("%d hardware watchpoints", watchpoint_count)
        for i in range(watchpoint_count):
            comparatorAddress = self.address + DWT.DWT_COMP_BASE + DWT.DWT_COMP_BLOCK_SIZE * i
            self.watchpoints.append(Watchpoint(comparatorAddress, self))
            self.ap.write_memory(comparatorAddress + DWT.DWT_FUNCTION_OFFSET, 0)
        
        # Enable cycle counter.
        self.ap.write32(self.address + DWT.DWT_CTRL, DWT.DWT_CTRL_CYCCNTENA_MASK)
        self.dwt_configured = True

    def find_watchpoint(self, addr, size, type):
        for watch in self.watchpoints:
            if watch.addr == addr and watch.size == size and watch.func == DWT.WATCH_TYPE_TO_FUNCT[type]:
                return watch
        return None

    ## @brief Set a hardware watchpoint.
    def set_watchpoint(self, addr, size, type):
        if self.dwt_configured is False:
            self.init()

        watch = self.find_watchpoint(addr, size, type)
        if watch != None:
            return True

        if type not in DWT.WATCH_TYPE_TO_FUNCT:
            logging.error("Invalid watchpoint type %i", type)
            return False

        for watch in self.watchpoints:
            if watch.func == 0:
                watch.addr = addr
                watch.func = DWT.WATCH_TYPE_TO_FUNCT[type]
                watch.size = size

                if size not in DWT.WATCH_SIZE_TO_MASK:
                    logging.error('Watchpoint of size %d not supported by device', size)
                    return False

                mask = DWT.WATCH_SIZE_TO_MASK[size]
                self.ap.write_memory(watch.comp_register_addr + DWT.DWT_MASK_OFFSET, mask)
                if self.ap.read_memory(watch.comp_register_addr + DWT.DWT_MASK_OFFSET) != mask:
                    logging.error('Watchpoint of size %d not supported by device', size)
                    return False

                self.ap.write_memory(watch.comp_register_addr, addr)
                self.ap.write_memory(watch.comp_register_addr + DWT.DWT_FUNCTION_OFFSET, watch.func)
                self.watchpoint_used += 1
                return True

        logging.error('No more available watchpoint!!, dropped watch at 0x%X', addr)
        return False

    ## @brief Remove a hardware watchpoint.
    def remove_watchpoint(self, addr, size, type):
        watch = self.find_watchpoint(addr, size, type)
        if watch is None:
            return

        watch.func = 0
        self.ap.write_memory(watch.comp_register_addr + DWT.DWT_FUNCTION_OFFSET, 0)
        self.watchpoint_used -= 1
    
    def remove_all_watchpoints(self):
        for watch in self.watchpoints:
            if watch.func != 0:
                self.remove_watchpoint(watch.addr, watch.size, DWT.WATCH_TYPE_TO_FUNCT[watch.func])
    
    @property
    def cycle_count(self):
        return self.ap.read32(self.address + DWT.DWT_CYCCNT)
    
    @cycle_count.setter
    def cycle_count(self, value):
        self.ap.write32(self.address + DWT.DWT_CYCCNT, value)

