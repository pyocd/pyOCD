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

LOG = logging.getLogger(__name__)

# Need a local copy to prevent circular import.
# Debug Exception and Monitor Control Register
DEMCR = 0xE000EDFC
# DWTENA in armv6 architecture reference manual
DEMCR_TRCENA = (1 << 24)

class Watchpoint(HardwareBreakpoint):
    def __init__(self, comp_register_addr, provider):
        super(Watchpoint, self).__init__(comp_register_addr, provider)
        self.addr = 0
        self.size = 0
        self.func = 0

class DWT(CoreSightComponent):
    """! @brief Data Watchpoint and Trace version 1.0"""
    
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
                            Target.WatchpointType.READ: 5,
                            Target.WatchpointType.WRITE: 6,
                            Target.WatchpointType.READ_WRITE: 7,
                            5: Target.WatchpointType.READ,
                            6: Target.WatchpointType.WRITE,
                            7: Target.WatchpointType.READ_WRITE,
                            }

    # Only sizes that are powers of 2 are supported
    # Breakpoint size = MASK**2
    WATCH_SIZE_TO_MASK = dict((2**i, i) for i in range(0,32))

    def __init__(self, ap, cmpid=None, addr=None):
        super(DWT, self).__init__(ap, cmpid, addr)
        self.watchpoints = []
        self.watchpoint_used = 0
        self.dwt_configured = False
    
    @property
    def watchpoint_count(self):
        return len(self.watchpoints)

    def init(self):
        """! @brief Inits the DWT.
        
        Reads the number of hardware watchpoints available on the core and makes sure that they
        are all disabled and ready for future use.
        """
        # Make sure trace is enabled.
        demcr = self.ap.read_memory(DEMCR)
        if (demcr & DEMCR_TRCENA) == 0:
            demcr |= DEMCR_TRCENA
            self.ap.write_memory(DEMCR, demcr)
        
        dwt_ctrl = self.ap.read_memory(self.address + self.DWT_CTRL)
        watchpoint_count = (dwt_ctrl & self.DWT_CTRL_NUM_COMP_MASK) >> self.DWT_CTRL_NUM_COMP_SHIFT
        LOG.info("%d hardware watchpoints", watchpoint_count)
        for i in range(watchpoint_count):
            comparatorAddress = self.address + self.DWT_COMP_BASE + self.DWT_COMP_BLOCK_SIZE * i
            self.watchpoints.append(Watchpoint(comparatorAddress, self))
            self.ap.write_memory(comparatorAddress + self.DWT_FUNCTION_OFFSET, 0)
        
        # Enable cycle counter.
        self.ap.write32(self.address + self.DWT_CTRL, self.DWT_CTRL_CYCCNTENA_MASK)
        self.dwt_configured = True

    def find_watchpoint(self, addr, size, type):
        for watch in self.watchpoints:
            if watch.addr == addr and watch.size == size and watch.func == self.WATCH_TYPE_TO_FUNCT[type]:
                return watch
        return None

    def set_watchpoint(self, addr, size, type):
        """! @brief Set a hardware watchpoint."""
        if self.dwt_configured is False:
            self.init()

        watch = self.find_watchpoint(addr, size, type)
        if watch is not None:
            return True

        if type not in self.WATCH_TYPE_TO_FUNCT:
            LOG.error("Invalid watchpoint type %i", type)
            return False

        for watch in self.watchpoints:
            if watch.func == 0:
                watch.addr = addr
                watch.func = self.WATCH_TYPE_TO_FUNCT[type]
                watch.size = size

                if size not in self.WATCH_SIZE_TO_MASK:
                    LOG.error('Watchpoint of size %d not supported by device', size)
                    return False

                mask = self.WATCH_SIZE_TO_MASK[size]
                self.ap.write_memory(watch.comp_register_addr + self.DWT_MASK_OFFSET, mask)
                if self.ap.read_memory(watch.comp_register_addr + self.DWT_MASK_OFFSET) != mask:
                    LOG.error('Watchpoint of size %d not supported by device', size)
                    return False

                self.ap.write_memory(watch.comp_register_addr, addr)
                self.ap.write_memory(watch.comp_register_addr + self.DWT_FUNCTION_OFFSET, watch.func)
                self.watchpoint_used += 1
                return True

        LOG.error('No more watchpoints are available, dropped watchpoint at 0x%08x', addr)
        return False

    def remove_watchpoint(self, addr, size, type):
        """! @brief Remove a hardware watchpoint."""
        watch = self.find_watchpoint(addr, size, type)
        if watch is None:
            return

        watch.func = 0
        self.ap.write_memory(watch.comp_register_addr + self.DWT_FUNCTION_OFFSET, 0)
        self.watchpoint_used -= 1
    
    def remove_all_watchpoints(self):
        for watch in self.watchpoints:
            if watch.func != 0:
                self.remove_watchpoint(watch.addr, watch.size, self.WATCH_TYPE_TO_FUNCT[watch.func])
    
    def get_watchpoints(self):
        return [watch for watch in self.watchpoints if watch.func != 0]
    
    @property
    def cycle_count(self):
        return self.ap.read32(self.address + self.DWT_CYCCNT)
    
    @cycle_count.setter
    def cycle_count(self, value):
        self.ap.write32(self.address + self.DWT_CYCCNT, value)

class DWTv2(DWT):
    """! @brief Data Watchpoint and Trace version 2.x
    
    This version is present in v8-M platforms.
    
    - DWT 2.0 appears in v8.0-M
    - DWT 2.1 appears in v8.1-M and adds the VMASKn registers.
    """
    
    DWT_ACTION_DEBUG_EVENT = 0x00000010
    
    ## Map from watchpoint type to FUNCTIONn.MATCH field value.
    WATCH_TYPE_TO_FUNCT = {
                            Target.WatchpointType.READ: 0b0110,
                            Target.WatchpointType.WRITE: 0b0101,
                            Target.WatchpointType.READ_WRITE: 0b0100,
                            0b0110: Target.WatchpointType.READ,
                            0b0101: Target.WatchpointType.WRITE,
                            0b0100: Target.WatchpointType.READ_WRITE,
                            }
    
    ## Map from data access size to pre-shifted DATAVSIZE field value.
    DATAVSIZE_MAP = {
                        1: (0 << 10),
                        2: (1 << 10),
                        4: (2 << 10),
                    }
    
    def set_watchpoint(self, addr, size, type):
        """! @brief Set a hardware watchpoint."""
        if self.dwt_configured is False:
            self.init()

        watch = self.find_watchpoint(addr, size, type)
        if watch is not None:
            return True

        if type not in self.WATCH_TYPE_TO_FUNCT:
            LOG.error("Invalid watchpoint type %i", type)
            return False
        
        # Only support sizes that can be handled with a single comparator.
        if size not in (1, 2, 4):
            LOG.error("Invalid watchpoint size %d", size)
            return False

        for watch in self.watchpoints:
            if watch.func == 0:
                watch.addr = addr
                watch.func = self.WATCH_TYPE_TO_FUNCT[type]
                watch.size = size

                # Build FUNCTIONn register value.
                value = self.DATAVSIZE_MAP[size] | self.DWT_ACTION_DEBUG_EVENT | watch.func

                self.ap.write_memory(watch.comp_register_addr, addr)
                self.ap.write_memory(watch.comp_register_addr + self.DWT_FUNCTION_OFFSET, value)
                self.watchpoint_used += 1
                return True

        LOG.error('No more watchpoints are available, dropped watchpoint at 0x%08x', addr)
        return False



