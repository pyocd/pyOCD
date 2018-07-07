"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2017 ARM Limited

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

from ...core.target import Target
from ...pyDAPAccess import DAPAccess
import logging

##
# @brief
class BreakpointManager(object):
    ## Number of hardware breakpoints to try to keep available.
    MIN_HW_BREAKPOINTS = 0

    def __init__(self, core):
        self._breakpoints = {}
        self._core = core
        self._fpb = None
        self._providers = {}

    def add_provider(self, provider, type):
        self._providers[type] = provider
        if type == Target.BREAKPOINT_HW:
            self._fpb = provider

    def find_breakpoint(self, addr):
        return self._breakpoints.get(addr, None)

    ## @brief Set a hardware or software breakpoint at a specific location in memory.
    #
    # @retval True Breakpoint was set.
    # @retval False Breakpoint could not be set.
    def set_breakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        logging.debug("set bkpt type %d at 0x%x", type, addr)

        # Clear Thumb bit in case it is set.
        addr = addr & ~1

        in_hw_bkpt_range = addr < 0x20000000
        fbp_available = ((self._fpb is not None) and
                         (self._fpb.available_breakpoints() > 0))
        fbp_below_min = ((self._fpb is None) or
                         (self._fpb.available_breakpoints() <= self.MIN_HW_BREAKPOINTS))

        # Check for an existing breakpoint at this address.
        bp = self.find_breakpoint(addr)
        if bp is not None:
            return True

        if self._core.memory_map is None:
            # No memory map - fallback to hardware breakpoints.
            type = Target.BREAKPOINT_HW
            is_flash = False
            is_ram = False
        else:
            # Look up the memory type for the requested address.
            region = self._core.memory_map.getRegionForAddress(addr)
            if region is not None:
                is_flash = region.isFlash
                is_ram = region.isRam
            else:
                # No memory region - fallback to hardware breakpoints.
                type = Target.BREAKPOINT_HW
                is_flash = False
                is_ram = False

        # Determine best type to use if auto.
        if type == Target.BREAKPOINT_AUTO:
            # Use sw breaks for:
            #  1. Addresses outside the supported FPBv1 range of 0-0x1fffffff
            #  2. RAM regions by default.
            #  3. Number of remaining hw breaks are at or less than the minimum we want to keep.
            #
            # Otherwise use hw.
            if not in_hw_bkpt_range or is_ram or fbp_below_min:
                type = Target.BREAKPOINT_SW
            else:
                type = Target.BREAKPOINT_HW

            logging.debug("using type %d for auto bp", type)

        # Revert to sw bp if out of hardware breakpoint range.
        if (type == Target.BREAKPOINT_HW) and not in_hw_bkpt_range:
            if is_ram:
                logging.debug("using sw bp instead because of unsupported addr")
                type = Target.BREAKPOINT_SW
            else:
                logging.debug("could not fallback to software breakpoint")
                return False

        # Revert to hw bp if region is flash.
        if is_flash:
            if in_hw_bkpt_range and fbp_available:
                logging.debug("using hw bp instead because addr is flash")
                type = Target.BREAKPOINT_HW
            else:
                logging.debug("could not fallback to hardware breakpoint")
                return False

        # Set the bp.
        try:
            provider = self._providers[type]
            bp = provider.set_breakpoint(addr)
        except KeyError:
            raise RuntimeError("Unknown breakpoint type %d" % type)


        if bp is None:
            return False

        # Save the bp.
        self._breakpoints[addr] = bp
        return True

    ## @brief Remove a breakpoint at a specific location.
    def remove_breakpoint(self, addr):
        try:
            logging.debug("remove bkpt at 0x%x", addr)

            # Clear Thumb bit in case it is set.
            addr = addr & ~1

            # Get bp and remove from dict.
            bp = self._breakpoints.pop(addr)

            assert bp.provider is not None
            bp.provider.remove_breakpoint(bp)
        except KeyError:
            logging.debug("Tried to remove breakpoint 0x%08x that wasn't set" % addr)

    def get_breakpoint_type(self, addr):
        bp = self.find_breakpoint(addr)
        return bp.type if (bp is not None) else None

    def filter_memory(self, addr, size, data):
        for provider in [p for p in self._providers.values() if p.do_filter_memory]:
            data = provider.filter_memory(addr, size, data)
        return data

    def filter_memory_unaligned_8(self, addr, size, data):
        for provider in [p for p in self._providers.values() if p.do_filter_memory]:
            for i, d in enumerate(data):
                data[i] = provider.filter_memory(addr + i, 8, d)
        return data

    def filter_memory_aligned_32(self, addr, size, data):
        for provider in [p for p in self._providers.values() if p.do_filter_memory]:
            for i, d in enumerate(data):
                data[i] = provider.filter_memory(addr + i, 32, d)
        return data

    def remove_all_breakpoints(self):
        for bp in self._breakpoints.values():
            bp.provider.remove_breakpoint(bp)
        self._breakpoints = {}
        self._flush_all()

    def _flush_all(self):
        # Flush all providers.
        for provider in self._providers.values():
            provider.flush()

    def flush(self):
        try:
            # Flush all providers.
            self._flush_all()
        finally:
            pass

