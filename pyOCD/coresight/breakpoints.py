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

from ..target.target import Target
from ..pyDAPAccess import DAPAccess
import logging

class Breakpoint(object):
    def __init__(self, comp_register_addr, provider):
        self.type = Target.BREAKPOINT_HW
        self.comp_register_addr = comp_register_addr
        self.enabled = False
        self.addr = 0
        self.original_instr = 0
        self.provider = provider

class Watchpoint(Breakpoint):
    def __init__(self, comp_register_addr, provider):
        super(Watchpoint, self).__init__(comp_register_addr, provider)
        self.addr = 0
        self.size = 0
        self.func = 0

## @brief Abstract base class for breakpoint providers.
class BreakpointProvider(object):
    def init(self):
        raise NotImplementedError()

    def bp_type(self):
        return 0

    def available_breakpoints(self):
        raise NotImplementedError()

    def find_breakpoint(self, addr):
        raise NotImplementedError()

    def set_breakpoint(self, addr):
        raise NotImplementedError()

    def remove_breakpoint(self, bp):
        raise NotImplementedError()

class SoftwareBreakpointProvider(BreakpointProvider):
    ## BKPT #0 instruction.
    BKPT_INSTR = 0xbe00

    def __init__(self, core):
        self._core = core
        self._breakpoints = {}

    def init(self):
        pass

    def bp_type(self):
        return Target.BREAKPOINT_SW

    def available_breakpoints(self):
        return -1

    def find_breakpoint(self, addr):
        return self._breakpoints.get(addr, None)

    def set_breakpoint(self, addr):
        assert self._core.memory_map.getRegionForAddress(addr).isRam
        assert (addr & 1) == 0

        try:
            # Read original instruction.
            instr = self._core.read16(addr)

            # Insert BKPT #0 instruction.
            self._core.write16(addr, self.BKPT_INSTR)

            # Create bp object.
            bp = Breakpoint(0, self)
            bp.type = Target.BREAKPOINT_SW
            bp.enabled = True
            bp.addr = addr
            bp.original_instr = instr

            # Save this breakpoint.
            self._breakpoints[addr] = bp
            return bp
        except DAPAccess.TransferError:
            logging.debug("Failed to set sw bp at 0x%x" % addr)
            return None

    def remove_breakpoint(self, bp):
        assert bp is not None and isinstance(bp, Breakpoint)

        try:
            # Restore original instruction.
            self._core.write16(bp.addr, bp.original_instr)

            # Remove from our list.
            del self._breakpoints[bp.addr]
        except DAPAccess.TransferError:
            logging.debug("Failed to set sw bp at 0x%x" % bp.addr)

    def filter_memory(self, addr, size, data):
        for bp in self._breakpoints.values():
            if size == 8:
                if bp.addr == addr:
                    data = bp.original_instr & 0xff
                elif bp.addr + 1 == addr:
                    data = bp.original_instr >> 8
            elif size == 16:
                if bp.addr == addr:
                    data = bp.original_instr
            elif size == 32:
                if bp.addr == addr:
                    data = (data & 0xffff0000) | bp.original_instr
                elif bp.addr == addr + 2:
                    data = (data & 0xffff) | (bp.original_instr << 16)

        return data

class BreakpointManager(object):
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

        # Determine best type to use if auto.
        if type == Target.BREAKPOINT_AUTO:
            # Use sw breaks for:
            #  1. Addresses outside the supported FPBv1 range of 0-0x1fffffff
            #  2. RAM regions by default.
            #  3. No hw breaks are left.
            #
            # Otherwise use hw.
            if not in_hw_bkpt_range or is_ram or fbp_available:
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
        if Target.BREAKPOINT_SW in self._providers:
            data = self._providers[Target.BREAKPOINT_SW].filter_memory(addr, size, data)
        return data

    def filter_memory_unaligned_8(self, addr, size, data):
        if Target.BREAKPOINT_SW in self._providers:
            sw_bp = self._providers[Target.BREAKPOINT_SW]
            for i, d in enumerate(data):
                data[i] = sw_bp.filter_memory(addr + i, 8, d)
        return data

    def filter_memory_aligned_32(self, addr, size, data):
        if Target.BREAKPOINT_SW in self._providers:
            sw_bp = self._providers[Target.BREAKPOINT_SW]
            for i, d in enumerate(data):
                data[i] = sw_bp.filter_memory(addr + i, 32, d)
        return data

    def remove_all_breakpoints(self):
        for bp in self._breakpoints.values():
            bp.provider.remove_breakpoint(bp)
        self._breakpoints = {}

