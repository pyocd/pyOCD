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

from .provider import (Breakpoint, BreakpointProvider)
from ...core import exceptions
from ...core.target import Target
import logging

LOG = logging.getLogger(__name__)

class SoftwareBreakpoint(Breakpoint):
    def __init__(self, provider):
        super(SoftwareBreakpoint, self).__init__(provider)
        self.type = Target.BreakpointType.SW

class SoftwareBreakpointProvider(BreakpointProvider):
    ## BKPT #0 instruction.
    BKPT_INSTR = 0xbe00

    def __init__(self, core):
        super(SoftwareBreakpointProvider, self).__init__()
        self._core = core
        self._breakpoints = {}

    def init(self):
        pass

    @property
    def bp_type(self):
        return Target.BreakpointType.SW

    @property
    def do_filter_memory(self):
        return True

    @property
    def available_breakpoints(self):
        return -1

    def find_breakpoint(self, addr):
        return self._breakpoints.get(addr, None)

    def set_breakpoint(self, addr):
        assert self._core.memory_map.get_region_for_address(addr).is_ram
        assert (addr & 1) == 0

        try:
            # Read original instruction.
            instr = self._core.read16(addr)

            # Insert BKPT #0 instruction.
            self._core.write16(addr, self.BKPT_INSTR)

            # Create bp object.
            bp = SoftwareBreakpoint(self)
            bp.enabled = True
            bp.addr = addr
            bp.original_instr = instr

            # Save this breakpoint.
            self._breakpoints[addr] = bp
            return bp
        except exceptions.TransferError:
            LOG.debug("Failed to set sw bp at 0x%x" % addr)
            return None

    def remove_breakpoint(self, bp):
        assert bp is not None and isinstance(bp, Breakpoint)

        try:
            # Restore original instruction.
            self._core.write16(bp.addr, bp.original_instr)

            # Remove from our list.
            del self._breakpoints[bp.addr]
        except exceptions.TransferError:
            LOG.debug("Failed to remove sw bp at 0x%x" % bp.addr)

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



