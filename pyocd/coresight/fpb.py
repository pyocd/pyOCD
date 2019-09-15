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

from ..core.target import Target
from .component import CoreSightComponent
from ..debug.breakpoints.provider import (Breakpoint, BreakpointProvider)
import logging

LOG = logging.getLogger(__name__)

class HardwareBreakpoint(Breakpoint):
    def __init__(self, comp_register_addr, provider):
        super(HardwareBreakpoint, self).__init__(provider)
        self.comp_register_addr = comp_register_addr
        self.type = Target.BreakpointType.HW

class FPB(BreakpointProvider, CoreSightComponent):
    """! @brief Flash Patch and Breakpoint unit"""
    
    # FPB registers
    #
    # The addresses are offsets from the base address.
    FP_CTRL = 0x00000000
    FP_CTRL_KEY = 1 << 1
    FP_CTRL_REV_MASK = 0xf0000000
    FP_CTRL_REV_SHIFT = 28
    FP_COMP0 = 0x00000008
    
    def __init__(self, ap, cmpid=None, addr=None):
        CoreSightComponent.__init__(self, ap, cmpid, addr)
        BreakpointProvider.__init__(self)
        self.hw_breakpoints = []
        self.nb_code = 0
        self.nb_lit = 0
        self.num_hw_breakpoint_used = 0
        self.enabled = False
        self.fpb_rev = 1

    @property
    def revision(self):
        return self.fpb_rev

    def init(self):
        """! @brief Inits the FPB.
        
        Reads the number of hardware breakpoints available on the core and disable the FPB
        (Flash Patch and Breakpoint Unit), which will be enabled when the first breakpoint is set.
        setup FPB (breakpoint)
        """
        fpcr = self.ap.read32(self.address + FPB.FP_CTRL)
        self.fpb_rev = 1 + ((fpcr & FPB.FP_CTRL_REV_MASK) >> FPB.FP_CTRL_REV_SHIFT)
        if self.fpb_rev not in (1, 2):
            LOG.warning("Unknown FPB version %d", self.fpb_rev)
        self.nb_code = ((fpcr >> 8) & 0x70) | ((fpcr >> 4) & 0xF)
        self.nb_lit = (fpcr >> 7) & 0xf
        LOG.info("%d hardware breakpoints, %d literal comparators", self.nb_code, self.nb_lit)
        for i in range(self.nb_code):
            self.hw_breakpoints.append(HardwareBreakpoint(self.address + FPB.FP_COMP0 + 4*i, self))

        # disable FPB (will be enabled on first bp set)
        self.disable()
        for bp in self.hw_breakpoints:
            self.ap.write_memory(bp.comp_register_addr, 0)

    @property
    def bp_type(self):
        return Target.BreakpointType.HW

    def enable(self):
        self.ap.write_memory(self.address + FPB.FP_CTRL, FPB.FP_CTRL_KEY | 1)
        self.enabled = True
        LOG.debug('fpb has been enabled')
        return

    def disable(self):
        self.ap.write_memory(self.address + FPB.FP_CTRL, FPB.FP_CTRL_KEY | 0)
        self.enabled = False
        LOG.debug('fpb has been disabled')
        return

    @property
    def available_breakpoints(self):
        return len(self.hw_breakpoints) - self.num_hw_breakpoint_used

    def can_support_address(self, addr):
        """! @brief Test whether an address is supported by the FPB.
        
        For FPBv1, hardware breakpoints are only supported in the range 0x00000000 - 0x1fffffff.
        This was fixed for FPBv2, which supports hardware breakpoints at any address.
        """
        return (self.fpb_rev == 2) or (addr < 0x20000000)

    def set_breakpoint(self, addr):
        """! @brief Set a hardware breakpoint at a specific location in flash."""
        if not self.enabled:
            self.enable()

        if not self.can_support_address(addr):
            LOG.error('Breakpoint out of range 0x%X', addr)
            return None

        if self.available_breakpoints == 0:
            LOG.error('No more hardware breakpoints are available, dropped breakpoint at 0x%08x', addr)
            return None

        for bp in self.hw_breakpoints:
            if not bp.enabled:
                bp.enabled = True
                comp = 0
                if self.fpb_rev == 1:
                    bp_match = (1 << 30)
                    if addr & 0x2:
                        bp_match = (2 << 30)
                    comp = addr & 0x1ffffffc | bp_match | 1
                elif self.fpb_rev == 2:
                    comp = (addr & 0xfffffffe) | 1
                self.ap.write32(bp.comp_register_addr, comp)
                LOG.debug("BP: wrote 0x%08x to comp @ 0x%08x", comp, bp.comp_register_addr)
                bp.addr = addr
                self.num_hw_breakpoint_used += 1
                return bp
        return None

    def remove_breakpoint(self, bp):
        """! @brief Remove a hardware breakpoint at a specific location in flash."""
        for hwbp in self.hw_breakpoints:
            if hwbp.enabled and hwbp.addr == bp.addr:
                hwbp.enabled = False
                self.ap.write_memory(hwbp.comp_register_addr, 0)
                self.num_hw_breakpoint_used -= 1
                return

