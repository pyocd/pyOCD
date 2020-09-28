# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import logging

from .target import Target
from ..flash.eraser import FlashEraser
from ..debug.cache import CachingDebugContext
from ..debug.elf.elf import ELFBinaryFile
from ..debug.elf.elf_reader import ElfReaderContext
from ..utility.graph import GraphNode
from ..utility.sequencer import CallSequence

LOG = logging.getLogger(__name__)

class SoCTarget(Target, GraphNode):
    """! @brief Represents a microcontroller system-on-chip.
    
    An instance of this class is the root of the chip-level object graph. It has child
    nodes for the DP and all cores. As a concrete subclass of Target, it provides methods
    to control the device, access memory, adjust breakpoints, and so on.
    
    For single core devices, the SoCTarget has mostly equivalent functionality to
    the Target object for the core. Multicore devices work differently. This class tracks
    a "selected core", to which all actions are directed. The selected core can be changed
    at any time. You may also directly access specific cores and perform operations on them.
    """
    
    VENDOR = "Generic"

    def __init__(self, session, memory_map=None):
        Target.__init__(self, session, memory_map)
        GraphNode.__init__(self)
        self.vendor = self.VENDOR
        self.part_families = getattr(self, 'PART_FAMILIES', [])
        self.part_number = getattr(self, 'PART_NUMBER', self.__class__.__name__)
        self._cores = {}
        self._selected_core = None
        self._new_core_num = 0
        self._elf = None

    @property
    def cores(self):
        return self._cores

    @property
    def selected_core(self):
        if self._selected_core is None:
            return None
        return self.cores[self._selected_core]
    
    @selected_core.setter
    def selected_core(self, core_number):
        if core_number not in self.cores:
            raise ValueError("invalid core number %d" % core_number)
        LOG.debug("selected core #%d" % core_number)
        self._selected_core = core_number

    @property
    def elf(self):
        return self._elf

    @elf.setter
    def elf(self, filename):
        if filename is None:
            self._elf = None
        else:
            self._elf = ELFBinaryFile(filename, self.memory_map)
            for core_number in range(len(self.cores)):
                self.cores[core_number].elf = self._elf
                if self.session.options['cache.read_code_from_elf']:
                    self.cores[core_number].set_target_context(
                            ElfReaderContext(self.cores[core_number].get_target_context(), self._elf))
    
    @property
    def supported_security_states(self):
        return self.selected_core.supported_security_states
    
    @property
    def core_registers(self):
        return self.selected_core.core_registers

    def add_core(self, core):
        core.delegate = self.delegate
        core.set_target_context(CachingDebugContext(core))
        self.cores[core.core_number] = core
        self.add_child(core)
        
        if self._selected_core is None:
            self._selected_core = core.core_number

    def create_init_sequence(self):
        # Return an empty call sequence. The subclass must override this.
        return CallSequence()
    
    def init(self):
        # If we don't have a delegate installed yet but there is a session delegate, use it.
        if (self.delegate is None) and (self.session.delegate is not None):
            self.delegate = self.session.delegate
        
        # Create and execute the init sequence.
        seq = self.create_init_sequence()
        self.call_delegate('will_init_target', target=self, init_sequence=seq)
        seq.invoke()
        self.call_delegate('did_init_target', target=self)
    
    def post_connect_hook(self):
        """! @brief Hook function called after post_connect init task.
        
        This hook lets the target subclass configure the target as necessary.
        """
        pass

    def disconnect(self, resume=True):
        self.session.notify(Target.Event.PRE_DISCONNECT, self)
        self.call_delegate('will_disconnect', target=self, resume=resume)
        for core in self.cores.values():
            core.disconnect(resume)
        self.dp.power_down_debug()
        self.call_delegate('did_disconnect', target=self, resume=resume)

    @property
    def run_token(self):
        return self.selected_core.run_token

    def halt(self):
        return self.selected_core.halt()

    def step(self, disable_interrupts=True, start=0, end=0, hook_cb=None):
        return self.selected_core.step(disable_interrupts, start, end, hook_cb)

    def resume(self):
        return self.selected_core.resume()

    def mass_erase(self):
        if not self.call_delegate('mass_erase', target=self):
            # The default mass erase implementation is to simply perform a chip erase.
            FlashEraser(self.session, FlashEraser.Mode.CHIP).erase()
        return True

    def write_memory(self, addr, value, transfer_size=32):
        return self.selected_core.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        return self.selected_core.read_memory(addr, transfer_size, now)

    def write_memory_block8(self, addr, value):
        return self.selected_core.write_memory_block8(addr, value)

    def write_memory_block32(self, addr, data):
        return self.selected_core.write_memory_block32(addr, data)

    def read_memory_block8(self, addr, size):
        return self.selected_core.read_memory_block8(addr, size)

    def read_memory_block32(self, addr, size):
        return self.selected_core.read_memory_block32(addr, size)

    def read_core_register(self, id):
        return self.selected_core.read_core_register(id)

    def write_core_register(self, id, data):
        return self.selected_core.write_core_register(id, data)

    def read_core_register_raw(self, reg):
        return self.selected_core.read_core_register_raw(reg)

    def read_core_registers_raw(self, reg_list):
        return self.selected_core.read_core_registers_raw(reg_list)

    def write_core_register_raw(self, reg, data):
        self.selected_core.write_core_register_raw(reg, data)

    def write_core_registers_raw(self, reg_list, data_list):
        self.selected_core.write_core_registers_raw(reg_list, data_list)

    def find_breakpoint(self, addr):
        return self.selected_core.find_breakpoint(addr)

    def set_breakpoint(self, addr, type=Target.BreakpointType.AUTO):
        return self.selected_core.set_breakpoint(addr, type)

    def get_breakpoint_type(self, addr):
        return self.selected_core.get_breakpoint_type(addr)

    def remove_breakpoint(self, addr):
        return self.selected_core.remove_breakpoint(addr)

    def set_watchpoint(self, addr, size, type):
        return self.selected_core.set_watchpoint(addr, size, type)

    def remove_watchpoint(self, addr, size, type):
        return self.selected_core.remove_watchpoint(addr, size, type)

    def reset(self, reset_type=None):
        # Perform a hardware reset if there is not a core.
        if self.selected_core is None:
            # Use the probe to reset if the DP doesn't exist yet.
            if self.dp is None:
                self.session.probe.reset()
            else:
                self.dp.reset()
            return
        self.selected_core.reset(reset_type)

    def reset_and_halt(self, reset_type=None):
        return self.selected_core.reset_and_halt(reset_type)

    def get_state(self):
        return self.selected_core.get_state()
        
    def get_security_state(self):
        return self.selected_core.get_security_state()

    def get_halt_reason(self):
        return self.selected_core.get_halt_reason()

    def set_vector_catch(self, enableMask):
        return self.selected_core.set_vector_catch(enableMask)

    def get_vector_catch(self):
        return self.selected_core.get_vector_catch()

    def get_target_context(self, core=None):
        if core is None:
            core = self._selected_core
        return self.cores[core].get_target_context()
    
    def trace_start(self):
        self.call_delegate('trace_start', target=self, mode=0)
    
    def trace_stop(self):
        self.call_delegate('trace_stop', target=self, mode=0)
    
        
