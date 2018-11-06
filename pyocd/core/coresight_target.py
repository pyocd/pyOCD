"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2018 ARM Limited

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
from ..coresight import (dap, cortex_m, rom_table)
from ..debug.svd import (SVDFile, SVDLoader)
from ..debug.context import DebugContext
from ..debug.cache import CachingDebugContext
from ..debug.elf.elf import ELFBinaryFile
from ..debug.elf.flash_reader import FlashReaderContext
from ..utility.notification import Notification
from ..utility.sequencer import CallSequence
import logging

##
# @brief Represents a chip that uses CoreSight debug infrastructure.
#
# An instance of this class is the root of the chip-level object graph. It has child
# nodes for the DP and all cores. As a concrete subclass of Target, it provides methods
# to control the device, access memory, adjust breakpoints, and so on.
#
# For single core devices, the CoreSightTarget has mostly equivalent functionality to
# the CortexM object for the core. Multicore devices work differently. This class tracks
# a "selected core", to which all actions are directed. The selected core can be changed
# at any time. You may also directly access specific cores and perform operations on them.
class CoreSightTarget(Target):

    def __init__(self, session, memoryMap=None):
        super(CoreSightTarget, self).__init__(session, memoryMap)
        self.root_target = self
        self.part_number = self.__class__.__name__
        self.cores = {}
        self.dp = dap.DebugPort(session.probe, self)
        self._selected_core = 0
        self._svd_load_thread = None
        self._root_contexts = {}
        self._new_core_num = 0
        self._elf = None
        self._irq_table = None

    @property
    def selected_core(self):
        return self.cores[self._selected_core]

    @property
    def elf(self):
        return self._elf

    @elf.setter
    def elf(self, filename):
        if filename is None:
            self._elf = None
        else:
            self._elf = ELFBinaryFile(filename, self.memory_map)
            self.cores[0].elf = self._elf
            self.cores[0].set_target_context(FlashReaderContext(self.cores[0].get_target_context(), self._elf))

    def select_core(self, num):
        if num not in self.cores:
            raise ValueError("invalid core number")
        logging.debug("selected core #%d" % num)
        self._selected_core = num

    @property
    def aps(self):
        return self.dp.aps

    @property
    ## @brief Waits for SVD file to complete loading before returning.
    def svd_device(self):
        if not self._svd_device and self._svd_load_thread:
            logging.debug("Waiting for SVD load to complete")
            self._svd_device = self._svd_load_thread.device
        return self._svd_device

    def load_svd(self):
        def svd_load_completed_cb(svdDevice):
#             logging.debug("Completed loading SVD")
            self._svd_device = svdDevice
            self._svd_load_thread = None

        if not self._svd_device and self._svd_location:
#             logging.debug("Started loading SVD")

            # Spawn thread to load SVD in background.
            self._svd_load_thread = SVDLoader(self._svd_location, svd_load_completed_cb)
            self._svd_load_thread.load()

    def add_core(self, core):
        core.halt_on_connect = self.halt_on_connect
        core.set_target_context(CachingDebugContext(DebugContext(core)))
        self.cores[core.core_number] = core
        self._root_contexts[core.core_number] = None

    def create_init_sequence(self):
        seq = CallSequence(
            ('load_svd',            self.load_svd),
            ('dp_init',             self.dp.init),
            ('power_up',            self.dp.power_up_debug),
            ('find_aps',            self.dp.find_aps),
            ('create_aps',          self.dp.create_aps),
            ('init_ap_roms',        self.dp.init_ap_roms),
            ('create_cores',        self.create_cores),
            ('create_components',   self.create_components),
            ('notify',              lambda : self.notify(Notification(event=Target.EVENT_POST_CONNECT, source=self)))
            )
        
        return seq
    
    def init(self):
        # Create and execute the init sequence.
        seq = self.create_init_sequence()
        seq.invoke()
    
    def _create_component(self, cmpid):
        cmp = cmpid.factory(cmpid.ap, cmpid, cmpid.address)
        cmp.init()

    def create_cores(self):
        self._new_core_num = 0
        self._apply_to_all_components(self._create_component, filter=lambda c: c.factory == cortex_m.CortexM.factory)

    def create_components(self):
        self._apply_to_all_components(self._create_component, filter=lambda c: c.factory is not None and c.factory != cortex_m.CortexM.factory)
    
    def _apply_to_all_components(self, action, filter=None):
        # Iterate over every top-level ROM table.
        for ap in [x for x in self.dp.aps.values() if x.has_rom_table]:
            ap.rom_table.for_each(action, filter)

    def disconnect(self, resume=True):
        self.notify(Notification(event=Target.EVENT_PRE_DISCONNECT, source=self))
        for core in self.cores.values():
            core.disconnect(resume)
        self.dp.power_down_debug()

    @property
    def run_token(self):
        return self.selected_core.run_token

    def halt(self):
        return self.selected_core.halt()

    def step(self, disable_interrupts=True):
        return self.selected_core.step(disable_interrupts)

    def resume(self):
        return self.selected_core.resume()

    def mass_erase(self):
        if self.flash is not None:
            self.flash.init()
            self.flash.erase_all()
            return True
        else:
            return False

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

    def read_core_register(self, reg):
        return self.selected_core.read_core_register(reg)

    def read_core_registers_raw(self, reg_list):
        return self.selected_core.read_core_registers_raw(reg_list)

    def write_core_register(self, reg, data):
        self.selected_core.write_core_register(reg, data)

    def write_core_registers_raw(self, reg_list, data_list):
        self.selected_core.write_core_registers_raw(reg_list, data_list)

    def find_breakpoint(self, addr):
        return self.selected_core.find_breakpoint(addr)

    def set_breakpoint(self, addr, type=Target.BREAKPOINT_AUTO):
        return self.selected_core.set_breakpoint(addr, type)

    def get_breakpoint_type(self, addr):
        return self.selected_core.get_breakpoint_type(addr)

    def remove_breakpoint(self, addr):
        return self.selected_core.remove_breakpoint(addr)

    def set_watchpoint(self, addr, size, type):
        return self.selected_core.set_watchpoint(addr, size, type)

    def remove_watchpoint(self, addr, size, type):
        return self.selected_core.remove_watchpoint(addr, size, type)

    def reset(self, software_reset=None):
        return self.selected_core.reset(software_reset=software_reset)

    def reset_stop_on_reset(self, software_reset=None):
        return self.selected_core.reset_stop_on_reset(software_reset)

    def set_target_state(self, state):
        return self.selected_core.set_target_state(state)

    def get_state(self):
        return self.selected_core.get_state()

    def get_memory_map(self):
        return self.memory_map

    def set_vector_catch(self, enableMask):
        return self.selected_core.set_vector_catch(enableMask)

    def get_vector_catch(self):
        return self.selected_core.get_vector_catch()

    # GDB functions
    def get_target_xml(self):
        return self.selected_core.get_target_xml()

    def get_target_context(self, core=None):
        if core is None:
            core = self._selected_core
        return self.cores[core].get_target_context()

    def get_root_context(self, core=None):
        if core is None:
            core = self._selected_core
        if self._root_contexts[core] is None:
            return self.get_target_context()
        else:
            return self._root_contexts[core]

    def set_root_context(self, context, core=None):
        if core is None:
            core = self._selected_core
        self._root_contexts[core] = context

    @property
    def irq_table(self):
        if self._irq_table is None:
            if self.svd_device is not None:
                self._irq_table = {i.value : i.name for i in
                    [i for p in self.svd_device.peripherals for i in p.interrupts]}
        return self._irq_table
        
        
