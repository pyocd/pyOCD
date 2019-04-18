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

from .target import Target
from .memory_map import MemoryType
from . import exceptions
from ..flash.loader import FlashEraser
from ..coresight import (dap, cortex_m, cortex_m_v8m, rom_table)
from ..debug.svd.loader import (SVDFile, SVDLoader)
from ..debug.context import DebugContext
from ..debug.cache import CachingDebugContext
from ..debug.elf.elf import ELFBinaryFile
from ..debug.elf.flash_reader import FlashReaderContext
from ..utility.graph import GraphNode
from ..utility.notification import Notification
from ..utility.sequencer import CallSequence
from ..target.pack.flash_algo import PackFlashAlgo
import logging

# inspect.getargspec is deprecated in Python 3.
try:
    from inspect import getfullargspec as getargspec
except ImportError:
    from inspect import getargspec

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
class CoreSightTarget(Target, GraphNode):

    def __init__(self, session, memoryMap=None):
        Target.__init__(self, session, memoryMap)
        GraphNode.__init__(self)
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
    
    @selected_core.setter
    def selected_core(self, core_number):
        if core_number not in self.cores:
            raise ValueError("invalid core number %d" % core_number)
        logging.debug("selected core #%d" % core_number)
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
            self.cores[0].elf = self._elf
            self.cores[0].set_target_context(FlashReaderContext(self.cores[0].get_target_context(), self._elf))

    def select_core(self, num):
        """! @note Deprecated."""
        self.selected_core = num

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
        core.delegate = self.delegate
        core.set_target_context(CachingDebugContext(DebugContext(core)))
        self.cores[core.core_number] = core
        self.add_child(core)
        self._root_contexts[core.core_number] = None

    def create_init_sequence(self):
        seq = CallSequence(
            ('load_svd',            self.load_svd),
            ('create_flash',        self.create_flash),
            ('dp_init',             self.dp.init),
            ('power_up',            self.dp.power_up_debug),
            ('find_aps',            self.dp.find_aps),
            ('create_aps',          self.dp.create_aps),
            ('init_ap_roms',        self.dp.init_ap_roms),
            ('create_cores',        self.create_cores),
            ('create_components',   self.create_components),
            ('check_for_cores',     self.check_for_cores),
            ('notify',              lambda : self.notify(Notification(event=Target.EVENT_POST_CONNECT, source=self)))
            )
        
        return seq
    
    def init(self):
        # If we don't have a delegate installed yet but there is a session delegate, use it.
        if (self.delegate is None) and (self.session.delegate is not None):
            self.delegate = self.session.delegate
        
        # Create and execute the init sequence.
        seq = self.create_init_sequence()
        self.call_delegate('will_init_target', target=self, init_sequence=seq)
        seq.invoke()
        self.call_delegate('did_init_target', target=self)
    
    def create_flash(self):
        """! @brief Instantiates flash objects for memory regions.
        
        This init task iterates over flash memory regions and for each one creates the Flash
        instance. It uses the flash_algo and flash_class properties of the region to know how
        to construct the flash object.
        """
        for region in self.memory_map.get_regions_of_type(MemoryType.FLASH):
            # If a path to an FLM file was set on the region, examine it first.
            if region.flm is not None:
                flmPath = self.session.find_user_file(None, [region.flm])
                if flmPath is not None:
                    logging.info("creating flash algo from: %s", flmPath)
                    packAlgo = PackFlashAlgo(flmPath)
                    algo = packAlgo.get_pyocd_flash_algo(
                            max(s[1] for s in packAlgo.sector_sizes),
                            self.memory_map.get_first_region_of_type(MemoryType.RAM))
                
                    # If we got a valid algo from the FLM, set it on the region. This will then
                    # be used below.
                    if algo is not None:
                        region.algo = algo
                else:
                    logging.warning("Failed to find FLM file: %s", region.flm)
            
            # If the constructor of the region's flash class takes the flash_algo arg, then we
            # need the region to have a flash algo dict to pass to it. Otherwise we assume the
            # algo is built-in.
            klass = region.flash_class
            argspec = getargspec(klass.__init__)
            if 'flash_algo' in argspec.args:
                if region.algo is not None:
                    obj = klass(self, region.algo)
                else:
                    logging.warning("flash region '%s' has no flash algo" % region.name)
                    continue
            else:
                obj = klass(self)
            
            # Set the region in the flash instance.
            obj.region = region
            
            # Store the flash object back into the memory region.
            region.flash = obj
    
    def _create_component(self, cmpid):
        logging.debug("Creating %s component", cmpid.name)
        cmp = cmpid.factory(cmpid.ap, cmpid, cmpid.address)
        cmp.init()

    def create_cores(self):
        self._new_core_num = 0
        self._apply_to_all_components(self._create_component,
            filter=lambda c: c.factory in (cortex_m.CortexM.factory, cortex_m_v8m.CortexM_v8M.factory))

    def create_components(self):
        self._apply_to_all_components(self._create_component,
            filter=lambda c: c.factory is not None
                and c.factory not in (cortex_m.CortexM.factory, cortex_m_v8m.CortexM_v8M.factory))
    
    def _apply_to_all_components(self, action, filter=None):
        # Iterate over every top-level ROM table.
        for ap in [x for x in self.dp.aps.values() if x.has_rom_table]:
            ap.rom_table.for_each(action, filter)

    def check_for_cores(self):
        """! @brief Init task: verify that at least one core was discovered."""
        if not len(self.cores):
            # Allow the user to override the exception to enable uses like chip bringup.
            if self.session.options.get('allow_no_cores', False):
                logging.error("No cores were discovered!")
            else:
                raise exceptions.Error("No cores were discovered!")

    def disconnect(self, resume=True):
        self.notify(Notification(event=Target.EVENT_PRE_DISCONNECT, source=self))
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

    def step(self, disable_interrupts=True):
        return self.selected_core.step(disable_interrupts)

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

    def reset(self, reset_type=None):
        self.selected_core.reset(reset_type)

    def reset_and_halt(self, reset_type=None):
        return self.selected_core.reset_and_halt(reset_type)

    def get_state(self):
        return self.selected_core.get_state()

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

    def get_core_thread_provider(self, core=None):
        if core is None:
            core = self._selected_core
        return self.cores[core].get_core_thread_provider()

    @property
    def irq_table(self):
        if self._irq_table is None:
            if self.svd_device is not None:
                self._irq_table = {i.value : i.name for i in
                    [i for p in self.svd_device.peripherals for i in p.interrupts]}
        return self._irq_table
    
    def trace_start(self):
        self.call_delegate('trace_start', target=self, mode=0)
    
    def trace_stop(self):
        self.call_delegate('trace_stop', target=self, mode=0)
    
        
