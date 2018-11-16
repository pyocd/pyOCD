# pyOCD debugger
# Copyright (c) 2006-2019 Arm Limited
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

#
# Cortex-M Thread support
#

from ..core.target import Target
from .context import DebugContext
from .thread_provider import (TargetThread, ThreadProvider)
from ..coresight.cortex_m import CortexM
import logging

## @brief Class representing the handler mode.
class MainStackThread(TargetThread):
    UNIQUE_ID = 2

    def __init__(self, targetContext, provider):
        super(MainStackThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider

    @property
    def priority(self):
        return 0

    @property
    def unique_id(self):
        return self.UNIQUE_ID

    @property
    def name(self):
        return "MSP"

    @property
    def description(self):
        ipsr = self._target_context.read_core_register('ipsr');
        return self._target_context.core.exception_number_to_name(ipsr, name_thread=True)

    @property
    def context(self):
        return self._target_context

    def __str__(self):
        return "<MainStackThread@0x%08x>" % (id(self))

    def __repr__(self):
        return str(self)

class PSPThreadContext(DebugContext):
    # SP/PSP are handled specially, so it is not in these dicts.

    NOFPU_REGISTER_OFFSETS = {
                 # Hardware stacked
                 0: 0, # r0
                 1: 4, # r1
                 2: 8, # r2
                 3: 12, # r3
                 12: 16, # r12
                 14: 20, # lr
                 15: 24, # pc
                 16: 28, # xpsr
            }

    FPU_REGISTER_OFFSETS = {
                 # Hardware stacked
                 0: 0, # r0
                 1: 4, # r1
                 2: 8, # r2
                 3: 12, # r3
                 12: 16, # r12
                 14: 20, # lr
                 15: 24, # pc
                 16: 28, # xpsr
                 0x40: 32, # s0
                 0x41: 36, # s1
                 0x42: 40, # s2
                 0x43: 44, # s3
                 0x44: 48, # s4
                 0x45: 52, # s5
                 0x46: 56, # s6
                 0x47: 60, # s7
                 0x48: 64, # s8
                 0x49: 68, # s9
                 0x4a: 72, # s10
                 0x4b: 76, # s11
                 0x4c: 80, # s12
                 0x4d: 84, # s13
                 0x4e: 88, # s14
                 0x4f: 92, # s15
                 33: 96, # fpscr
                 # (reserved word: 100)
            }

    # Thread is only set if we are backing a real RTOS thread - it's not
    # set by ProcessStackThread
    def __init__(self, parentContext, thread=None):
        super(PSPThreadContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._thread = thread
        self._has_fpu = parentContext.core.has_fpu

    def read_core_registers_raw(self, reg_list):

        inException = self._parent.read_core_register('ipsr') > 0

        # If we're not in an exception, just read the live registers.
        if not inException:
            return self._parent.read_core_registers_raw(reg_list)

        sp = self._parent.read_core_register('psp')

        reg_list = [self.core.register_name_to_index(reg) for reg in reg_list]
        reg_vals = []

        # Determine which register offset table to use and the offsets past the saved state.
        stacked = 0x20
        table = self.NOFPU_REGISTER_OFFSETS
        if self._has_fpu:
            try:
                # Check bit 4 of the exception LR to determine if FPU registers were stacked.
                ftype = None

                if self._thread is not None and not self._parent.core.is_vector_catch():
                    # If not at vector catch, we'll take any guess someone can
                    # give us, such as an LR stored from a previous task switch
                    ftype = self._thread.get_exc_return_ftype()

                if ftype is None:
                    # This may well not be live, but will at least be at instant of vector entry.
                    ftype = bool(self._parent.read_core_register('lr') & CortexM.EXC_RETURN_FTYPE)

                if not ftype:
                    table = self.FPU_REGISTER_OFFSETS
                    stacked = 0x68
            except exceptions.TransferError:
                logging.debug("Transfer error while reading thread's saved LR")

        for reg in reg_list:

            # Must handle stack pointer specially.
            if reg == 13:
                reg_vals.append(sp + stacked)
                continue

            # Look up offset for this register on the stack.
            spOffset = table.get(reg, None)
            if spOffset is None:
                reg_vals.append(self._parent.read_core_register_raw(reg))
                continue

            try:
                reg_vals.append(self._parent.read32(sp + spOffset))
            except exceptions.TransferError:
                reg_vals.append(0)

        return reg_vals

    def write_core_registers_raw(self, reg_list, data_list):
        self._parent.write_core_registers_raw(reg_list, data_list)

## @brief Class representing the thread mode.
class ProcessStackThread(TargetThread):
    UNIQUE_ID = 3

    def __init__(self, targetContext, provider):
        super(ProcessStackThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._thread_context = PSPThreadContext(self._target_context)

    @property
    def priority(self):
        return 0

    @property
    def unique_id(self):
        return self.UNIQUE_ID

    @property
    def name(self):
        return "PSP"

    @property
    def description(self):
        return None

    @property
    def context(self):
        return self._thread_context

    def __str__(self):
        return "<ProcessStackThread@0x%08x>" % (id(self))

    def __repr__(self):
        return str(self)

## @brief Thread provider for bare ARM M-profile.
class CortexMThreadProvider(ThreadProvider):

    # Unlike RTOS providers, we do everything in __init__ - our needs are few
    def __init__(self, target, parent):
        super(CortexMThreadProvider, self).__init__(target, parent)
        self._threads = self._parent.threads
        self._psp_in_use = False
        self._current = None
        self._current_id = None
        self._target.subscribe(Target.EVENT_POST_RESET, self.event_handler)
        self._main_thread = MainStackThread(self._target_context, self)
        self._process_thread = ProcessStackThread(self._target_context, self)

    def invalidate(self):
        self._psp_in_use = False
        self._build_thread_list()

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        self.invalidate();

    def _build_thread_list(self):
        sp = self._target_context.read_core_register('sp')
        msp = self._target_context.read_core_register('msp')
        psp = self._target_context.read_core_register('psp')

        if False or sp not in (msp, psp):
            self._current_id = None
        elif (self._target_context.read_core_register('ipsr') == 0 and
                (self._target_context.read_core_register('control') & CortexM.CONTROL_SPSEL)):
            self._current_id = CortexM.PSP
        else:
            self._current_id = CortexM.MSP

        if self._current_id is None:
            # Something weird is happening - keep the root thread to show it
            self._threads = self._parent.threads.copy()
        else:
            # Under normal circumstances we totally replace the root
            self._threads = {}

        # Include main thread only if it is active - matches previous RTOS
        # providers.
        if self._current_id is not CortexM.PSP:
            self._threads[self._main_thread.unique_id] = self._main_thread

        # Original idea was to show this thread only the first time we need
        # to (not on MainStack), but if our first stop is in the Main stack,
        # we'd miss it. So this effectively shows it all the time, unless PSP
        # is 0. PSP on boot is architecturally undefined, but code could choose
        # to manually set it to 0.
        if self._psp_in_use or self._current_id is not CortexM.MSP or psp != 0:
            self._threads[self._process_thread.unique_id] = self._process_thread
            self._psp_in_use = True
        elif psp == 0:
            self._psp_in_use = False

    @property
    def threads(self):
        self.update_threads()
        return self._threads

    @property
    def read_from_target(self):
        return True

    @read_from_target.setter
    def read_from_target(self, value):
        pass

    @property
    def is_enabled(self):
        return True

    def get_current_stack_pointer_id(self):
        self.update_threads()
        return self._current_id

    def get_current_thread_id_for_stack(self, stack_id):
        if stack_id == CortexM.PSP:
            return ProcessStackThread.UNIQUE_ID
        elif stack_id == CortexM.MSP:
            return MainStackThread.UNIQUE_ID
        else:
            return None
