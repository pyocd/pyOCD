# pyOCD debugger
# Copyright (c) 2016 Arm Limited
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
from .common import read_c_string
from ..core import exceptions
from ..core.target import Target
from ..coresight.cortex_m import CortexM
from ..debug.context import DebugContext
from ..debug.cortex_m_thread_provider import (ProcessStackThread, PSPThreadContext)
from ..debug.thread_provider import (TargetThread, ThreadProvider, RootThread)
import logging

# Create a logger for this module.
log = logging.getLogger("rtx5")

class TargetList(object):
    def __init__(self, context, ptr, nextOffset):
        self._context = context
        self._list = ptr
        self._offset = nextOffset

    def __iter__(self):
        # Read first item on list.
        node = self._context.read32(self._list)

        while node != 0:
            # Return previously read item.
            yield node

            try:
                # Read the next item in the list.
                node = self._context.read32(node + self._offset)
            except exceptions.TransferError as exc:
                log.warning("TransferError while reading list elements (list=0x%08x, node=0x%08x), terminating list: %s", self._list, node, exc)
                break

## @brief
class RTXThreadContext(DebugContext):
    # SP/PSP are handled specially, so it is not in these dicts.

    # Offsets are relative to stored SP in a task switch block, for the
    # combined software + hardware stacked registers.
    NOFPU_REGISTER_OFFSETS = {
                 # Software stacked
                 4: 0, # r4
                 5: 4, # r5
                 6: 8, # r6
                 7: 12, # r7
                 8: 16, # r8
                 9: 20, # r9
                 10: 24, # r10
                 11: 28, # r11
                 # Hardware stacked
                 0: 32, # r0
                 1: 36, # r1
                 2: 40, # r2
                 3: 44, # r3
                 12: 48, # r12
                 14: 52, # lr
                 15: 56, # pc
                 16: 60, # xpsr
            }

    FPU_REGISTER_OFFSETS = {
                 # Software stacked
                 0x50: 0, # s16
                 0x51: 4, # s17
                 0x52: 8, # s18
                 0x53: 12, # s19
                 0x54: 16, # s20
                 0x55: 20, # s21
                 0x56: 24, # s22
                 0x57: 28, # s23
                 0x58: 32, # s24
                 0x59: 36, # s25
                 0x5a: 40, # s26
                 0x5b: 44, # s27
                 0x5c: 48, # s28
                 0x5d: 52, # s29
                 0x5e: 56, # s30
                 0x5f: 60, # s31
                 4: 64, # r4
                 5: 68, # r5
                 6: 72, # r6
                 7: 76, # r7
                 8: 80, # r8
                 9: 84, # r9
                 10: 88, # r10
                 11: 92, # r11
                 # Hardware stacked
                 0: 96, # r0
                 1: 100, # r1
                 2: 104, # r2
                 3: 108, # r3
                 12: 112, # r12
                 14: 116, # lr
                 15: 120, # pc
                 16: 124, # xpsr
                 0x40: 128, # s0
                 0x41: 132, # s1
                 0x42: 136, # s2
                 0x43: 140, # s3
                 0x44: 144, # s4
                 0x45: 148, # s5
                 0x46: 152, # s6
                 0x47: 156, # s7
                 0x48: 160, # s8
                 0x49: 164, # s9
                 0x4a: 168, # s10
                 0x4b: 172, # s11
                 0x4c: 176, # s12
                 0x4d: 180, # s13
                 0x4e: 184, # s14
                 0x4f: 188, # s15
                 33: 192, # fpscr
                 # (reserved word: 196)
            }

    def __init__(self, parentContext, thread):
        super(RTXThreadContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._thread = thread
        self._has_fpu = parentContext.core.has_fpu

    def read_core_registers_raw(self, reg_list):
        reg_list = [self.core.register_name_to_index(reg) for reg in reg_list]

        sp = self._thread.get_stack_pointer()

        # Determine which register offset table to use and the offsets past the saved state.
        stacked = 0x40
        table = self.NOFPU_REGISTER_OFFSETS
        if self._has_fpu and not self._thread.get_exc_return_ftype():
            table = self.FPU_REGISTER_OFFSETS
            stacked = 0xC8

        return self._do_read_regs_in_memory(reg_list, [(sp, table)], { 13: sp + stacked } )

    def write_core_registers_raw(self, reg_list, data_list):
        self._parent.write_core_registers_raw(reg_list, data_list)

## @brief Base class representing a thread on the target.
class RTXTargetThread(TargetThread):
    STATE_OFFSET = 1
    NAME_OFFSET = 4
    PRIORITY_OFFSET = 33
    STACKFRAME_OFFSET = 34
    SP_OFFSET = 56

    STATES = {
         0x00: "Inactive",
         0x01: "Ready",
         0x02: "Running",
         0x03: "Blocked",
         0x04: "Terminated",
         0x13: "Waiting[Delay]",
         0x23: "Waiting[Join]",
         0x33: "Waiting[ThrFlg]",
         0x43: "Waiting[EvtFlg]",
         0x53: "Waiting[Mutex]",
         0x63: "Waiting[Sem]",
         0x73: "Waiting[MemPool]",
         0x83: "Waiting[MsgGet]",
         0x93: "Waiting[MsgPut]",
    }
    
    def __init__(self, targetContext, provider, base):
        super(RTXTargetThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._base = base
        self._state = 0
        self._priority = 0
        self._rtx_context = RTXThreadContext(self._target_context, self)
        self._psp_context = PSPThreadContext(self._target_context, self)
        self._has_fpu = self._target_context.core.has_fpu
        try:
            name_ptr = self._target_context.read32(self._base + RTXTargetThread.NAME_OFFSET)
            self._name = read_c_string(self._target_context, name_ptr)
            
            self.update_state()
        except exceptions.TransferError as exc:
            log.debug("Transfer error while reading thread %x name: %s", self._base, exc)
            self._name = "?"
        log.debug('RTXTargetThread 0x%x' % base)
    
    def update_state(self):
        try:
            state = self._target_context.read8(self._base + RTXTargetThread.STATE_OFFSET)
            priority = self._target_context.read8(self._base + RTXTargetThread.PRIORITY_OFFSET)
        except exceptions.TransferError as exc:
            log.debug("Transfer error while reading thread %x state: %s", self._base, exc)
        else:
            self._state = state
            self._priority = priority

    @property
    def priority(self):
        return self._priority

    @property
    def unique_id(self):
        # There is no other meaningful ID than base address
        return self._base

    @property
    def context(self):
        if self.is_current:
            return self._psp_context
        else:
            return self._rtx_context

    @property
    def description(self):
        return "%s; Priority %d" % (self.STATES[self._state], self.priority)

    @property
    def name(self):
        return self._name

    @property
    def is_current(self):
        return self._provider.get_actual_current_thread_id() == self._base

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        try:
            return self._target_context.read32(self._base + RTXTargetThread.SP_OFFSET)
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread's stack pointer @ 0x%08x", self._base + RTXTargetThread.SP_OFFSET)
            return 0

    def get_exc_return_ftype(self):
        try:
            return bool(self._target_context.read8(self._base + RTXTargetThread.STACKFRAME_OFFSET) & CortexM.EXC_RETURN_FTYPE)
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread's stack frame @ 0x%08x", self._base + RTXTargetThread.STACKFRAME_OFFSET)
            return True

## @brief Thread provider for RTX5 RTOS.
class RTX5ThreadProvider(ThreadProvider):
    # Offsets in osRtxInfo_t
    KERNEL_STATE_OFFSET = 8
    CURRENT_OFFSET = 20
    THREADLIST_OFFSET = 36
    DELAYLIST_OFFSET = 44
    WAITLIST_OFFSET = 48

    # Offset in osRtxThread_t
    THREADNEXT_OFFSET = 8
    DELAYNEXT_OFFSET = 16

    def __init__(self, target, parent):
        super(RTX5ThreadProvider, self).__init__(target, parent)

    def init(self, symbolProvider):
        # Lookup required symbols.
        # return False
        self._os_rtx_info = symbolProvider.get_symbol_value('osRtxInfo')
        if self._os_rtx_info is None:
            return False
        log.debug('osRtxInfo = 0x%08x', self._os_rtx_info)
        self._readylist = self._os_rtx_info + RTX5ThreadProvider.THREADLIST_OFFSET
        self._delaylist = self._os_rtx_info + RTX5ThreadProvider.DELAYLIST_OFFSET
        self._waitlist = self._os_rtx_info + RTX5ThreadProvider.WAITLIST_OFFSET
        self._threads = self._parent.threads
        self._current = None
        self._current_id = None
        self._target.root_target.subscribe(Target.EVENT_POST_FLASH_PROGRAM, self.event_handler)
        self._target.subscribe(Target.EVENT_POST_RESET, self.event_handler)
        self._psp_context = PSPThreadContext(self._target_context)
        return True
        
    @property
    def threads(self):
        self.update_threads()
        return self._threads

    def invalidate(self):
        self._parent.invalidate()
        self._threads = self._parent.threads

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        self.invalidate();

    def _build_thread_list(self):
        if not self.is_enabled:
            self._threads = self._parent.threads
            return

        newThreads = self._parent.threads.copy()

        def create_or_update(thread):
            # Check for and reuse existing thread.
            if thread in self._threads:
                # Thread already exists, update its state.
                t = self._threads[thread]
                t.update_state()
            else:
                # Create a new thread.
                t = RTXTargetThread(self._target_context, self, thread)
            newThreads[t.unique_id] = t

        # Currently running Thread
        thread = self._target_context.read32(self._os_rtx_info + RTX5ThreadProvider.CURRENT_OFFSET)
        if thread:
            create_or_update(thread)
            self._current_id = thread
            self._current = newThreads[thread]
            # Our current thread replaces the PSP thread from CortexMThreadProvider
            newThreads.pop(ProcessStackThread.UNIQUE_ID, None)
            # Our current thread replaces the root thread, if on PSP stack
            if (self.get_current_stack_pointer_id() == CortexM.PSP):
                newThreads.pop(RootThread.UNIQUE_ID, None)
        else:
            self._current_id = None
            self._current = None

        # List of target thread lists to examine.
        threadLists = [
            TargetList(self._target_context, self._readylist, RTX5ThreadProvider.THREADNEXT_OFFSET),
            TargetList(self._target_context, self._delaylist, RTX5ThreadProvider.DELAYNEXT_OFFSET),
            TargetList(self._target_context, self._waitlist, RTX5ThreadProvider.DELAYNEXT_OFFSET),
            ]

        # Scan thread lists.
        for theList in threadLists:
            for thread in theList:
                create_or_update(thread)

        self._threads = newThreads

    @property
    def is_enabled(self):
        if self._os_rtx_info is None:
            return False
        try:
            # If we're in Thread mode on the main stack, can't be active, even
            # if kernel state says we are (eg post reset)
            return self.get_kernel_state() != 0 and not self._target.in_thread_mode_on_main_stack()
        except exceptions.TransferError as exc:
            log.debug("Transfer error checking if enabled: %s", exc)
            return False

    def get_actual_current_thread_id(self):
        if not self.is_enabled:
            return None
        self.update_threads()
        return self._current_id

    def get_current_thread_id_for_stack(self, stack_id):
        if stack_id == CortexM.PSP:
            return self.get_actual_current_thread_id()
        else:
            return None

    def get_kernel_state(self):
        return self._target_context.read8(self._os_rtx_info + RTX5ThreadProvider.KERNEL_STATE_OFFSET)
