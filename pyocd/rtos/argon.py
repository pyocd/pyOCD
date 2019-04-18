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
from ..trace import events
from ..trace.sink import TraceEventFilter
import logging

KERNEL_FLAGS_OFFSET = 0x1c
IS_RUNNING_MASK = 0x1

ALL_OBJECTS_THREADS_OFFSET = 0

THREAD_STACK_POINTER_OFFSET = 0
THREAD_EXTENDED_FRAME_OFFSET = 4
THREAD_NAME_OFFSET = 8
THREAD_STACK_BOTTOM_OFFSET = 12
THREAD_PRIORITY_OFFSET = 16
THREAD_STATE_OFFSET = 17
THREAD_CREATED_NODE_OFFSET = 36

LIST_NODE_NEXT_OFFSET = 0
LIST_NODE_OBJ_OFFSET= 8

# Create a logger for this module.
log = logging.getLogger("argon")

class TargetList(object):
    def __init__(self, context, ptr):
        self._context = context
        self._list = ptr

    def __iter__(self):
        next = 0
        head = self._context.read32(self._list)
        node = head
        is_valid = head != 0

        while is_valid and next != head:
            try:
                # Read the object from the node.
                obj = self._context.read32(node + LIST_NODE_OBJ_OFFSET)
                yield obj

                next = self._context.read32(node + LIST_NODE_NEXT_OFFSET)
                node = next
            except exceptions.TransferError:
                log.warning("TransferError while reading list elements (list=0x%08x, node=0x%08x), terminating list", self._list, node)
                is_valid = False

## @brief
class ArgonThreadContext(DebugContext):
    # SP is handled specially, so it is not in these dicts.

    CORE_REGISTER_OFFSETS = {
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

    FPU_EXTENDED_REGISTER_OFFSETS = {
                # Software stacked
                 4: 0, # r4
                 5: 4, # r5
                 6: 8, # r6
                 7: 12, # r7
                 8: 16, # r8
                 9: 20, # r9
                 10: 24, # r10
                 11: 28, # r11
                 0x50: 32, # s16
                 0x51: 36, # s17
                 0x52: 40, # s18
                 0x53: 44, # s19
                 0x54: 48, # s20
                 0x55: 52, # s21
                 0x56: 56, # s22
                 0x57: 60, # s23
                 0x58: 64, # s24
                 0x59: 68, # s25
                 0x5a: 72, # s26
                 0x5b: 76, # s27
                 0x5c: 80, # s28
                 0x5d: 84, # s29
                 0x5e: 88, # s30
                 0x5f: 92, # s31
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
        super(ArgonThreadContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._thread = thread
        self._has_fpu = parentContext.core.has_fpu

    def read_core_registers_raw(self, reg_list):
        reg_list = [self.core.register_name_to_index(reg) for reg in reg_list]

        sp = self._thread.get_stack_pointer()

        # Determine which register offset table to use and the offsets past the saved state.
        stacked = 0x20
        table = self.CORE_REGISTER_OFFSETS
        if not self._thread.get_exc_return_ftype():
            table = self.FPU_EXTENDED_REGISTER_OFFSETS
            stacked = 0xC8

        return self._do_read_regs_in_memory(reg_list, [(sp, table)], { 13: sp + stacked } )

    def write_core_registers_raw(self, reg_list, data_list):
        self._parent.write_core_registers_raw(reg_list, data_list)

## @brief Base class representing a thread on the target.
class ArgonThread(TargetThread):
    UNKNOWN = 0
    SUSPENDED = 1
    READY = 2
    RUNNING = 3
    BLOCKED = 4
    SLEEPING = 5
    DONE = 6

    STATE_NAMES = {
            UNKNOWN : "Unknown",
            SUSPENDED : "Suspended",
            READY : "Ready",
            RUNNING : "Running",
            BLOCKED : "Blocked",
            SLEEPING : "Sleeping",
            DONE : "Done",
        }

    def __init__(self, targetContext, provider, base):
        super(ArgonThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._base = base
        self._psp_context = PSPThreadContext(self._target_context, self)
        self._argon_context = ArgonThreadContext(self._target_context, self)
        self._has_fpu = self._target_context.core.has_fpu
        self._priority = 0
        self._state = self.UNKNOWN
        self._name = "?"

        try:
            self.update_info()

            ptr = self._target_context.read32(self._base + THREAD_NAME_OFFSET)
            self._name = read_c_string(self._target_context, ptr)
            log.debug("Thread@%x name=%x '%s'", self._base, ptr, self._name)
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread info")

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        try:
            return self._target_context.read32(self._base + THREAD_STACK_POINTER_OFFSET)
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread's stack pointer @ 0x%08x", self._base + THREAD_STACK_POINTER_OFFSET)
            return 0

    def update_info(self):
        try:
            self._priority = self._target_context.read8(self._base + THREAD_PRIORITY_OFFSET)

            self._state = self._target_context.read8(self._base + THREAD_STATE_OFFSET)
            if self._state > self.DONE:
                self._state = self.UNKNOWN
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread info")

    @property
    def state(self):
        return self._state

    @property
    def priority(self):
        return self._priority

    @property
    def unique_id(self):
        return self._base

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return "%s; Priority %d" % (self.STATE_NAMES[self.state], self.priority)

    @property
    def is_current(self):
        return self._provider.get_actual_current_thread_id() == self.unique_id

    @property
    def context(self):
        if is_current:
            return self._psp_context
        else:
            return self._argon_context

    @property
    def get_exc_return_ftype(self):
        if not self._has_fpu:
            return True
        try:
            flag = self._target_context.read8(self._base + THREAD_EXTENDED_FRAME_OFFSET)
            return flag == 0
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread's extended frame flag @ 0x%08x", self._base + THREAD_EXTENDED_FRAME_OFFSET)
            return True

    def __str__(self):
        return "<ArgonThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

    def __repr__(self):
        return str(self)

## @brief Base class for RTOS support plugins.
class ArgonThreadProvider(ThreadProvider):
    def __init__(self, target, parent):
        super(ArgonThreadProvider, self).__init__(target, parent)
        self.g_ar = None
        self.g_ar_objects = None
        self._all_threads = None
        self._threads = {}

    def init(self, symbolProvider):
        self.g_ar = symbolProvider.get_symbol_value("g_ar")
        if self.g_ar is None:
            return False
        log.debug("Argon: g_ar = 0x%08x", self.g_ar)

        self.g_ar_objects = symbolProvider.get_symbol_value("g_ar_objects")
        if self.g_ar_objects is None:
            return False
        log.debug("Argon: g_ar_objects = 0x%08x", self.g_ar_objects)

        self._all_threads = self.g_ar_objects + ALL_OBJECTS_THREADS_OFFSET

        self._target.root_target.subscribe(Target.EVENT_POST_FLASH_PROGRAM, self.event_handler)
        self._target.subscribe(Target.EVENT_POST_RESET, self.event_handler)

        return True

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        log.debug("Argon: invalidating threads list: %s" % (repr(notification)))
        self.invalidate();

    def _build_thread_list(self):
        if not self.is_enabled:
            self._threads = self._parent.threads
            return

        newThreads = self._parent.threads.copy()

        allThreads = TargetList(self._target_context, self._all_threads)

        for threadBase in allThreads:
            try:
                # Reuse existing thread objects if possible.
                if threadBase in self._threads:
                    t = self._threads[threadBase]

                    # Ask the thread object to update its state and priority.
                    t.update_info()
                else:
                    t = ArgonThread(self._target_context, self, threadBase)
                log.debug("Thread 0x%08x (%s)", threadBase, t.name)
                newThreads[t.unique_id] = t
            except exceptions.TransferError:
                log.debug("TransferError while examining thread 0x%08x", threadBase)

        if newThreads.get(self.get_actual_current_thread_id()) is not None:
            # Our current thread replaces the PSP thread from CortexMThreadProvider
            newThreads.pop(ProcessStackThread.UNIQUE_ID, None)
            # Our current thread replaces the root thread, if on PSP stack
            if (self.get_current_stack_pointer_id() == CortexM.PSP):
                newThreads.pop(RootThread.UNIQUE_ID, None)

        self._threads = newThreads

    @property
    def threads(self):
        self.update_threads()
        return self._threads

    @property
    def is_enabled(self):
        return self.g_ar is not None and self.get_is_running()

    def get_actual_current_thread_id(self):
        if not self.is_enabled:
            return None
        return self._target_context.read32(self.g_ar)

    def get_current_thread_id_for_stack(self, stack_id):
        if stack_id == CortexM.PSP:
            return self.get_actual_current_thread_id()
        else:
            return None

    def get_is_running(self):
        if self.g_ar is None:
            return False
        flags = self._target_context.read32(self.g_ar + KERNEL_FLAGS_OFFSET)
        return (flags & IS_RUNNING_MASK) != 0

## @brief Argon kernel trace event.
class ArgonTraceEvent(events.TraceEvent):
    kArTraceThreadSwitch = 1 # 2 value: 0=previous thread's new state, 1=new thread id
    kArTraceThreadCreated = 2 # 1 value
    kArTraceThreadDeleted = 3 # 1 value
    
    def __init__(self, eventID, threadID, name, state, ts=0):
        super(ArgonTraceEvent, self).__init__("argon", ts)
        self._event_id = eventID
        self._thread_id = threadID
        self._thread_name = name
        self._prev_thread_state = state
    
    @property
    def event_id(self):
        return self._event_id
    
    @property
    def thread_id(self):
        return self._thread_id
    
    @property
    def thread_name(self):
        return self._thread_name
    
    @property
    def prev_thread_state(self):
        return self._prev_thread_state
    
    def __str__(self):
        if self.event_id == ArgonTraceEvent.kArTraceThreadSwitch:
            stateName = ArgonThread.STATE_NAMES.get(self.prev_thread_state, "<invalid state>")
            desc = "New thread = {}; old thread state = {}".format(self.thread_name, stateName)
        elif self.event_id == ArgonTraceEvent.kArTraceThreadCreated:
            desc = "Created thread {}".format(self.thread_id)
        elif self.event_id == ArgonTraceEvent.kArTraceThreadDeleted:
            desc = "Deleted thread {}".format(self.thread_id)
        else:
            desc = "Unknown kernel event #{}".format(self.event_id)
        return "[{}] Argon: {}".format(self.timestamp, desc)

## @brief Trace event filter to identify Argon kernel trace events sent via ITM.
#
# As Argon kernel trace events are identified, the ITM trace events are replaced with instances
# of ArgonTraceEvent.
class ArgonTraceEventFilter(TraceEventFilter):
    def __init__(self, threads):
        super(ArgonTraceEventFilter, self).__init__()
        self._threads = threads
        self._is_thread_event_pending = False
        self._pending_event = None
        
    def filter(self, event):
        if isinstance(event, events.TraceITMEvent):
            if event.port == 31:
                eventID = event.data >> 24
                if eventID in (ArgonTraceEvent.kArTraceThreadSwitch, ArgonTraceEvent.kArTraceThreadCreated, ArgonTraceEvent.kArTraceThreadDeleted):
                    self._is_thread_event_pending = True
                    self._pending_event = event
                    # Swallow the event.
                    return
            elif event.port == 30 and self._is_thread_event_pending:
                eventID = self._pending_event.data >> 24
                threadID = event.data
                name = self._threads.get(threadID, "<unknown thread>")
                state = self._pending_event.data & 0x00ffffff
                
                # Create the Argon event.
                event = ArgonTraceEvent(eventID, threadID, name, state, self._pending_event.timestamp)

                self._is_thread_event_pending = False
                self._pending_event = None

        return event        

