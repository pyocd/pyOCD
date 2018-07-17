"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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

from .provider import (TargetThread, ThreadProvider)
from .common import (read_c_string, HandlerModeThread)
from ..core.target import Target
from ..debug.context import DebugContext
from ..coresight.cortex_m import (CORE_REGISTER, register_name_to_index)
from pyOCD.pyDAPAccess import DAPAccess
import logging

IS_RUNNING_OFFSET = 0x54

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
            except DAPAccess.TransferError:
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

    # Registers that are not available on the stack for exceptions.
    EXCEPTION_UNAVAILABLE_REGS = (4, 5, 6, 7, 8, 9, 10, 11)

    def __init__(self, parentContext, thread):
        super(ArgonThreadContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._thread = thread

    def readCoreRegistersRaw(self, reg_list):
        reg_list = [register_name_to_index(reg) for reg in reg_list]
        reg_vals = []

        inException = self._get_ipsr() > 0
        isCurrent = self._thread.is_current

        # If this is the current thread and we're not in an exception, just read the live registers.
        if isCurrent and not inException:
            return self._parent.readCoreRegistersRaw(reg_list)

        sp = self._thread.get_stack_pointer()

        # Determine which register offset table to use and the offsets past the saved state.
        realSpOffset = 0x40
        realSpExceptionOffset = 0x20
        table = self.CORE_REGISTER_OFFSETS
        if self._thread.has_extended_frame:
            table = self.FPU_EXTENDED_REGISTER_OFFSETS
            realSpOffset = 0xc8
            realSpExceptionOffset = 0x68

        for reg in reg_list:
            # Check for regs we can't access.
            if isCurrent and inException:
                if reg in self.EXCEPTION_UNAVAILABLE_REGS:
                    reg_vals.append(0)
                    continue
                if reg == 18 or reg == 13: # PSP
                    log.debug("psp = 0x%08x", sp + realSpExceptionOffset)
                    reg_vals.append(sp + realSpExceptionOffset)
                    continue

            # Must handle stack pointer specially.
            if reg == 13:
                reg_vals.append(sp + realSpOffset)
                continue

            # Look up offset for this register on the stack.
            spOffset = table.get(reg, None)
            if spOffset is None:
                reg_vals.append(self._parent.readCoreRegisterRaw(reg))
                continue
            if isCurrent and inException:
                spOffset -= realSpExceptionOffset #0x20

            try:
                reg_vals.append(self._parent.read32(sp + spOffset))
            except DAPAccess.TransferError:
                reg_vals.append(0)

        return reg_vals

    def _get_ipsr(self):
        return self._parent.readCoreRegister('xpsr') & 0xff

    def writeCoreRegistersRaw(self, reg_list, data_list):
        self._parent.writeCoreRegistersRaw(reg_list, data_list)

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
        self._thread_context = ArgonThreadContext(self._target_context, self)
        self._has_fpu = self._thread_context.core.has_fpu
        self._priority = 0
        self._state = self.UNKNOWN
        self._name = "?"

        try:
            self.update_info()

            ptr = self._target_context.read32(self._base + THREAD_NAME_OFFSET)
            self._name = read_c_string(self._target_context, ptr)
            log.debug("Thread@%x name=%x '%s'", self._base, ptr, self._name)
        except DAPAccess.TransferError:
            log.debug("Transfer error while reading thread info")

    def get_stack_pointer(self):
        sp = 0
        if self.is_current:
            # Read live process stack.
            sp = self._target_context.readCoreRegister('psp')
        else:
            # Get stack pointer saved in thread struct.
            try:
                sp = self._target_context.read32(self._base + THREAD_STACK_POINTER_OFFSET)
            except DAPAccess.TransferError:
                log.debug("Transfer error while reading thread's stack pointer @ 0x%08x", self._base + THREAD_STACK_POINTER_OFFSET)
        return sp

    def update_info(self):
        try:
            self._priority = self._target_context.read8(self._base + THREAD_PRIORITY_OFFSET)

            self._state = self._target_context.read8(self._base + THREAD_STATE_OFFSET)
            if self._state > self.DONE:
                self._state = self.UNKNOWN
        except DAPAccess.TransferError:
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
        return self._thread_context

    @property
    def has_extended_frame(self):
        if not self._has_fpu:
            return False
        try:
            flag = self._target_context.read8(self._base + THREAD_EXTENDED_FRAME_OFFSET)
            return flag != 0
        except DAPAccess.TransferError:
            log.debug("Transfer error while reading thread's extended frame flag @ 0x%08x", self._base + THREAD_EXTENDED_FRAME_OFFSET)
            return False

    def __str__(self):
        return "<ArgonThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

    def __repr__(self):
        return str(self)

## @brief Base class for RTOS support plugins.
class ArgonThreadProvider(ThreadProvider):
    def __init__(self, target):
        super(ArgonThreadProvider, self).__init__(target)
        self.g_ar = None
        self.g_ar_objects = None
        self._all_threads = None
        self._threads = {}

        self._target.root_target.subscribe(Target.EVENT_POST_FLASH_PROGRAM, self.event_handler)
        self._target.subscribe(Target.EVENT_POST_RESET, self.event_handler)

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

        return True

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        log.debug("Argon: invalidating threads list: %s" % (repr(notification)))
        self.invalidate();

    def _build_thread_list(self):
        allThreads = TargetList(self._target_context, self._all_threads)
        newThreads = {}
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
            except DAPAccess.TransferError:
                log.debug("TransferError while examining thread 0x%08x", threadBase)

        # Create fake handler mode thread.
        if self.get_ipsr() > 0:
            log.debug("creating handler mode thread")
            t = HandlerModeThread(self._target_context, self)
            newThreads[t.unique_id] = t

        self._threads = newThreads

    def get_threads(self):
        if not self.is_enabled:
            return []
        self.update_threads()
        return list(self._threads.values())

    def get_thread(self, threadId):
        if not self.is_enabled:
            return None
        self.update_threads()
        return self._threads.get(threadId, None)

    @property
    def is_enabled(self):
        return self.g_ar is not None and self.get_is_running()

    @property
    def current_thread(self):
        if not self.is_enabled:
            return None
        self.update_threads()
        id = self.get_current_thread_id()
        try:
            return self._threads[id]
        except KeyError:
            log.debug("key error getting current thread id=%x", id)
            log.debug("self._threads = %s", repr(self._threads))
            return None

    def is_valid_thread_id(self, threadId):
        if not self.is_enabled:
            return False
        self.update_threads()
        return threadId in self._threads

    def get_current_thread_id(self):
        if not self.is_enabled:
            return None
        if self.get_ipsr() > 0:
            return 2
        return self.get_actual_current_thread_id()

    def get_actual_current_thread_id(self):
        if not self.is_enabled:
            return None
        return self._target_context.read32(self.g_ar)

    def get_is_running(self):
        if self.g_ar is None:
            return False
        flag = self._target_context.read8(self.g_ar + IS_RUNNING_OFFSET)
        return flag != 0


