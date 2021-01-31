# pyOCD debugger
# Copyright (c) 2020-2021 Federico Zuccardi Merli
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

from .provider import (TargetThread, ThreadProvider)
from .common import (read_c_string, HandlerModeThread,
                     EXC_RETURN_EXT_FRAME_MASK)
from ..core import exceptions
from ..core.target import Target
from ..core.plugin import Plugin
from ..debug.context import DebugContext
from ..coresight.cortex_m_core_registers import index_for_reg
from ..coresight.core_ids import CoreArchitecture

import logging

TX_THREAD_ID = 0x54485244  # 'THRD'
THREAD_ID_OFFSET = 0
THREAD_STACK_POINTER_OFFSET = 8
# All the following offset may be messed up if thread extensions are defined.
# They should be read somehow from the elf.
THREAD_NAME_OFFSET = 40
THREAD_PRIORITY_OFFSET = 44
THREAD_STATE_OFFSET = 48
THREAD_NEXT_OFFSET = 136

# Create a logger for this module.
LOG = logging.getLogger(__name__)


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
                # Check if this is really a thread
                if self._context.read32(node) == TX_THREAD_ID:
                    # Yields the thread pointer.
                    yield node
                else:
                    # Something is wrong. Might depend on a thread extension
                    is_valid = False
                    LOG.warning(
                        "Wrong thread ID found. Memory corruption or unknown extensions")

                next = self._context.read32(node + THREAD_NEXT_OFFSET)
                node = next
            except exceptions.TransferError:
                LOG.warning(
                    "TransferError while reading list elements (list=0x%08x, node=0x%08x), terminating list", self._list, node)
                is_valid = False


class ThreadXThreadContext(DebugContext):
    """! @brief Thread context for ThreadX."""

    # SP/PSP are handled specially, so it is not in these dicts.

    # Offsets are relative to stored SP in a task switch block, for the
    # combined software + hardware stacked registers. In exception case,
    # software registers are not stacked, so appropriate amount must be
    # subtracted.
    NOFPU_REGISTER_OFFSETS = {
        # Software stacked
        -1:     0,      # lr (exception)
        4:      4,      # r4
        5:      8,      # r5
        6:      12,     # r6
        7:      16,     # r7
        8:      20,     # r8
        9:      24,     # r9
        10:     28,     # r10
        11:     32,     # r11
        # Hardware stacked
        0:      36,     # r0
        1:      40,     # r1
        2:      44,     # r2
        3:      48,     # r3
        12:     52,     # r12
        14:     56,     # lr (thread)
        15:     60,     # pc
        16:     64,     # xpsr
    }

    # Cortex-m0 port of threadx reverses r4-7 and r8-11
    NOFPU_REGISTER_OFFSETS_V6M = {
        # Software stacked
        4:      20,     # r4
        5:      24,     # r5
        6:      28,     # r6
        7:      32,     # r7
        8:      4,      # r8
        9:      8,      # r9
        10:     12,     # r10
        11:     16,     # r11
    }

    FPU_REGISTER_OFFSETS = {
        # Software stacked
        -1:     0,      # lr (exception)
        0x50:   4,      # s16
        0x51:   8,      # s17
        0x52:   12,     # s18
        0x53:   16,     # s19
        0x54:   20,     # s20
        0x55:   24,     # s21
        0x56:   28,     # s22
        0x57:   32,     # s23
        0x58:   36,     # s24
        0x59:   40,     # s25
        0x5a:   44,     # s26
        0x5b:   48,     # s27
        0x5c:   52,     # s28
        0x5d:   56,     # s29
        0x5e:   60,     # s30
        0x5f:   64,     # s31
        4:      68,     # r4
        5:      72,     # r5
        6:      76,     # r6
        7:      80,     # r7
        8:      84,     # r8
        9:      88,     # r9
        10:     92,     # r10
        11:     96,     # r11
        # Hardware stacked
        0:      100,    # r0
        1:      104,    # r1
        2:      108,    # r2
        3:      112,    # r3
        12:     116,    # r12
        14:     120,    # lr
        15:     124,    # pc
        16:     128,    # xpsr
        0x40:   132,    # s0
        0x41:   136,    # s1
        0x42:   140,    # s2
        0x43:   144,    # s3
        0x44:   148,    # s4
        0x45:   152,    # s5
        0x46:   156,    # s6
        0x47:   160,    # s7
        0x48:   164,    # s8
        0x49:   168,    # s9
        0x4a:   172,    # s10
        0x4b:   176,    # s11
        0x4c:   180,    # s12
        0x4d:   184,    # s13
        0x4e:   188,    # s14
        0x4f:   192,    # s15
        33:     196,    # fpscr
        # (reserved word: 200)
    }

    def __init__(self, parent, thread):
        super(ThreadXThreadContext, self).__init__(parent)
        self._thread = thread
        self._has_fpu = self.core.has_fpu
        if self.core.architecture != CoreArchitecture.ARMv6M:
            # Use the default offsets for this istance
            self._nofpu_register_offsets = self.NOFPU_REGISTER_OFFSETS
        else:
            # Use a copy with the Cortex-M0 specific offsets for this istance
            self._nofpu_register_offsets = self.NOFPU_REGISTER_OFFSETS.copy()
            self._nofpu_register_offsets.update(
                self.NOFPU_REGISTER_OFFSETS_V6M)

    def read_core_registers_raw(self, reg_list):
        reg_list = [index_for_reg(reg) for reg in reg_list]
        reg_vals = []

        isCurrent = self._thread.is_current
        inException = isCurrent and self._parent.read_core_register('ipsr') > 0

        # If this is the current thread and we're not in an exception, just read the live registers.
        if isCurrent and not inException:
            return self._parent.read_core_registers_raw(reg_list)

        # Because of above tests, from now on, inException implies isCurrent;
        # we are generating the thread view for the RTOS thread where the
        # exception occurred; the actual Handler Mode thread view is produced
        # by HandlerModeThread
        if inException:
            # Reasonable to assume PSP is still valid
            sp = self._parent.read_core_register('psp')
        else:
            sp = self._thread.get_stack_pointer()

        # Determine which register offset table to use and the offsets past the saved state.
        hwStacked = 0x20
        swStacked = 0x24
        table = self._nofpu_register_offsets
        if self._has_fpu:
            try:
                if inException and self.core.is_vector_catch():
                    # Vector catch has just occurred, take live LR
                    exceptionLR = self._parent.read_core_register('lr')
                else:
                    # Read stacked exception return LR.
                    offset = self.FPU_REGISTER_OFFSETS[-1]
                    exceptionLR = self._parent.read32(sp + offset)

                # Check bit 4 of the exception LR to determine if FPU registers were stacked.
                if (exceptionLR & EXC_RETURN_EXT_FRAME_MASK) == 0:
                    table = self.FPU_REGISTER_OFFSETS
                    hwStacked = 0x68
                    swStacked = 0x64
            except exceptions.TransferError:
                LOG.debug("Transfer error while reading thread's saved LR")

        for reg in reg_list:

            # Must handle stack pointer specially.
            if reg == 13:
                if inException:
                    reg_vals.append(sp + hwStacked)
                else:
                    reg_vals.append(sp + swStacked + hwStacked)
                continue

            # Look up offset for this register on the stack.
            spOffset = table.get(reg, None)
            if spOffset is None:
                reg_vals.append(self._parent.read_core_register_raw(reg))
                continue
            if inException:
                spOffset -= swStacked

            try:
                if spOffset >= 0:
                    reg_vals.append(self._parent.read32(sp + spOffset))
                else:
                    # Not available - try live one
                    reg_vals.append(self._parent.read_core_register_raw(reg))
            except exceptions.TransferError:
                reg_vals.append(0)

        return reg_vals


class ThreadXThread(TargetThread):
    """! @brief A ThreadX task."""

    STATE_NAMES = {
        0: "Ready",
        1: "Completed",
        2: "Terminated",
        3: "Suspended",
        4: "Sleep",
        5: "Queue",
        6: "Semaphore",
        7: "EventFlag",
        8: "BlockMemory",
        9: "ByteMemory",
        10: "IoDriver",
        11: "File",
        12: "TcpIp",
        13: "Mutex",
        14: "PriorityChange",
        99: "Unknown"
    }

    READY = 0
    PRIORITYCHANGE = 14
    UNKNOWN = 99

    def __init__(self, targetContext, provider, base):
        super(ThreadXThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._base = base
        self._state = self._target_context.read32(
            self._base + THREAD_STATE_OFFSET)
        self._priority = self._target_context.read32(
            self._base + THREAD_PRIORITY_OFFSET)
        self._name = ""
        namePtr = self._target_context.read32(self._base + THREAD_NAME_OFFSET)
        if namePtr != 0:
            self._name = read_c_string(self._target_context, namePtr)
        if len(self._name) == 0:
            self._name = "Unnamed"
        self._thread_context = ThreadXThreadContext(self._target_context, self)

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        try:
            return self._target_context.read32(self._base + THREAD_STACK_POINTER_OFFSET)
        except exceptions.TransferError:
            LOG.debug("Transfer error while reading thread's stack pointer @ 0x%08x",
                      self._base + THREAD_STACK_POINTER_OFFSET)
            return 0

    def update_info(self):
        try:
            self._priority = self._target_context.read32(
                self._base + THREAD_PRIORITY_OFFSET)
            self._state = self._target_context.read32(
                self._base + THREAD_STATE_OFFSET)
            if not self.READY <= self._state <= self.PRIORITYCHANGE:
                self._state = self.UNKNOWN
        except exceptions.TransferError:
            LOG.debug("Transfer error while reading thread info")

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

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
        # return "%s; Priority %d" % (self.STATE_NAMES[self.state], self.priority)
        return "%s; Priority %d" % (self.STATE_NAMES[self.state], self.priority)

    @property
    def is_current(self):
        return self._provider.get_actual_current_thread_id() == self.unique_id

    @property
    def context(self):
        return self._thread_context

    def __str__(self):
        return "<ThreadXThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

    def __repr__(self):
        return str(self)


class ThreadXThreadProvider(ThreadProvider):
    """! @brief Thread provider for ThreadX.

        To successfully initialize, the following ThreadX symbols are needed:
            _tx_thread_created_ptr:     pointer to list of created processes
            _tx_thread_created_count:   count of created processes
            _tx_thread_current_ptr:     current thread
            _tx_thread_system_state:    ThreadX state: initializing, run, interrupt
    """

    # Scheduler not yet up
    TX_INITIALIZE_IN_PROGRESS = 0xF0F0F0F0

    def __init__(self, target):
        super(ThreadXThreadProvider, self).__init__(target)
        self._created_ptr = None
        self._created_cnt = None
        self._current_ptr = None
        self._system_state = None
        self._threads = {}

    def init(self, symbolProvider):
        self._created_ptr = symbolProvider.get_symbol_value(
            '_tx_thread_created_ptr')
        if self._created_ptr is None:
            return False
        LOG.debug("ThreadX: _tx_thread_created_ptr = 0x%08x", self._created_ptr)

        self._created_cnt = symbolProvider.get_symbol_value(
            '_tx_thread_created_count')
        if self._created_cnt is None:
            return False
        LOG.debug("ThreadX: _tx_thread_created_cnt = 0x%08x", self._created_cnt)

        self._current_ptr = symbolProvider.get_symbol_value(
            '_tx_thread_current_ptr')
        if self._current_ptr is None:
            return False
        LOG.debug("ThreadX: _tx_thread_current_ptr = 0x%08x", self._current_ptr)

        self._system_state = symbolProvider.get_symbol_value(
            '_tx_thread_system_state')
        if self._system_state is None:
            return False
        LOG.debug("ThreadX: _tx_thread_system_state = 0x%08x",
                  self._current_ptr)

        self._target.session.subscribe(
            self.event_handler, Target.Event.POST_FLASH_PROGRAM)
        self._target.session.subscribe(
            self.event_handler, Target.Event.POST_RESET)

        return True

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        LOG.debug("ThreadX: invalidating threads list: %s" %
                  (repr(notification)))
        self.invalidate()

    def _build_thread_list(self):
        # Read the number of threads.
        threadCount = self._target_context.read32(self._created_cnt)

        # Build up list of all the threads
        allThreads = TargetList(self._target_context, self._created_ptr)
        newThreads = {}
        for threadBase in allThreads:
            try:
                # Reuse existing thread objects if possible.
                if threadBase in self._threads:
                    t = self._threads[threadBase]

                    # Ask the thread object to update its state and priority.
                    t.update_info()
                else:
                    t = ThreadXThread(self._target_context, self, threadBase)
                LOG.debug("Thread 0x%08x (%s)", threadBase, t.name)
                newThreads[t.unique_id] = t
            except exceptions.TransferError:
                LOG.debug(
                    "TransferError while examining thread 0x%08x", threadBase)

        # Is the number of threads correct?
        if len(newThreads) != threadCount:
            LOG.warning("ThreadX: thread count mismatch, %d expected, %d found",
                        threadCount, len(newThreads))

        # Create fake handler mode thread.
        if self._target_context.read_core_register('ipsr') > 0:
            LOG.debug("ThreadX: creating handler mode thread")
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
        # The _tx_thread_system_state global is used to determine whether
        # the kernel is running. Before the kernel starts, it'll contain
        # TX_INITIALIZE_IN_PROGRESS and possibly TX_INITIALIZE_IN_PROGRESS+1.
        # On cortex-m ports it should otherwise be 0.
        # As it's used in other ports to indicate the interrupt nesting level, it's
        # safer to compare it with TX_INITIALIZE_IN_PROGRESS.
        if self._system_state is None:
            return False
        return self._target_context.read32(self._system_state) < self.TX_INITIALIZE_IN_PROGRESS

    @property
    def current_thread(self):
        if not self.is_enabled:
            return None
        self.update_threads()
        id = self.get_current_thread_id()
        try:
            return self._threads[id]
        except KeyError:
            return None

    def is_valid_thread_id(self, threadId):
        if not self.is_enabled:
            return False
        self.update_threads()
        return threadId in self._threads

    def get_current_thread_id(self):
        if not self.is_enabled:
            return None
        if self._target_context.read_core_register('ipsr') > 0:
            return HandlerModeThread.UNIQUE_ID
        return self.get_actual_current_thread_id()

    def get_actual_current_thread_id(self):
        if not self.is_enabled:
            return None
        return self._target_context.read32(self._current_ptr)


class ThreadXPlugin(Plugin):
    """! @brief Plugin class for ThreadX."""

    def load(self):
        return ThreadXThreadProvider

    @property
    def name(self):
        return "threadx"

    @property
    def description(self):
        return "ThreadX"
