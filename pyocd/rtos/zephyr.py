# pyOCD debugger
# Copyright (c) 2016-2020 Arm Limited
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
from .common import (read_c_string, HandlerModeThread)
from ..core import exceptions
from ..core.target import Target
from ..core.plugin import Plugin
from ..debug.context import DebugContext
from ..coresight.cortex_m_core_registers import index_for_reg
import logging

# Create a logger for this module.
LOG = logging.getLogger(__name__)

class TargetList(object):
    def __init__(self, context, ptr, next_offset):
        self._context = context
        self._list = ptr
        self._list_node_next_offset = next_offset

    def __iter__(self):
        node = self._context.read32(self._list)

        while (node != 0):
            try:
                yield node

                # Read next list node pointer.
                node = self._context.read32(node + self._list_node_next_offset)
            except exceptions.TransferError:
                LOG.warning("TransferError while reading list elements (list=0x%08x, node=0x%08x), terminating list", self._list, node)
                node = 0

class ZephyrThreadContext(DebugContext):
    """! @brief Thread context for Zephyr."""
    
    STACK_FRAME_OFFSETS = {
                 0: 0, # r0
                 1: 4, # r1
                 2: 8, # r2
                 3: 12, # r3
                 12: 16, # r12
                 14: 20, # lr
                 15: 24, # pc
                 16: 28, # xpsr
            }

    CALLEE_SAVED_OFFSETS = {
                 4: -32, # r4
                 5: -28, # r5
                 6: -24, # r6
                 7: -20, # r7
                 8: -16, # r8
                 9: -12, # r9
                 10: -8, # r10
                 11: -4, # r11
                 13: 0, # r13/sp
            }

    def __init__(self, parent, thread):
        super(ZephyrThreadContext, self).__init__(parent)
        self._thread = thread
        self._has_fpu = self.core.has_fpu

    def read_core_registers_raw(self, reg_list):
        reg_list = [index_for_reg(reg) for reg in reg_list]
        reg_vals = []

        isCurrent = self._thread.is_current
        inException = isCurrent and self._parent.read_core_register('ipsr') > 0

        # If this is the current thread and we're not in an exception, just read the live registers.
        if isCurrent and not inException:
            LOG.debug("Reading live registers")
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
        exceptionFrame = 0x20

        for reg in reg_list:

            # If this is a stack pointer register, add an offset to account for the exception stack frame
            if reg == 13:
                val = sp + exceptionFrame
                LOG.debug("Reading register %d = 0x%x", reg, val)
                reg_vals.append(val)
                continue

            # If this is a callee-saved register, read it from the thread structure
            calleeOffset = self.CALLEE_SAVED_OFFSETS.get(reg, None)
            if calleeOffset is not None:
                try:
                    addr = self._thread._base + self._thread._offsets["t_stack_ptr"] + calleeOffset
                    val = self._parent.read32(addr)
                    reg_vals.append(val)
                    LOG.debug("Reading callee-saved register %d at 0x%08x = 0x%x", reg, addr, val)
                except exceptions.TransferError:
                    reg_vals.append(0)
                continue

            # If this is a exception stack frame register, read it from the stack
            stackFrameOffset = self.STACK_FRAME_OFFSETS.get(reg, None)
            if stackFrameOffset is not None:
                try:
                    addr = sp + stackFrameOffset
                    val = self._parent.read32(addr)
                    reg_vals.append(val)
                    LOG.debug("Reading stack frame register %d at 0x%08x = 0x%x", reg, addr, val)
                except exceptions.TransferError:
                    reg_vals.append(0)
                continue

            # If we get here, this is a register not in any of the dictionaries
            val = self._parent.read_core_register_raw(reg)
            LOG.debug("Reading live register %d = 0x%x", reg, val)
            reg_vals.append(val)
            continue

        return reg_vals

class ZephyrThread(TargetThread):
    """! @brief A Zephyr task."""

    READY = 0
    PENDING = 1 << 1
    PRESTART = 1 << 2
    DEAD = 1 << 3
    SUSPENDED = 1 << 4
    POLLING = 1 << 5
    RUNNING = 1 << 6

    STATE_NAMES = {
            READY : "Ready",
            PENDING : "Pending",
            PRESTART : "Prestart",
            DEAD : "Dead",
            SUSPENDED : "Suspended",
            POLLING : "Polling",
            RUNNING : "Running",
        }

    def __init__(self, targetContext, provider, base, offsets):
        super(ZephyrThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._base = base
        self._thread_context = ZephyrThreadContext(self._target_context, self)
        self._offsets = offsets
        self._state = ZephyrThread.READY
        self._priority = 0
        self._name = "Unnamed"

        try:
            self.update_info()
        except exceptions.TransferError:
            LOG.debug("Transfer error while reading thread info")

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        addr = self._base + self._offsets["t_stack_ptr"]
        try:
            return self._target_context.read32(addr)
        except exceptions.TransferError:
            LOG.debug("Transfer error while reading thread's stack pointer @ 0x%08x", addr)
            return 0

    def update_info(self):
        try:
            self._priority = self._target_context.read8(self._base + self._offsets["t_prio"])
            self._state = self._target_context.read8(self._base + self._offsets["t_state"])

            if self._provider.version > 0:
                addr = self._target_context.read32(self._base + self._offsets["t_name"])
                if addr != 0:
                    self._name = read_c_string(self._target_context, addr)
                else:
                    self._name = "Unnamed"


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
        return "%s; Priority %d" % (self.STATE_NAMES.get(self.state, "UNKNOWN"), self.priority)

    @property
    def is_current(self):
        return self._provider.get_actual_current_thread_id() == self.unique_id

    @property
    def context(self):
        return self._thread_context

    def __str__(self):
        return "<ZephyrThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

    def __repr__(self):
        return str(self)

class ZephyrThreadProvider(ThreadProvider):
    """! @brief Thread provider for Zephyr."""

    ## Required Zephyr symbols.
    ZEPHYR_SYMBOLS = [
        "_kernel",
        "_kernel_openocd_offsets",
        "_kernel_openocd_size_t_size",
        ]

    ZEPHYR_OFFSETS = [
        'version',
        'k_curr_thread',
        'k_threads',
        't_entry',
        't_next_thread',
        't_state',
        't_user_options',
        't_prio',
        't_stack_ptr',
        't_name',
    ]

    def __init__(self, target):
        super(ZephyrThreadProvider, self).__init__(target)
        self._symbols = None
        self._offsets = None
        self._version = None
        self._all_threads = None
        self._curr_thread = None
        self._threads = {}

    def init(self, symbolProvider):
        # Lookup required symbols.
        self._symbols = self._lookup_symbols(self.ZEPHYR_SYMBOLS, symbolProvider)
        if self._symbols is None:
            return False

        self._update()
        self._target.session.subscribe(self.event_handler, Target.Event.POST_FLASH_PROGRAM)
        self._target.session.subscribe(self.event_handler, Target.Event.POST_RESET)

        return True

    def _get_offsets(self):
        # Read the kernel and thread structure member offsets
        size = self._target_context.read8(self._symbols["_kernel_openocd_size_t_size"])
        LOG.debug("_kernel_openocd_size_t_size = %d", size)
        if size != 4:
            LOG.error("Unsupported _kernel_openocd_size_t_size")
            return None

        offsets = {}
        for index, name in enumerate(self.ZEPHYR_OFFSETS):
            offset = self._symbols["_kernel_openocd_offsets"] + index * size
            offsets[name] = self._target_context.read32(offset)
            LOG.debug("%s = 0x%04x", name, offsets[name])

        return offsets

    def _update(self):
        self._offsets = self._get_offsets()

        if self._offsets is None:
            self._version = None
            self._all_threads = None
            self._curr_thread = None
            LOG.debug("_offsets, _all_threads, and _curr_thread are invalid")
        else:
            self._version = self._offsets["version"]
            self._all_threads = self._symbols["_kernel"] + self._offsets["k_threads"]
            self._curr_thread = self._symbols["_kernel"] + self._offsets["k_curr_thread"]
            LOG.debug("version = %d, _all_threads = 0x%08x, _curr_thread = 0x%08x", self._version, self._all_threads, self._curr_thread)

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        if notification.event == Target.Event.POST_RESET:
            LOG.debug("Invalidating threads list: %s" % (repr(notification)))
            self.invalidate();

        elif notification.event == Target.Event.POST_FLASH_PROGRAM:
            self._update()

    def _build_thread_list(self):
        allThreads = TargetList(self._target_context, self._all_threads, self._offsets["t_next_thread"])
        newThreads = {}

        currentThread = self._target_context.read32(self._curr_thread)
        LOG.debug("currentThread = 0x%08x", currentThread)

        for threadBase in allThreads:
            try:
                # Reuse existing thread objects.
                if threadBase in self._threads:
                    t = self._threads[threadBase]

                    # Ask the thread object to update its state and priority.
                    t.update_info()
                else:
                    t = ZephyrThread(self._target_context, self, threadBase, self._offsets)

                # Set thread state.
                if threadBase == currentThread:
                    t.state = ZephyrThread.RUNNING

                LOG.debug("Thread 0x%08x (%s)", threadBase, t.name)
                newThreads[t.unique_id] = t
            except exceptions.TransferError:
                LOG.debug("TransferError while examining thread 0x%08x", threadBase)

        # Create fake handler mode thread.
        if self._target_context.read_core_register('ipsr') > 0:
            LOG.debug("creating handler mode thread")
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
        return self._symbols is not None and self.get_is_running()

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
        return self._target_context.read32(self._curr_thread)

    def get_is_running(self):
        if self._symbols is None or self._offsets is None:
            return False
        # TODO
        return True

    @property
    def version(self):
        return self._version

class ZephyrPlugin(Plugin):
    """! @brief Plugin class for the Zephyr RTOS."""
    
    def load(self):
        return ZephyrThreadProvider
    
    @property
    def name(self):
        return "zephyr"
    
    @property
    def description(self):
        return "Zephyr"
