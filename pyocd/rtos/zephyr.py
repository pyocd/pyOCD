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
from ..debug.cortex_m_thread_provider import ProcessStackThread, PSPThreadContext
from ..debug.thread_provider import (TargetThread, ThreadProvider, RootThread)
import logging

# Create a logger for this module.
log = logging.getLogger("zephyr")

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
                log.warning("TransferError while reading list elements (list=0x%08x, node=0x%08x), terminating list", self._list, node)
                node = 0

## @brief
class ZephyrThreadContext(DebugContext):
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

    def __init__(self, parentContext, thread):
        super(ZephyrThreadContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._thread = thread
        self._has_fpu = parentContext.core.has_fpu

    def read_core_registers_raw(self, reg_list):
        reg_list = [self.core.register_name_to_index(reg) for reg in reg_list]

        sp = self._thread.get_stack_pointer()
        exceptionFrame = 0x20

        return self._do_read_regs_in_memory(reg_list, \
                [(self._thread._base + self._thread._offsets["t_stack_ptr"], self.CALLEE_SAVED_OFFSETS), \
                 (sp, self.STACK_FRAME_OFFSETS)], \
                { 13: sp + exceptionFrame } )

    def write_core_registers_raw(self, reg_list, data_list):
        self._parent.write_core_registers_raw(reg_list, data_list)

## @brief A Zephyr task.
class ZephyrThread(TargetThread):
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
        self._psp_context = PSPThreadContext(self._target_context, self)
        self._zephyr_context = ZephyrThreadContext(self._target_context, self)
        self._offsets = offsets
        self._state = ZephyrThread.READY
        self._priority = 0
        self._name = "Unnamed"

        try:
            self.update_info()
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread info")

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        addr = self._base + self._offsets["t_stack_ptr"]
        try:
            return self._target_context.read32(addr)
        except exceptions.TransferError:
            log.debug("Transfer error while reading thread's stack pointer @ 0x%08x", addr)
            return 0

    def get_exc_return_ftype(self):
        # This code does not support floating point, so can assume all threads
        # use standard frames
        return True

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
            log.debug("Transfer error while reading thread info")

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
        return "%s; Priority %d" % (self.STATE_NAMES[self.state], self.priority)

    @property
    def is_current(self):
        return self._provider.get_actual_current_thread_id() == self.unique_id

    @property
    def context(self):
        if is_current:
            return self._psp_context
        else:
            return self._zephyr_context

    def __str__(self):
        return "<ZephyrThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

    def __repr__(self):
        return str(self)

## @brief Thread provider for Zephyr.
class ZephyrThreadProvider(ThreadProvider):

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

    def __init__(self, target, parent):
        super(ZephyrThreadProvider, self).__init__(target, parent)
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
        self._target.root_target.subscribe(Target.EVENT_POST_FLASH_PROGRAM, self.event_handler)
        self._target.subscribe(Target.EVENT_POST_RESET, self.event_handler)

        return True

    def _get_offsets(self):
        # Read the kernel and thread structure member offsets
        size = self._target_context.read8(self._symbols["_kernel_openocd_size_t_size"])
        log.debug("_kernel_openocd_size_t_size = %d", size)
        if size != 4:
            log.error("Unsupported _kernel_openocd_size_t_size")
            return None

        offsets = {}
        for index, name in enumerate(self.ZEPHYR_OFFSETS):
            offset = self._symbols["_kernel_openocd_offsets"] + index * size
            offsets[name] = self._target_context.read32(offset)
            log.debug("%s = 0x%04x", name, offsets[name])

        return offsets

    def _update(self):
        self._offsets = self._get_offsets()

        if self._offsets is None:
            self._version = None
            self._all_threads = None
            self._curr_thread = None
            log.debug("_offsets, _all_threads, and _curr_thread are invalid")
        else:
            self._version = self._offsets["version"]
            self._all_threads = self._symbols["_kernel"] + self._offsets["k_threads"]
            self._curr_thread = self._symbols["_kernel"] + self._offsets["k_curr_thread"]
            log.debug("version = %d, _all_threads = 0x%08x, _curr_thread = 0x%08x", self._version, self._all_threads, self._curr_thread)

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        if notification.event == Target.EVENT_POST_RESET:
            log.debug("Invalidating threads list: %s" % (repr(notification)))
            self.invalidate();

        elif notification.event == Target.EVENT_POST_FLASH_PROGRAM:
            self._update()

    def _build_thread_list(self):
        if not self.is_enabled:
            self._threads = self._parent.threads
            return

        newThreads = self._parent.threads.copy()

        allThreads = TargetList(self._target_context, self._all_threads, self._offsets["t_next_thread"])

        currentThread = self._target_context.read32(self._curr_thread)
        log.debug("currentThread = 0x%08x", currentThread)

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
                    # Our current thread replaces the PSP thread from CortexMThreadProvider
                    newThreads.pop(ProcessStackThread.UNIQUE_ID, None)
                    # Our current thread replaces the root thread, if on PSP stack
                    if (self.get_current_stack_pointer_id() == CortexM.PSP):
                        newThreads.pop(RootThread.UNIQUE_ID, None)

                log.debug("Thread 0x%08x (%s)", threadBase, t.name)
                newThreads[t.unique_id] = t
            except exceptions.TransferError:
                log.debug("TransferError while examining thread 0x%08x", threadBase)

        self._threads = newThreads

    @property
    def threads(self):
        self.update_threads()
        return self._threads

    @property
    def is_enabled(self):
        return self._symbols is not None and self.get_is_running()

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
