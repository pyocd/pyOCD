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
            except DAPAccess.TransferError:
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

    def readCoreRegistersRaw(self, reg_list):
        reg_list = [register_name_to_index(reg) for reg in reg_list]
        reg_vals = []

        inException = self._get_ipsr() > 0
        isCurrent = self._thread.is_current

        # If this is the current thread and we're not in an exception, just read the live registers.
        if isCurrent and not inException:
            log.debug("Reading live registers")
            return self._parent.readCoreRegistersRaw(reg_list)

        sp = self._thread.get_stack_pointer()
        exceptionFrame = 0x20

        for reg in reg_list:

            # If this is a stack pointer register, add an offset to account for the exception stack frame
            if reg == 13 or reg == 18:
                val = sp + exceptionFrame
                log.debug("Reading register %d = 0x%x", reg, val)
                reg_vals.append(val)
                continue

            # If this is a callee-saved register, read it from the thread structure
            calleeOffset = self.CALLEE_SAVED_OFFSETS.get(reg, None)
            if calleeOffset is not None:
                try:
                    addr = self._thread._base + self._thread._offsets["t_stack_ptr"] + calleeOffset
                    val = self._parent.read32(addr)
                    reg_vals.append(val)
                    log.debug("Reading callee-saved register %d at 0x%08x = 0x%x", reg, addr, val)
                except DAPAccess.TransferError:
                    reg_vals.append(0)
                continue

            # If this is a exception stack frame register, read it from the stack
            stackFrameOffset = self.STACK_FRAME_OFFSETS.get(reg, None)
            if stackFrameOffset is not None:
                try:
                    addr = sp + stackFrameOffset
                    val = self._parent.read32(addr)
                    reg_vals.append(val)
                    log.debug("Reading stack frame register %d at 0x%08x = 0x%x", reg, addr, val)
                except DAPAccess.TransferError:
                    reg_vals.append(0)
                continue

            # If we get here, this is a register not in any of the dictionaries
            val = self._parent.readCoreRegisterRaw(reg)
            log.debug("Reading live register %d = 0x%x", reg, val)
            reg_vals.append(val)
            continue

        return reg_vals

    def _get_ipsr(self):
        return self._parent.readCoreRegister('xpsr') & 0xff

    def writeCoreRegistersRaw(self, reg_list, data_list):
        self._parent.writeCoreRegistersRaw(reg_list, data_list)

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
        self._thread_context = ZephyrThreadContext(self._target_context, self)
        self._offsets = offsets
        self._state = ZephyrThread.READY
        self._priority = 0
        self._name = "Unnamed"

        try:
            self.update_info()
        except DAPAccess.TransferError:
            log.debug("Transfer error while reading thread info")

    def get_stack_pointer(self):
        if self.is_current:
            # Read live process stack.
            sp = self._target_context.readCoreRegister('psp')
        else:
            # Get stack pointer saved in thread struct.
            addr = self._base + self._offsets["t_stack_ptr"]
            try:
                sp = self._target_context.read32(addr)
            except DAPAccess.TransferError:
                log.debug("Transfer error while reading thread's stack pointer @ 0x%08x", addr)
        return sp

    def update_info(self):
        try:
            self._priority = self._target_context.read8(self._base + self._offsets["t_prio"])
            self._state = self._target_context.read8(self._base + self._offsets["t_state"])
        except DAPAccess.TransferError:
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
        return self._thread_context

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
    ]

    def __init__(self, target):
        super(ZephyrThreadProvider, self).__init__(target)
        self._symbols = None
        self._offsets = None
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
            self._all_threads = None
            self._curr_thread = None
            log.debug("_offsets, _all_threads, and _curr_thread are invalid")
        else:
            self._all_threads = self._symbols["_kernel"] + self._offsets["k_threads"]
            self._curr_thread = self._symbols["_kernel"] + self._offsets["k_curr_thread"]
            log.debug("_all_threads = 0x%08x, _curr_thread = 0x%08x", self._all_threads, self._curr_thread)

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        if notification.event == Target.EVENT_POST_RESET:
            log.info("Invalidating threads list: %s" % (repr(notification)))
            self.invalidate();

        elif notification.event == Target.EVENT_POST_FLASH_PROGRAM:
            self._update()

    def _build_thread_list(self):
        allThreads = TargetList(self._target_context, self._all_threads, self._offsets["t_next_thread"])
        newThreads = {}

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
        if self.get_ipsr() > 0:
            return 2
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
