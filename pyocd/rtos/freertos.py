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
from .common import (read_c_string, HandlerModeThread, EXC_RETURN_EXT_FRAME_MASK)
from ..core import exceptions
from ..core.target import Target
from ..core.plugin import Plugin
from ..debug.context import DebugContext
from ..coresight.cortex_m_core_registers import index_for_reg
import logging

FREERTOS_MAX_PRIORITIES	= 63

LIST_SIZE = 20
LIST_INDEX_OFFSET = 16
LIST_NODE_NEXT_OFFSET = 8 # 4?
LIST_NODE_OBJECT_OFFSET = 12

THREAD_STACK_POINTER_OFFSET = 0
THREAD_PRIORITY_OFFSET = 44
THREAD_NAME_OFFSET = 52

# Create a logger for this module.
LOG = logging.getLogger(__name__)

class TargetList(object):
    def __init__(self, context, ptr):
        self._context = context
        self._list = ptr

    def __iter__(self):
        prev = -1
        found = 0
        count = self._context.read32(self._list)
        if count == 0:
            return

        node = self._context.read32(self._list + LIST_INDEX_OFFSET)

        while (node != 0) and (node != prev) and (found < count):
            try:
                # Read the object from the node.
                obj = self._context.read32(node + LIST_NODE_OBJECT_OFFSET)
                yield obj
                found += 1

                # Read next list node pointer.
                prev = node
                node = self._context.read32(node + LIST_NODE_NEXT_OFFSET)
            except exceptions.TransferError:
                LOG.warning("TransferError while reading list elements (list=0x%08x, node=0x%08x), terminating list", self._list, node)
                node = 0

class FreeRTOSThreadContext(DebugContext):
    """! @brief Thread context for FreeRTOS."""
    
    # SP/PSP are handled specially, so it is not in these dicts.

    COMMON_REGISTER_OFFSETS = {
                 4: 0, # r4
                 5: 4, # r5
                 6: 8, # r6
                 7: 12, # r7
                 8: 16, # r8
                 9: 20, # r9
                 10: 24, # r10
                 11: 28, # r11
            }

    NOFPU_REGISTER_OFFSETS = {
                 0: 32, # r0
                 1: 36, # r1
                 2: 40, # r2
                 3: 44, # r3
                 12: 48, # r12
                 14: 52, # lr
                 15: 56, # pc
                 16: 60, # xpsr
            }
    NOFPU_REGISTER_OFFSETS.update(COMMON_REGISTER_OFFSETS)

    FPU_BASIC_REGISTER_OFFSETS = {
                -1: 32, # exception LR
                 0: 36, # r0
                 1: 40, # r1
                 2: 44, # r2
                 3: 48, # r3
                 12: 52, # r12
                 14: 56, # lr
                 15: 60, # pc
                 16: 64, # xpsr
            }
    FPU_BASIC_REGISTER_OFFSETS.update(COMMON_REGISTER_OFFSETS)

    FPU_EXTENDED_REGISTER_OFFSETS = {
                -1: 32, # exception LR
                 0x50: 36, # s16
                 0x51: 40, # s17
                 0x52: 44, # s18
                 0x53: 48, # s19
                 0x54: 52, # s20
                 0x55: 56, # s21
                 0x56: 60, # s22
                 0x57: 64, # s23
                 0x58: 68, # s24
                 0x59: 72, # s25
                 0x5a: 76, # s26
                 0x5b: 80, # s27
                 0x5c: 84, # s28
                 0x5d: 88, # s29
                 0x5e: 92, # s30
                 0x5f: 96, # s31
                 0: 100, # r0
                 1: 104, # r1
                 2: 108, # r2
                 3: 112, # r3
                 12: 116, # r12
                 14: 120, # lr
                 15: 124, # pc
                 16: 128, # xpsr
                 0x40: 132, # s0
                 0x41: 136, # s1
                 0x42: 140, # s2
                 0x43: 144, # s3
                 0x44: 148, # s4
                 0x45: 152, # s5
                 0x46: 156, # s6
                 0x47: 160, # s7
                 0x48: 164, # s8
                 0x49: 168, # s9
                 0x4a: 172, # s10
                 0x4b: 176, # s11
                 0x4c: 180, # s12
                 0x4d: 184, # s13
                 0x4e: 188, # s14
                 0x4f: 192, # s15
                 33: 196, # fpscr
                 # (reserved word: 200)
            }
    FPU_EXTENDED_REGISTER_OFFSETS.update(COMMON_REGISTER_OFFSETS)

    def __init__(self, parent, thread):
        super(FreeRTOSThreadContext, self).__init__(parent)
        self._thread = thread
        self._has_fpu = self.core.has_fpu

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
        swStacked = 0x20
        table = self.NOFPU_REGISTER_OFFSETS
        if self._has_fpu:
            try:
                if inException and self.core.is_vector_catch():
                    # Vector catch has just occurred, take live LR
                    exceptionLR = self._parent.read_core_register('lr')
                else:
                    # Read stacked exception return LR.
                    offset = self.FPU_BASIC_REGISTER_OFFSETS[-1]
                    exceptionLR = self._parent.read32(sp + offset)

                # Check bit 4 of the saved exception LR to determine if FPU registers were stacked.
                if (exceptionLR & EXC_RETURN_EXT_FRAME_MASK) != 0:
                    table = self.FPU_BASIC_REGISTER_OFFSETS
                    swStacked = 0x24
                else:
                    table = self.FPU_EXTENDED_REGISTER_OFFSETS
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

class FreeRTOSThread(TargetThread):
    """! @brief A FreeRTOS task."""

    RUNNING = 1
    READY = 2
    BLOCKED = 3
    SUSPENDED = 4
    DELETED = 5

    STATE_NAMES = {
            RUNNING : "Running",
            READY : "Ready",
            BLOCKED : "Blocked",
            SUSPENDED : "Suspended",
            DELETED : "Deleted",
        }

    def __init__(self, targetContext, provider, base):
        super(FreeRTOSThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._base = base
        self._state = FreeRTOSThread.READY
        self._thread_context = FreeRTOSThreadContext(self._target_context, self)

        self._priority = self._target_context.read32(self._base + THREAD_PRIORITY_OFFSET)

        self._name = read_c_string(self._target_context, self._base + THREAD_NAME_OFFSET)
        if len(self._name) == 0:
            self._name = "Unnamed"

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        try:
            return self._target_context.read32(self._base + THREAD_STACK_POINTER_OFFSET)
        except exceptions.TransferError:
            LOG.debug("Transfer error while reading thread's stack pointer @ 0x%08x", self._base + THREAD_STACK_POINTER_OFFSET)
            return 0

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
        return "<FreeRTOSThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

    def __repr__(self):
        return str(self)

class FreeRTOSThreadProvider(ThreadProvider):
    """! @brief Thread provider for FreeRTOS."""

    ## Required FreeRTOS symbols.
    FREERTOS_SYMBOLS = [
        "uxCurrentNumberOfTasks",
        "pxCurrentTCB",
        "pxReadyTasksLists",
        "xDelayedTaskList1",
        "xDelayedTaskList2",
        "xPendingReadyList",
        "uxTopReadyPriority",
        "xSchedulerRunning",
        ]

    def __init__(self, target):
        super(FreeRTOSThreadProvider, self).__init__(target)
        self._symbols = None
        self._total_priorities = 0
        self._threads = {}

    def init(self, symbolProvider):
        # Lookup required symbols.
        self._symbols = self._lookup_symbols(self.FREERTOS_SYMBOLS, symbolProvider)
        if self._symbols is None:
            return False

        # Look up optional xSuspendedTaskList, controlled by INCLUDE_vTaskSuspend
        suspendedTaskListSym = self._lookup_symbols(["xSuspendedTaskList"], symbolProvider)
        if suspendedTaskListSym is not None:
            self._symbols['xSuspendedTaskList'] = suspendedTaskListSym['xSuspendedTaskList']

        # Look up optional xTasksWaitingTermination, controlled by INCLUDE_vTaskDelete
        tasksWaitingTerminationSym = self._lookup_symbols(["xTasksWaitingTermination"], symbolProvider)
        if tasksWaitingTerminationSym is not None:
            self._symbols['xTasksWaitingTermination'] = tasksWaitingTerminationSym['xTasksWaitingTermination']

        # Look up vPortEnableVFP() to determine if the FreeRTOS port supports the FPU.
        vPortEnableVFP = self._lookup_symbols(["vPortEnableVFP"], symbolProvider)
        self._fpu_port = vPortEnableVFP is not None

        elfOptHelp = " Try using the --elf option." if self._target.elf is None else ""

        # Check for the expected list size. These two symbols are each a single list and xDelayedTaskList2
        # immediately follows xDelayedTaskList1, so we can just subtract their addresses to get the
        # size of a single list.
        delta = self._symbols['xDelayedTaskList2'] - self._symbols['xDelayedTaskList1']
        delta = self._get_elf_symbol_size('xDelayedTaskList1', self._symbols['xDelayedTaskList1'], delta)
        if delta != LIST_SIZE:
            LOG.warning("FreeRTOS: list size is unexpected, maybe an unsupported configuration of FreeRTOS." + elfOptHelp)
            return False

        # xDelayedTaskList1 immediately follows pxReadyTasksLists, so subtracting their addresses gives
        # us the total size of the pxReadyTaskLists array. But not trustworthy. Compiler can rearrange things
        delta = self._symbols['xDelayedTaskList1'] - self._symbols['pxReadyTasksLists']
        delta = self._get_elf_symbol_size('pxReadyTasksLists', self._symbols['pxReadyTasksLists'], delta);
        if delta % LIST_SIZE:
            LOG.warning("FreeRTOS: pxReadyTasksLists size is unexpected, maybe an unsupported version of FreeRTOS." + elfOptHelp)
            return False
        self._total_priorities = delta // LIST_SIZE
        if self._total_priorities > FREERTOS_MAX_PRIORITIES:
            LOG.warning("FreeRTOS: number of priorities is too large (%d)." + elfOptHelp, self._total_priorities)
            return False
        LOG.debug("FreeRTOS: number of priorities is %d", self._total_priorities)

        self._target.session.subscribe(self.event_handler, Target.Event.POST_FLASH_PROGRAM)
        self._target.session.subscribe(self.event_handler, Target.Event.POST_RESET)

        return True

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        LOG.debug("FreeRTOS: invalidating threads list: %s" % (repr(notification)))
        self.invalidate();

    def _build_thread_list(self):
        newThreads = {}

        # Read the number of threads.
        threadCount = self._target_context.read32(self._symbols['uxCurrentNumberOfTasks'])

        # Read the current thread.
        currentThread = self._target_context.read32(self._symbols['pxCurrentTCB'])

        # We should only be building the thread list if the scheduler is running, so a zero thread
        # count or a null current thread means something is bizarrely wrong.
        if threadCount == 0 or currentThread == 0:
            LOG.warning("FreeRTOS: no threads even though the scheduler is running")
            return

        # Read the top ready priority.
        topPriority = self._target_context.read32(self._symbols['uxTopReadyPriority'])

        # Handle an uxTopReadyPriority value larger than the number of lists. This is most likely
        # caused by the configUSE_PORT_OPTIMISED_TASK_SELECTION option being enabled, which treats
        # uxTopReadyPriority as a bitmap instead of integer. This is ok because uxTopReadyPriority
        # in optimised mode will always be >= the actual top priority.
        if topPriority >= self._total_priorities:
            topPriority = self._total_priorities - 1

        # Build up list of all the thread lists we need to scan.
        listsToRead = []
        for i in range(topPriority + 1):
            listsToRead.append((self._symbols['pxReadyTasksLists'] + i * LIST_SIZE, FreeRTOSThread.READY))

        listsToRead.append((self._symbols['xDelayedTaskList1'], FreeRTOSThread.BLOCKED))
        listsToRead.append((self._symbols['xDelayedTaskList2'], FreeRTOSThread.BLOCKED))
        listsToRead.append((self._symbols['xPendingReadyList'], FreeRTOSThread.READY))
        if 'xSuspendedTaskList' in self._symbols:
            listsToRead.append((self._symbols['xSuspendedTaskList'], FreeRTOSThread.SUSPENDED))
        if 'xTasksWaitingTermination' in self._symbols:
            listsToRead.append((self._symbols['xTasksWaitingTermination'], FreeRTOSThread.DELETED))

        for listPtr, state in listsToRead:
            for threadBase in TargetList(self._target_context, listPtr):
                try:
                    # Don't try adding more threads than the number of threads that FreeRTOS says there are.
                    if len(newThreads) >= threadCount:
                        break

                    # Reuse existing thread objects.
                    if threadBase in self._threads:
                        t = self._threads[threadBase]
                    else:
                        t = FreeRTOSThread(self._target_context, self, threadBase)

                    # Set thread state.
                    if threadBase == currentThread:
                        t.state = FreeRTOSThread.RUNNING
                    else:
                        t.state = state

                    LOG.debug("Thread 0x%08x (%s)", threadBase, t.name)
                    newThreads[t.unique_id] = t
                except exceptions.TransferError:
                    LOG.debug("TransferError while examining thread 0x%08x", threadBase)

        if len(newThreads) != threadCount:
            LOG.warning("FreeRTOS: thread count mismatch")

        # Create fake handler mode thread.
        if self._target_context.read_core_register('ipsr') > 0:
            LOG.debug("FreeRTOS: creating handler mode thread")
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
        return self._target_context.read32(self._symbols['pxCurrentTCB'])

    def get_is_running(self):
        if self._symbols is None:
            return False
        return self._target_context.read32(self._symbols['xSchedulerRunning']) != 0

    def _get_elf_symbol_size(self, name, addr, calculated_size):
        if self._target.elf is not None:
            symInfo = None
            try:
                symInfo = self._target.elf.symbol_decoder.get_symbol_for_name(name)
            except RuntimeError as e:
                LOG.error("FreeRTOS elf symbol query failed for (%s) with an exception. " + str(e),
                    name, exc_info=self._target.session.log_tracebacks)

            # Simple checks to make sure gdb is looking at the same executable we are
            if symInfo is None:
                LOG.debug("FreeRTOS symbol '%s' not found in elf file", name)
            elif symInfo.address != addr:
                LOG.debug("FreeRTOS symbol '%s' address mismatch elf=0x%08x, gdb=0x%08x", name, symInfo.address, addr)
            else:
                if calculated_size != symInfo.size:
                    LOG.info("FreeRTOS symbol '%s' size from elf (%ld) != calculated size (%ld). Using elf value.",
                        name, symInfo.size, calculated_size)
                else:
                    LOG.debug("FreeRTOS symbol '%s' size (%ld) from elf file matches calculated value", name, calculated_size)
                return symInfo.size
        return calculated_size

class FreeRTOSPlugin(Plugin):
    """! @brief Plugin class for FreeRTOS."""
    
    def load(self):
        return FreeRTOSThreadProvider
    
    @property
    def name(self):
        return "freertos"
    
    @property
    def description(self):
        return "FreeRTOS"
