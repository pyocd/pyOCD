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

import logging

from .provider import (TargetThread, ThreadProvider)
from .common import (
    nbits,
    read_c_string,
    build_register_offset_table,
    HandlerModeThread,
    EXC_RETURN_FTYPE_BIT,
    EXC_RETURN_DCRS_BIT,
    )
from ..core import exceptions
from ..core.target import Target
from ..core.plugin import Plugin
from ..debug.context import DebugContext
from ..coresight.cortex_m_core_registers import index_for_reg
from ..coresight.core_ids import CoreArchitecture

# FreeRTOS 10.x MPU support:
#
# All MPU-enabled ports, both v7-M and v8-M, set portTOTAL_NUM_REGIONS == 9.
#
# v7-M:
# sizeof(xMPU_REGION_REGISTERS) = 8 (sizeof(uint32_t) * 2)
# sizeof(xMPU_SETTINGS) = 72 (portTOTAL_NUM_REGIONS * sizeof(xMPU_REGION_REGISTERS))
#
# v8-M:
# sizeof(xMPU_REGION_REGISTERS) = 8 (sizeof(uint32_t) * 2)
# sizeof(xMPU_SETTINGS) = 76 (sizeof(uint32_t) + portTOTAL_NUM_REGIONS * sizeof(xMPU_REGION_REGISTERS))

V7M_MPU_SETTING_SIZE = 72
V8M_MPU_SETTING_SIZE = 76

# Create a logger for this module.
LOG = logging.getLogger(__name__)

class FreeRTOSLinkedList(object):
    """@brief Iterator for FreeRTOS linked list using capabilities.

    Linked lists in FreeRTOS have a fairly unusual structure.

    Each list node, the `ListItem_t` type, contains:
    - Item value.
    - Pointer to owning object, such as a TCB.
    - Pointer to the list itself, i.e. the `List_t` object.

    Lists are double-linked and circular, with a special sentinel end node. The lists have both an item count
    and a current index pointer that can point to any node, including the end node.

    An empty list has an item count of zero and contains only the end node. So the index will point to the
    end node, and the end node points to itself in both directions.
    """

    LIST_COUNT_OFFSET = 0
    LIST_END_ITEM_OFFSET = 8
    LIST_NODE_NEXT_OFFSET = 4
    LIST_NODE_OBJECT_OFFSET = 12

    def __init__(self, context, ptr):
        """! @brief Constructor.
        @param self This object.
        @param context The debug context used to read memory.
        @param ptr Address of the `List_t` object.
        """
        self._context = context
        self._list = ptr
        self._end_node = ptr + self.LIST_END_ITEM_OFFSET
        self.count = self._context.read32(self._list + self.LIST_COUNT_OFFSET)

    def __iter__(self):
        # Nothing to return if there are no items.
        if self.count == 0:
            return
        prev = -1
        found_count = 0

        # Start with node that the end node's next pointer points to (i.e. the first node).
        node = self._context.read32(self._end_node + self.LIST_NODE_NEXT_OFFSET)
        if node == 0:
            LOG.warning("list %#010x has unexpected NULL next pointer from end node", self._list)
            return

        # Iterate over the list and yield objects associated with each node.
        # Exit when we encounter the end node again, or if we have found all expected items.
        while (node != self._end_node) and (found_count < self.count):
            try:
                # Read the object from the node.
                obj = self._context.read32(node + self.LIST_NODE_OBJECT_OFFSET)
                yield obj
                found_count += 1

                # Read next list node pointer.
                prev = node
                node = self._context.read32(node + self.LIST_NODE_NEXT_OFFSET)

                if node == 0:
                    LOG.warning("list %#010x has unexpected NULL next pointer from node %#010x",
                            self._list, prev)
                    return
            except exceptions.TransferError:
                LOG.warning("TransferError while reading list elements (list=0x%08x, node=0x%08x, "
                            "prev=0x%08x), terminating list",
                            self._list, node, exc_info=self._context.session.log_tracebacks)
                return

        # Check that we found all the expected items.
        if found_count != self.count:
            LOG.warning("list %#010x has fewer items than expected (found %i, should have %i)",
                    found_count, self.count)

REGS_R4_R11 = ['r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11']

REGS_SW_NO_MPU_V7M = REGS_R4_R11
REGS_SW_MPU_V7M = ['control'] + REGS_R4_R11

REGS_SW_NO_MPU_V8M = ['psplim_s', '_exc_return_'] + REGS_R4_R11
REGS_SW_MPU_V8M = ['psplim_s', 'control', '_exc_return_'] + REGS_R4_R11

REGS_HW_DCRS_0 = ['_signature_', '_reserved0_'] + REGS_R4_R11
REGS_HW_STANDARD = ['r0', 'r1', 'r2', 'r3', 'r12', 'lr', 'pc', 'xpsr']

REGS_HW_FP_STANDARD_CTX = [('s%i' % n) for n in range(16)] + ['fpscr', '_reserved1_']
REGS_FP_HI = [('s%i' % n) for n in range(16, 32)] # s16-s31

def _get_table_regs_v7m(fpu, ftype, mpu):
    """@brief Construct the full v6-M/v7-M FreeRTOS register sequence given stack frame options."""
    if mpu:
        regs = REGS_SW_MPU_V7M
    else:
        regs = REGS_SW_NO_MPU_V7M
    # Note we don't use += here because that updates the original list!
    if fpu:
        regs + regs + ['_exc_return_']
        if ftype == 0:
            regs = regs + REGS_FP_HI
    regs = regs + REGS_HW_STANDARD
    if ftype == 0:
        regs = regs + REGS_HW_FP_STANDARD_CTX
    return regs

def _get_table_regs_v8m(dcrs, ftype, mpu):
    """@brief Construct the full v8-M FreeRTOS register sequence given stack frame options.

    For certain combinations, FreeRTOS 10.x unnecessarily saves registers that were already saved on the
    stack by the hardware. In these cases, the offset we use will be set to the hardware-written register.
    """
    if mpu:
        regs = REGS_SW_MPU_V8M
    else:
        regs = REGS_SW_NO_MPU_V8M
    # Note we don't use += here because that updates the original list!
    if ftype == 0:
        regs = regs + REGS_FP_HI
    if dcrs == 0:
        regs = regs + REGS_HW_DCRS_0
    regs = regs + REGS_HW_STANDARD
    if ftype == 0:
        regs = regs + REGS_HW_FP_STANDARD_CTX
        if dcrs == 0:
            regs = regs + REGS_FP_HI
    return regs

class FreeRTOSThreadContext(DebugContext):
    """@brief Thread context for FreeRTOS."""

    # FreeRTOS 10.x stack layout for v6-M and v7-M:
    #
    #   <new SP here, lowest addr>
    #   <sw> control                [configENABLE_MPU==1]
    #   <sw> r4-r11
    #   <sw> exc_return (lr)        [configENABLE_FPU==1]
    #   <sw> s16-s31                [configENABLE_FPU==1 && EXC_RETURN.FType==0]
    #   <hw> r0-r3, r12-r15, xpsr
    #   <hw> s0-s15                 [FPU && EXC_RETURN.FType==0]
    #   <hw> fpscr                  [FPU && EXC_RETURN.FType==0]
    #   <hw> (reserved word)        [FPU && EXC_RETURN.FType==0]
    #   <orig SP here, highest addr>
    #
    # Notes:
    # - FreeRTOS does not support MPU on M0/+.
    # - No non-FPU builds, EXC_RETURN is saved on temporarily on MSP during the call to vTaskSwitchContext.

    # FreeRTOS 10.x stack layout for v8-M:
    #
    #   <new SP here, lowest addr>
    #   <sw> psplim
    #   <sw> control                [configENABLE_MPU==1]
    #   <sw> exc_return (lr)
    #   <sw> r4-r11
    #   <sw> s16-s31                [EXC_RETURN.FType==0]
    # <todo> secure context shite   [SECCTX]
    #   <hw> integrity signature    [EXC_RETURN.DCRS==0]
    #   <hw> (reserved word)        [EXC_RETURN.DCRS==0]
    #   <hw> r4-r11                 [EXC_RETURN.DCRS==0]
    #   <hw> r0-r3, r12-r15, xpsr
    #   <hw> s0-s15                 [EXC_RETURN.FType==0]
    #   <hw> fpscr                  [EXC_RETURN.FType==0]
    #   <hw> (reserved word)        [EXC_RETURN.FType==0]
    #   <hw> s16-s31                [EXC_RETURN.DCRS==0 && EXC_RETURN.FType==0]
    #   <orig SP here, highest addr>
    #
    # combinations:
    #   - DCRS=={0,1}, FType=={0,1}, use_mpu={0,1}
    #
    # Note that FreeRTOS currently does not optimize for whether the extended secure state context
    # is already on the stack (EXC_RETURN.DCRS). This can happen under these conditions:
    #   - FreeRTOS running in S world: by R_BLQS, it is IMPDEF whether a S exception taken from S background
    #       context will stack additional state.
    #   -  FreeRTOS running in S world: by R_PLHM, a NS exception taken from S background causes the
    #       additional context to be saved. Unlikely, because FreeRTOS in S world is intended to stay in
    #       the S world only.

    # TODO secure context
    # TODO FP lazy state
    # TODO psplim for right state

    ## Map of v6-M, v7-M register offset maps.
    REGISTER_TABLES_V7M = {
            (fpu, ftype, mpu): build_register_offset_table(_get_table_regs_v7m(fpu, ftype, mpu))
            for fpu, ftype, mpu in (
                    # This is just a binary progression...
                    nbits(3, x) for x in range(8)
                    )
        }

    ## Map of v8-M register offset maps.
    REGISTER_TABLES_V8M = {
            (dcrs, ftype, mpu): build_register_offset_table(_get_table_regs_v8m(dcrs, ftype, mpu))
            for dcrs, ftype, mpu in (
                    # This is just a binary progression...
                    nbits(3, x) for x in range(8)
                    )
        }

    V7M_EXC_RETURN_OFFSET = 0

    ## Offset to the EXC_RETURN value saved on a thread's stack frame.
    #
    # Map from <MPU support> -> offset
    V8M_EXC_RETURN_OFFSET = {
    #   MPU    Offset
        False: 4,  # psplim, exc_return, ...
        True:  8,  # psplim, control, exc_return, ...
        }

    FTYPE_BASIC_FRAME = 1
    FTYPE_EXT_FRAME = 0

    BASIC_EXC_RETURN = 0xfffffffd

    def __init__(self, parent, thread):
        super(FreeRTOSThreadContext, self).__init__(parent)
        self._thread = thread
        self._use_fpu = self.core.has_fpu and thread.provider.is_fpu_enabled
        self._use_mpu = thread.provider.is_mpu_enabled
        self._use_secure_context = thread.provider.is_secure_context_enabled

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

        # Get the EXC_RETURN to examine.
        if inException and self.core.is_vector_catch():
            # Vector catch has just occurred, take live LR
            exc_return = self._parent.read_core_register('lr')
        else:
            # Read stacked exception return LR. FreeRTOS uses different stack layouts for v7-M and v8-M.
            if self.core.architecture in (CoreArchitecture.ARMv8M_BASE, CoreArchitecture.ARMv8M_MAIN):
                offset = self.V8M_EXC_RETURN_OFFSET[self._use_mpu]
            elif self._use_fpu:
                offset = self.V7M_EXC_RETURN_OFFSET
            else:
                # v6-M and v7-M non-FPU builds don't save EXC_RETURN on the stack, so use a fixed value.
                offset = None
                exc_return = self.BASIC_EXC_RETURN

            if offset is not None:
                # Read stacked exception return LR. The saved EXC_RETURN is always at the top of the stack.
                try:
                    exc_return = self._parent.read32(sp + offset)
                except exceptions.TransferError as err:
                    LOG.warning("Transfer error while reading thread's saved LR: %s", err, exc_info=True)
                    exc_return = self.BASIC_EXC_RETURN # Just a guess!

        # Extract bits from EXC_RETURN.
        ftype = (exc_return >> EXC_RETURN_FTYPE_BIT) & 1
        dcrs = (exc_return >> EXC_RETURN_DCRS_BIT) & 1

        LOG.debug("%s: isCurrent=%i inException=%i exc_return=%#010x ftype=%i dcrs=%i",
            self._thread, isCurrent, inException, exc_return, ftype, dcrs)

        # Determine the hw and sw stacked register sizes.
        if self.core.architecture in (CoreArchitecture.ARMv8M_BASE, CoreArchitecture.ARMv8M_MAIN):
            swStacked = 0x28 # r4-r11, exc_return, psplim
            hwStacked = 0x20 # r0-r3, r12, lr, pc, xpsr
            if self._use_mpu:
                swStacked += 4 # control
            if ftype == self.FTYPE_EXT_FRAME:
                swStacked += 0x40 # s16-s31
                hwStacked += 0x48 # s0-s15, fpscr, reserved
            if dcrs == 0:
                hwStacked += 0x28 # signature, reserved, r4-r11
                if ftype == self.FTYPE_EXT_FRAME:
                    hwStacked += 0x40 # s16-s31
        else:
            swStacked = 0x20 # r4-r11
            hwStacked = 0x20 # r0-r3, r12, lr, pc, xpsr
            if self._use_mpu:
                swStacked += 4 # control
            if self._use_fpu:
                swStacked += 4 # exc_return
                if ftype == self.FTYPE_EXT_FRAME:
                    swStacked += 0x40 # s16-s31
                    hwStacked += 0x48 # s0-s15, fpscr, reserved

        LOG.debug("%s: swStacked=%i hwStacked=%i", self._thread, swStacked, hwStacked)

        # Sanity check for FPU.
        if (ftype == self.FTYPE_EXT_FRAME) and not self._use_fpu:
            raise exceptions.CoreRegisterAccessError(
                    "FreeRTOS thread has flag set indicating FPU registers are saved, but FPU support is "
                    "not enabled.")

        # Look up the register offset table to use.
        if self.core.architecture in (CoreArchitecture.ARMv8M_BASE, CoreArchitecture.ARMv8M_MAIN):
            table = self.REGISTER_TABLES_V8M[(dcrs, ftype, int(self._use_mpu))]
        else:
            table = self.REGISTER_TABLES_V7M[(int(self._use_fpu), ftype, int(self._use_mpu))]
        LOG.debug("%s: table=%r", self._thread, table)

        for reg in reg_list:
            # Must handle stack pointer specially. We report the original SP as it was on the "live" thread
            # by skipping over the saved stack frame.
            if reg == 13:
                if inException:
                    # In an exception, only the hardware has stacked registers.
                    reg_vals.append(sp + hwStacked)
                else:
                    #
                    reg_vals.append(sp + swStacked + hwStacked)
                continue

            # Look up offset for this register on the stack.
            spOffset = table.get(reg, None)
            if spOffset is None:
                reg_vals.append(self._parent.read_core_register_raw(reg))
                continue

            # Used below to identify registers that are not present on the stack. To get those, we'd have
            # to unwind the stack using debug info.
            if inException:
                spOffset -= swStacked

            try:
                if spOffset >= 0:
                    reg_vals.append(self._parent.read32(sp + spOffset))
                else:
                    # Not available - try live one
                    # TODO return None here for unavailable register.
                    reg_vals.append(self._parent.read_core_register_raw(reg))
            except exceptions.TransferError:
                reg_vals.append(0)

        return reg_vals

class FreeRTOSThread(TargetThread):
    """@brief A FreeRTOS task."""

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

    THREAD_STACK_POINTER_OFFSET = 0
    THREAD_PRIORITY_OFFSET = 44 # + VxM_MPU_SETTINGS_SIZE
    THREAD_NAME_OFFSET = 52 # + VxM_MPU_SETTINGS_SIZE

    def __init__(self, targetContext, provider, base):
        super(FreeRTOSThread, self).__init__(targetContext, provider, base)
        self._base = base
        self._state = FreeRTOSThread.READY
        self._thread_context = FreeRTOSThreadContext(self._target_context, self)

        self._priority = self._target_context.read32(self._base + self.THREAD_PRIORITY_OFFSET)

        self._name = read_c_string(self._target_context, self._base + self.THREAD_NAME_OFFSET)
        if len(self._name) == 0:
            self._name = "Unnamed"

    def get_stack_pointer(self):
        # Get stack pointer saved in thread struct.
        try:
            return self._target_context.read32(self._base + self.THREAD_STACK_POINTER_OFFSET)
        except exceptions.TransferError:
            LOG.debug("Transfer error while reading thread's stack pointer @ 0x%08x",
                    self._base + self.THREAD_STACK_POINTER_OFFSET)
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

    def __repr__(self):
        return "<FreeRTOSThread@0x%08x id=%x name=%s>" % (id(self), self.unique_id, self.name)

class FreeRTOSThreadProvider(ThreadProvider):
    """@brief Thread provider for FreeRTOS.
    @todo Support FreeRTOSDebugConfig from NXP's freertos_tasks_c_additions.h.
    """

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

    FREERTOS_MAX_PRIORITIES	= 63

    LIST_SIZE = 20

    def __init__(self, target):
        super(FreeRTOSThreadProvider, self).__init__(target)
        self._symbols = None
        self._total_priorities = 0
        self._threads = {}
        self._fpu_port = False
        self._mpu_port = False
        self._secure_context_port = False

    @property
    def is_fpu_enabled(self):
        """@brief Whether FPU support is enabled in the FreeRTOS configuration."""
        return self._fpu_port

    @property
    def is_mpu_enabled(self):
        """@brief Whether MPU support is enabled in the FreeRTOS configuration."""
        return self._mpu_port

    @property
    def is_secure_context_enabled(self):
        """@brief Whether secure context support is enabled in the FreeRTOS configuration."""
        return self._secure_context_port

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

        # Look up vPortEnableVFP() (v7-M) or prvSetupFPU() (v8-M) to determine if the FreeRTOS port
        # supports the FPU.
        vPortEnableVFP = self._lookup_symbols(["vPortEnableVFP"], symbolProvider)
        prvSetupFPU = self._lookup_symbols(["prvSetupFPU"], symbolProvider)
        self._fpu_port = (vPortEnableVFP is not None) or (prvSetupFPU is not None)

        # Look up vPortStoreTaskMPUSettings() to determine if MPU support is enabled.
        vPortStoreTaskMPUSettings = self._lookup_symbols(["vPortStoreTaskMPUSettings"], symbolProvider)
        self._mpu_port = vPortStoreTaskMPUSettings is not None

        # Look up vPortAllocateSecureContext() to determine if secure context (TrustZone-M) support is enabled.
        vPortAllocateSecureContext = self._lookup_symbols(["vPortAllocateSecureContext"], symbolProvider)
        self._secure_context_port = vPortAllocateSecureContext is not None

        LOG.debug("FreeRTOS: FPU=%i MPU=%i SECCTX=%i", self._fpu_port, self._mpu_port, self._secure_context_port)

        elfOptHelp = " Try using the --elf option." if self._target.elf is None else ""

        # Check for the expected list size. These two symbols are each a single list and xDelayedTaskList2
        # immediately follows xDelayedTaskList1, so we can just subtract their addresses to get the
        # size of a single list.
        delta = self._symbols['xDelayedTaskList2'] - self._symbols['xDelayedTaskList1']
        delta = self._get_elf_symbol_size('xDelayedTaskList1', self._symbols['xDelayedTaskList1'], delta)
        if delta != self.LIST_SIZE:
            LOG.warning("FreeRTOS: list size is unexpected, maybe an unsupported configuration of FreeRTOS." + elfOptHelp)
            return False

        # xDelayedTaskList1 immediately follows pxReadyTasksLists, so subtracting their addresses gives
        # us the total size of the pxReadyTaskLists array. But not trustworthy. Compiler can rearrange things
        delta = self._symbols['xDelayedTaskList1'] - self._symbols['pxReadyTasksLists']
        delta = self._get_elf_symbol_size('pxReadyTasksLists', self._symbols['pxReadyTasksLists'], delta);
        if delta % self.LIST_SIZE:
            LOG.warning("FreeRTOS: pxReadyTasksLists size is unexpected, maybe an unsupported version of FreeRTOS." + elfOptHelp)
            return False
        self._total_priorities = delta // self.LIST_SIZE
        if self._total_priorities > self.FREERTOS_MAX_PRIORITIES:
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
            listsToRead.append((self._symbols['pxReadyTasksLists'] + i * self.LIST_SIZE, FreeRTOSThread.READY))

        listsToRead.append((self._symbols['xDelayedTaskList1'], FreeRTOSThread.BLOCKED))
        listsToRead.append((self._symbols['xDelayedTaskList2'], FreeRTOSThread.BLOCKED))
        listsToRead.append((self._symbols['xPendingReadyList'], FreeRTOSThread.READY))
        if 'xSuspendedTaskList' in self._symbols:
            listsToRead.append((self._symbols['xSuspendedTaskList'], FreeRTOSThread.SUSPENDED))
        if 'xTasksWaitingTermination' in self._symbols:
            listsToRead.append((self._symbols['xTasksWaitingTermination'], FreeRTOSThread.DELETED))

        for listPtr, state in listsToRead:
            for threadBase in FreeRTOSLinkedList(self._target_context, listPtr):
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
        try:
            return self._target_context.read32(self._symbols['xSchedulerRunning']) != 0
        except exceptions.TransferFaultError:
            LOG.warn("FreeRTOS: read running state failed, target memory might not be initialized yet.")
            return False


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
    """@brief Plugin class for FreeRTOS."""

    def load(self):
        return FreeRTOSThreadProvider

    @property
    def name(self):
        return "freertos"

    @property
    def description(self):
        return "FreeRTOS"
