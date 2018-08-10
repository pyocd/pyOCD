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
log = logging.getLogger("rtx5")

## @brief
class RTXThreadContext(DebugContext):
    # SP/PSP are handled specially, so it is not in these dicts.

    NOFPU_REGISTER_OFFSETS = {
                 4: 0, # r4
                 5: 4, # r5
                 6: 8, # r6
                 7: 12, # r7
                 8: 16, # r8
                 9: 20, # r9
                 10: 24, # r10
                 11: 28, # r11
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
        super(RTXThreadContext, self).__init__(parentContext.core)
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
            return self._parent.readCoreRegistersRaw(reg_list)

        sp = self._thread.get_stack_pointer()

        # Determine which register offset table to use and the offsets past the saved state.
        realSpOffset = 0x40
        realSpExceptionOffset = 0x20
        table = self.NOFPU_REGISTER_OFFSETS
        if self._has_fpu:
            try:
                # Read stacked exception return LR.
                exceptionLR = self._thread.get_stack_frame()

                # Check bit 4 of the saved exception LR to determine if FPU registers were stacked.
                if (exceptionLR & (1 << 4)) == 0:
                    table = self.FPU_REGISTER_OFFSETS
                    realSpOffset = 0xc8
                    realSpExceptionOffset = 0x68
            except DAPAccess.TransferError:
                log.debug("Transfer error while reading thread's saved LR")

        for reg in reg_list:
            # Check for regs we can't access.
            if isCurrent and inException:
                if reg in self.EXCEPTION_UNAVAILABLE_REGS:
                    reg_vals.append(0)
                    continue
                if reg == 18 or reg == 13: # PSP
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

STATE_OFFSET = 1
NAME_OFFSET = 4
STACKFRAME_OFFSET = 34
SP_OFFSET = 56

## @brief Base class representing a thread on the target.
class RTXTargetThread(TargetThread):
    STATES = {
         0: "Inactive",
         1: "Ready",
         2: "Running",
         3: "Blocked",
         4: "Terminated",
    }
    def __init__(self, targetContext, provider, base):
        super(RTXTargetThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider
        self._base = base
        self._thread_context = RTXThreadContext(self._target_context, self)
        self._has_fpu = self._thread_context.core.has_fpu
        name_ptr = self._target_context.read32(self._base + NAME_OFFSET)
        self._name = read_c_string(self._target_context, name_ptr)
        log.debug('RTXTargetThread 0x%x' % base)

    @property
    def unique_id(self):
        # There is no other meaningful ID than base address
        return self._base

    @property
    def context(self):
        return self._thread_context

    @property
    def description(self):
        state = self._target_context.read8(self._base + STATE_OFFSET) & 0x0F

        return self.STATES[state] + ' 0x%x' % self._base

    @property
    def name(self):
        return self._name

    @property
    def is_current(self):
        return self._provider.get_current_thread_id() == self._base

    def get_stack_pointer(self):
        if self.is_current:
            # Read live process stack.
            sp = self._target_context.readCoreRegister('psp')
        else:
            # Get stack pointer saved in thread struct.
            try:
                sp = self._target_context.read32(self._base + SP_OFFSET)
            except DAPAccess.TransferError:
                log.debug("Transfer error while reading thread's stack pointer @ 0x%08x", self._base + SP_OFFSET)
        return sp

    def get_stack_frame(self):
        return self._target_context.read8(self._base + STACKFRAME_OFFSET)


CURRENT_OFFSET = 20
THREADLIST_OFFSET = 36
DELAYLIST_OFFSET = 44
WAITLIST_OFFSET = 48
THREADNEXT_OFFSET = 8
DELAYNEXT_OFFSET = 16

## @brief Base class for RTOS support plugins.
class RTX5ThreadProvider(ThreadProvider):
    def __init__(self, target):
        super(RTX5ThreadProvider, self).__init__(target)

    def init(self, symbolProvider):
        # Lookup required symbols.
        self._osRtxInfo =symbolProvider.get_symbol_value('osRtxInfo')
        if self._osRtxInfo is None:
            return False
        log.debug('init(), found osRtxInfo')
        self._threads = {}
        return True

    def get_threads(self):
        if not self.is_enabled:
            return []
        return list(self._threads.values())

    def invalidate(self):
        self._threads = {}

    def event_handler(self, notification):
        # Invalidate threads list if flash is reprogrammed.
        self.invalidate();

    def _build_thread_list(self):
        log.debug('_build_thread_list()')
        self._readylist = self._osRtxInfo + THREADLIST_OFFSET
        self._delaylist = self._osRtxInfo + DELAYLIST_OFFSET
        self._waitlist = self._osRtxInfo + WAITLIST_OFFSET

        # Currently running Thread
        thread = self._target_context.read32(self._osRtxInfo + CURRENT_OFFSET)
        if thread:
            log.debug('found RUNNING thread %x' % thread)
            if not thread in self._threads:
                self._threads[thread] = RTXTargetThread(self._target_context, self, thread)
            self._current_id = thread
            self._current = self._threads[thread]

        # Scan Ready list
        thread = self._target_context.read32(self._readylist)
        while thread:
            log.debug('found READY thread %x' % thread)
            # targetContext, provider, base
            if not thread in self._threads:
                self._threads[thread] = RTXTargetThread(self._target_context, self, thread)
            thread = self._target_context.read32(thread+THREADNEXT_OFFSET)

        # Delay list
        thread = self._target_context.read32(self._delaylist)
        while thread:
            log.debug('found DELAY thread %x' % thread)
            if not thread in self._threads:
                self._threads[thread] = RTXTargetThread(self._target_context, self, thread)
            thread = self._target_context.read32(thread+DELAYNEXT_OFFSET)

        # Wait list
        thread = self._target_context.read32(self._waitlist)
        while thread:
            log.debug('found WAIT thread %x' % thread)
            if not thread in self._threads:
                self._threads[thread] = RTXTargetThread(self._target_context, self, thread)
            thread = self._target_context.read32(thread+DELAYNEXT_OFFSET)

        log.debug('found %d threads' % len(self._threads))

    def get_thread(self, threadId):
        log.debug('get_thread()')
        if not threadId in self._threads:
            return None
        return self._threads[threadId]

    @property
    def is_enabled(self):
        log.debug('is_enabled()')
        self.update_threads()  # Has caching, so not a bottleneck
        return len(self._threads) > 0

    @property
    def current_thread(self):
        return self._current

    def is_valid_thread_id(self, threadId):
        return self._threads[threadId] is not None

    def get_current_thread_id(self):
        return self._current_id
