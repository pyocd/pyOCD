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
from ..debug.context import DebugContext
from ..coresight.cortex_m import (CORE_REGISTER, register_name_to_index)
from pyOCD.pyDAPAccess import DAPAccess
import logging

LIST_NODE_NEXT_OFFSET = 0
LIST_NODE_OBJ_OFFSET= 8

## @brief Reads a null-terminated C string from the target.
def read_c_string(context, ptr):
    if ptr == 0:
        return ""

    s = ""
    done = False
    count = 0
    badCount = 0
    try:
        while not done and count < 256:
            data = context.readBlockMemoryUnaligned8(ptr, 16)
            ptr += 16
            count += 16

            for c in data:
                if c == 0:
                    done = True
                    break
                elif c > 127:
                    # Replace non-ASCII characters. If there is a run of invalid characters longer
                    # than 4, then terminate the string early.
                    badCount += 1
                    if badCount > 4:
                        done = True
                        break
                    s += '?'
                else:
                    s += chr(c)
                    badCount = 0
    except DAPAccess.TransferError:
        logging.debug("TransferError while trying to read 16 bytes at 0x%08x", ptr)

    return s

## @brief Standard Cortex-M register stacking context.
class CommonThreadContext(DebugContext):
    # SP is handled specially, so it is not in this dict.
    CORE_REGISTER_OFFSETS = {
                 0: 32, # r0
                 1: 36, # r1
                 2: 40, # r2
                 3: 44, # r3
                 4: 0, # r4
                 5: 4, # r5
                 6: 8, # r6
                 7: 12, # r7
                 8: 16, # r8
                 9: 20, # r9
                 10: 24, # r10
                 11: 28, # r11
                 12: 48, # r12
                 14: 52, # lr
                 15: 56, # pc
                 16: 60, # xpsr
            }

    def __init__(self, parentContext, thread):
        super(CommonThreadContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._thread = thread

    def readCoreRegistersRaw(self, reg_list):
        reg_list = [register_name_to_index(reg) for reg in reg_list]
        reg_vals = []

        inException = self._get_ipsr() > 0
        isCurrent = self._is_current()

        sp = self._get_stack_pointer()
        saveSp = sp
        if not isCurrent:
            sp -= 0x40
        elif inException:
            sp -= 0x20

        for reg in reg_list:
            if isCurrent:
                if not inException:
                    # Not in an exception, so just read the live register.
                    reg_vals.append(self._core.readCoreRegisterRaw(reg))
                    continue
                else:
                    # Check for regs we can't access.
                    if reg in (4, 5, 6, 7, 8, 9, 10, 11):
                        reg_vals.append(0)
                        continue

            # Must handle stack pointer specially.
            if reg == 13:
                reg_vals.append(saveSp)
                continue

            spOffset = self.CORE_REGISTER_OFFSETS.get(reg, None)
            if spOffset is None:
                reg_vals.append(self._core.readCoreRegisterRaw(reg))
                continue
            if isCurrent and inException:
                spOffset -= 0x20

            try:
                reg_vals.append(self._core.read32(sp + spOffset))
            except DAPAccess.TransferError:
                reg_vals.append(0)

        return reg_vals

    def _get_stack_pointer(self):
        sp = 0
        if self._is_current():
            # Read live process stack.
            sp = self._core.readCoreRegister('sp')

            # In IRQ context, we have to adjust for hw saved state.
            if self._get_ipsr() > 0:
                sp += 0x20
        else:
            # Get stack pointer saved in thread struct.
            sp = self._core.read32(self._thread._base + THREAD_STACK_POINTER_OFFSET)

            # Skip saved thread state.
            sp += 0x40
        return sp

    def _get_ipsr(self):
        return self._core.readCoreRegister('xpsr') & 0xff

    def _has_extended_frame(self):
        return False

    def _is_current(self):
        return self._thread.is_current

    def writeCoreRegistersRaw(self, reg_list, data_list):
        self._core.writeCoreRegistersRaw(reg_list, data_list)

## @brief Class representing the handler mode.
class HandlerModeThread(TargetThread):
    def __init__(self, targetContext, provider):
        super(HandlerModeThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider

    def get_stack_pointer(self):
        return self._target_context.readCoreRegister('msp')

    @property
    def priority(self):
        return 0

    @property
    def unique_id(self):
        return 2

    @property
    def name(self):
        return "Handler mode"

    @property
    def description(self):
        return ""

    @property
    def is_current(self):
        return self._provider.get_ipsr() > 0

    @property
    def context(self):
        return self._target_context

    def __str__(self):
        return "<HandlerModeThread@0x%08x>" % (id(self))

    def __repr__(self):
        return str(self)



