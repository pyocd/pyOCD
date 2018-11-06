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
from ..core import exceptions
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
            data = context.read_memory_block8(ptr, 16)
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
    except exceptions.TransferError:
        logging.debug("TransferError while trying to read 16 bytes at 0x%08x", ptr)

    return s

## @brief Class representing the handler mode.
class HandlerModeThread(TargetThread):
    UNIQUE_ID = 2
    
    def __init__(self, targetContext, provider):
        super(HandlerModeThread, self).__init__()
        self._target_context = targetContext
        self._provider = provider

    def get_stack_pointer(self):
        return self._target_context.read_core_register('msp')

    @property
    def priority(self):
        return 0

    @property
    def unique_id(self):
        return self.UNIQUE_ID

    @property
    def name(self):
        return "Handler mode"

    @property
    def description(self):
        ipsr = self._target_context.read_core_register('ipsr');
        return self._target_context.core.exception_number_to_name(ipsr)

    @property
    def is_current(self):
        return self._target_context.read_core_register('ipsr') > 0

    @property
    def context(self):
        return self._target_context

    def __str__(self):
        return "<HandlerModeThread@0x%08x>" % (id(self))

    def __repr__(self):
        return str(self)



