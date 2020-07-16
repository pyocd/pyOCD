# pyOCD debugger
# Copyright (c) 2016-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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
from ..core import exceptions
from ..coresight.cortex_m_core_registers import CortexMCoreRegisterInfo

LOG = logging.getLogger(__name__)

## The security domain to which the exception was taken. 0==NS, 1=S.
EXC_RETURN_ES_MASK = (1 << 0)
## Mask on EXC_RETURN indicating whether space for FP registers is allocated
# on the frame. The bit is 0 if the frame is extended.
EXC_RETURN_EXT_FRAME_MASK = (1 << 4)
EXC_RETURN_FTYPE_BIT = 4
## Callee registers are already on the stack when this bit is 0.
EXC_RETURN_DCRS_BIT = 5

def nbits(n, v):
    """@brief Return a tuple of the low n bits of v. First element is MSb."""
    return tuple(((v >> i) & 1) for i in range(n - 1, -1, -1))

def read_c_string(context, ptr):
    """@brief Reads a null-terminated C string from the target."""
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
        LOG.debug("TransferError while trying to read 16 bytes at 0x%08x", ptr)

    return s

def build_register_offset_table(register_order):
    """@brief Construct a register offset table.
    @param register_order Iterable of registers in the order from current thread SP, the lowest address, to
        the register at the highest address. Software-stacked registers will naturally be listed first. Either
        register names or indexes may be used. Invalid register names are accepted and will be used as-is
        for the keys. This is to support non-register stack frame entries and reserved words. Invalid
        registers always have a size of 4 bytes, while known registers use their actual size.
    @return Dict from register index -> SP offset.
    """
    table = {}
    offset = 0
    for reg in register_order:
        try:
            info = CortexMCoreRegisterInfo.get(reg)
            table[info.index] = offset
            offset += info.bitsize // 8
        except KeyError:
            table[reg] = offset
            offset += 4
    return table

class HandlerModeThread(TargetThread):
    """@brief Class representing the handler mode."""

    UNIQUE_ID = 2

    def __init__(self, targetContext, provider):
        super(HandlerModeThread, self).__init__(targetContext, provider, 0)

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

    def __repr__(self):
        return "<HandlerModeThread@0x%08x>" % (id(self))



