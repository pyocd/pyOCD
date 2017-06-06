"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2017 ARM Limited

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

from ...core.target import Target

class Breakpoint(object):
    def __init__(self, provider):
        self.type = Target.BREAKPOINT_HW
        self.enabled = False
        self.addr = 0
        self.original_instr = 0
        self.provider = provider

    def __repr__(self):
        return "<%s@0x%08x type=%d addr=0x%08x>" % (self.__class__.__name__, id(self), self.type, self.addr)

## @brief Abstract base class for breakpoint providers.
class BreakpointProvider(object):
    def init(self):
        raise NotImplementedError()

    def bp_type(self):
        return 0

    @property
    def do_filter_memory(self):
        return False

    def available_breakpoints(self):
        raise NotImplementedError()

    def find_breakpoint(self, addr):
        raise NotImplementedError()

    def set_breakpoint(self, addr):
        raise NotImplementedError()

    def remove_breakpoint(self, bp):
        raise NotImplementedError()

    def filter_memory(self, addr, size, data):
        return data

    def flush(self):
        pass



