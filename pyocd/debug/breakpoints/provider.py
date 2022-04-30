# pyOCD debugger
# Copyright (c) 2015-2017 Arm Limited
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

from typing import Optional

from ...core.target import Target

class Breakpoint:
    def __init__(self, provider):
        self.type: Target.BreakpointType = Target.BreakpointType.HW
        self.enabled: bool = False
        self.addr: int = 0
        self.original_instr: int = 0
        self.provider: BreakpointProvider = provider

    def __repr__(self) -> str:
        return "<%s@0x%08x type=%s addr=0x%08x>" % (self.__class__.__name__, id(self), self.type.name, self.addr)

class BreakpointProvider:
    """@brief Abstract base class for breakpoint providers."""
    def init(self) -> None:
        raise NotImplementedError()

    @property
    def bp_type(self) -> Target.BreakpointType:
        raise NotImplementedError()

    @property
    def do_filter_memory(self) -> bool:
        return False

    @property
    def available_breakpoints(self) -> int:
        raise NotImplementedError()

    def can_support_address(self, addr: int) -> bool:
        raise NotImplementedError()

    def find_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        raise NotImplementedError()

    def set_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        raise NotImplementedError()

    def remove_breakpoint(self, bp: Breakpoint) -> None:
        raise NotImplementedError()

    def filter_memory(self, addr: int, size: int, data: int) -> int:
        return data

    def flush(self) -> None:
        pass



