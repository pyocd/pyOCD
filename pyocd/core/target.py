# pyOCD debugger
# Copyright (c) 2006-2019 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
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

from __future__ import annotations

from enum import Enum
from typing import (Callable, List, Optional, Sequence, TYPE_CHECKING, Set)

from .memory_interface import MemoryInterface
from .memory_map import MemoryMap
from .target_delegate import DelegateHavingMixIn
from ..utility.graph import GraphNode

if TYPE_CHECKING:
    from .session import Session
    from .core_registers import (CoreRegistersIndex, CoreRegisterNameOrNumberType, CoreRegisterValueType)
    from ..debug.breakpoints.provider import Breakpoint
    from ..debug.context import DebugContext
    from ..debug.svd.loader import SVDFile
    from ..debug.svd.model import SVDDevice
    from ..utility.sequencer import CallSequence

class Target(MemoryInterface, DelegateHavingMixIn):

    class State(Enum):
        """@brief States a target processor can be in."""
        ## Core is executing code.
        RUNNING = 1
        ## Core is halted in debug mode.
        HALTED = 2
        ## Core is being held in reset.
        RESET = 3
        ## Core is sleeping due to a wfi or wfe instruction.
        SLEEPING = 4
        ## Core is locked up.
        LOCKUP = 5

    class SecurityState(Enum):
        """@brief Security states for a processor with the Security extension."""
        ## PE is in the Non-secure state.
        NONSECURE = 0
        ## PE is in the Secure state.
        SECURE = 1

    class ResetType(Enum):
        """@brief Available reset methods."""
        ## Hardware reset via the nRESET signal.
        HW = 1
        ## Software reset using the core's default software reset method.
        SW = 2
        ## Software reset the entire system .
        SW_SYSTEM = 3
        ## Software reset using the AIRCR.SYSRESETREQ bit (alias of #SW_SYSTEM).
        SW_SYSRESETREQ = SW_SYSTEM
        ## Software reset the core only.
        SW_CORE = 4
        ## Software reset using the AIRCR.VECTRESET bit (alias of #SW_CORE).
        #
        # v6-M and v8-M targets do not support VECTRESET, so they will fall back to SW_EMULATED,
        # unless a target-specific core reset method is made available.
        SW_VECTRESET = SW_CORE
        ## Emulated software reset.
        SW_EMULATED = 5

    class BreakpointType(Enum):
        """@brief Types of breakpoints."""
        ## Hardware breakpoint.
        HW = 1
        ## Software breakpoint.
        SW = 2
        ## Auto will select the best type given the address and available breakpoints.
        AUTO = 3

    class WatchpointType(Enum):
        """@brief Types of watchpoints."""
        ## Watchpoint on read accesses.
        READ = 1
        ## Watchpoint on write accesses.
        WRITE = 2
        ## Watchpoint on either read or write accesses.
        READ_WRITE = 3

    class VectorCatch:
        """Vector catch option masks.

        These constants can be OR'd together to form any combination of vector catch settings.
        """
        ## Disable vector catch.
        NONE = 0
        ## Trap on HardFault exception.
        HARD_FAULT = (1 << 0)
        ## Trap on BusFault exception.
        BUS_FAULT = (1 << 1)
        ## Trap on MemManage exception.
        MEM_FAULT = (1 << 2)
        ## Trap on fault occurring during exception entry or exit.
        INTERRUPT_ERR = (1 << 3)
        ## Trap on UsageFault exception caused by state information error, such as an undefined
        # instruction exception.
        STATE_ERR = (1 << 4)
        ## Trap on UsageFault exception caused by checking error, for example an alignment check error.
        CHECK_ERR = (1 << 5)
        ## Trap on UsageFault exception caused by a failed access to a coprocessor.
        COPROCESSOR_ERR = (1 << 6)
        ## Trap on local reset.
        CORE_RESET = (1 << 7)
        ## Trap SecureFault.
        SECURE_FAULT = (1 << 8)
        ALL = (HARD_FAULT | BUS_FAULT | MEM_FAULT | INTERRUPT_ERR
                    | STATE_ERR | CHECK_ERR | COPROCESSOR_ERR | CORE_RESET
                    | SECURE_FAULT)

    class Event(Enum):
        """Target notification events."""
        ## Sent after completing the initialisation sequence.
        POST_CONNECT = 1
        ## Sent prior to disconnecting cores and powering down the DP.
        PRE_DISCONNECT = 2
        ## Sent prior to resume or step.
        #
        # Associated data is a RunType enum.
        PRE_RUN = 3
        ## Sent after a resume or step operation.
        #
        # For resume, this event will be sent while the target is still running. Use a halt event
        # to trap when the target stops running.
        #
        # Associated data is a RunType enum.
        POST_RUN = 4
        ## Sent prior to a user-invoked halt.
        #
        # Associated data is a HaltReason enum, which will currently always be HaltReason.USER.
        PRE_HALT = 5
        ## Sent after the target halts.
        #
        # Associated data is a HaltReason enum.
        POST_HALT = 6
        ## Sent before executing a reset operation.
        PRE_RESET = 7
        ## Sent after the target has been reset.
        POST_RESET = 8
        ## Sent before programming target flash.
        PRE_FLASH_PROGRAM = 9
        ## Sent after target flash has been reprogrammed.
        POST_FLASH_PROGRAM = 10

    class RunType(Enum):
        """Run type for run notifications.

        An enum of this type is set as the data attribute on PRE_RUN and POST_RUN notifications.
        """
        ## Target is being resumed.
        RESUME = 1
        ## Target is being stepped one instruction.
        STEP = 2

    class HaltReason(Enum):
        """Halt type for halt notifications.

        An value of this type is returned from Target.get_halt_reason(). It is also used as the data
        attribute on PRE_HALT and POST_HALT notifications.
        """
        ## Target halted due to user action.
        USER = 1
        ## Target halted because of a halt or step event.
        DEBUG = 2
        ## Breakpoint event.
        BREAKPOINT = 3
        ## DWT watchpoint event.
        WATCHPOINT = 4
        ## Vector catch event.
        VECTOR_CATCH = 5
        ## External debug request.
        EXTERNAL = 6
        ## PMU event. v8.1-M only.
        PMU = 7

    def __init__(self, session: Session, memory_map: Optional[MemoryMap] = None) -> None:
        self._session = session
        # Make a target-specific copy of the memory map. This is safe to do without locking
        # because the memory map may not be mutated until target initialization.
        self.memory_map = memory_map.clone() if memory_map else MemoryMap()
        self._svd_location: Optional[SVDFile] = None
        self._svd_device: Optional[SVDDevice] = None

    @property
    def session(self) -> Session:
        return self._session

    @property
    def svd_device(self) -> Optional[SVDDevice]:
        return self._svd_device

    @property
    def supported_security_states(self) -> Sequence[SecurityState]:
        raise NotImplementedError()

    @property
    def core_registers(self) -> CoreRegistersIndex:
        raise NotImplementedError()

    @property
    def supported_reset_types(self) -> Set[ResetType]:
        """@brief Set of reset types that can be used with this target."""
        raise NotImplementedError()

    def is_locked(self) -> bool:
        return False

    def create_init_sequence(self) -> CallSequence:
        raise NotImplementedError()

    def init(self) -> None:
        raise NotImplementedError()

    def disconnect(self, resume: bool = True) -> None:
        pass

    def flush(self) -> None:
        if self.session.probe:
            self.session.probe.flush()

    def halt(self) -> None:
        raise NotImplementedError()

    def step(self, disable_interrupts: bool = True, start: int = 0, end: int = 0,
            hook_cb: Optional[Callable[[], bool]] = None) -> None:
        raise NotImplementedError()

    def resume(self) -> None:
        raise NotImplementedError()

    def mass_erase(self) -> None:
        raise NotImplementedError()

    def read_core_register(self, id: CoreRegisterNameOrNumberType) -> CoreRegisterValueType:
        raise NotImplementedError()

    def write_core_register(self, id: CoreRegisterNameOrNumberType, data: CoreRegisterValueType) -> None:
        raise NotImplementedError()

    def read_core_register_raw(self, reg: CoreRegisterNameOrNumberType) -> int:
        raise NotImplementedError()

    def read_core_registers_raw(self, reg_list: Sequence[CoreRegisterNameOrNumberType]) -> List[int]:
        raise NotImplementedError()

    def write_core_register_raw(self, reg: CoreRegisterNameOrNumberType, data: int) -> None:
        raise NotImplementedError()

    def write_core_registers_raw(self, reg_list: Sequence[CoreRegisterNameOrNumberType], data_list: Sequence[int]) -> None:
        raise NotImplementedError()

    def find_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        raise NotImplementedError()

    def set_breakpoint(self, addr: int, type: BreakpointType = BreakpointType.AUTO) -> bool:
        raise NotImplementedError()

    def get_breakpoint_type(self, addr: int) -> Optional[BreakpointType]:
        raise NotImplementedError()

    def remove_breakpoint(self, addr: int) -> None:
        raise NotImplementedError()

    def set_watchpoint(self, addr: int, size: int, type: WatchpointType) -> bool:
        raise NotImplementedError()

    def remove_watchpoint(self, addr: int, size: Optional[int], type: Optional[WatchpointType]) -> None:
        raise NotImplementedError()

    def reset(self, reset_type: Optional[ResetType] = None) -> None:
        raise NotImplementedError()

    def reset_and_halt(self, reset_type: Optional[ResetType] = None) -> None:
        raise NotImplementedError()

    def get_state(self) -> State:
        raise NotImplementedError()

    def get_security_state(self) -> SecurityState:
        raise NotImplementedError()

    def get_halt_reason(self) -> HaltReason:
        raise NotImplementedError()

    @property
    def run_token(self) -> int:
        return 0

    def is_running(self) -> bool:
        return self.get_state() == Target.State.RUNNING

    def is_halted(self) -> bool:
        return self.get_state() == Target.State.HALTED

    def get_memory_map(self) -> MemoryMap:
        return self.memory_map

    def set_vector_catch(self, enable_mask: int) -> None:
        raise NotImplementedError()

    def get_vector_catch(self) -> int:
        raise NotImplementedError()

    def get_target_context(self, core: Optional[int] = None) -> DebugContext:
        raise NotImplementedError()

class TargetGraphNode(Target, GraphNode):
    """@brief Abstract class for a target that is a graph node."""

    def __init__(self, session: Session, memory_map: Optional[MemoryMap] = None) -> None:
        Target.__init__(self, session, memory_map)
        GraphNode.__init__(self)
