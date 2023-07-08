# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import logging
from typing import (Callable, Dict, List, Optional, overload, Sequence, Union, TYPE_CHECKING)
from typing_extensions import Literal

from .target import (Target, TargetGraphNode)
from .core_target import CoreTarget
from ..flash.eraser import FlashEraser
from ..debug.cache import CachingDebugContext
from ..debug.context import DebugContext
from ..debug.elf.elf import ELFBinaryFile
from ..debug.elf.elf_reader import ElfReaderContext
from ..utility.sequencer import CallSequence

if TYPE_CHECKING:
    from .session import Session
    from .memory_map import MemoryMap
    from .core_registers import (CoreRegistersIndex, CoreRegisterNameOrNumberType, CoreRegisterValueType)
    from ..debug.context import DebugContext
    from ..debug.breakpoints.provider import Breakpoint
    from ..commands.execution_context import CommandSet

LOG = logging.getLogger(__name__)

class SoCTarget(TargetGraphNode):
    """@brief Represents a microcontroller system-on-chip.

    An instance of this class is the root of the chip-level object graph. It has child
    nodes for the DP and all cores. As a concrete subclass of Target, it provides methods
    to control the device, access memory, adjust breakpoints, and so on.

    For single core devices, the SoCTarget has mostly equivalent functionality to
    the CoreTarget object for the core. Multicore devices work differently. This class tracks
    a "selected core", to which all actions are directed. The selected core can be changed
    at any time. You may also directly access specific cores and perform operations on them.

    SoCTarget subclasses must restrict usage of the DebugProbe instance in their constructor, ideally not
    using it at all. This is required in order to be able to gather information about targets for commands
    such as `pyocd json` and `pyocd list`. These commands create a session with the probe set to an instance
    of StubProbe, which is a subclass of DebugProbe with the minimal implementation necessary to support
    session creation but not opening.
    """

    VENDOR = "Generic"

    def __init__(self, session: Session, memory_map: Optional[MemoryMap] = None) -> None:
        super().__init__(session, memory_map)
        self.vendor: str = self.VENDOR
        self.part_families: List[str] = getattr(self, 'PART_FAMILIES', [])
        self.part_number: str = getattr(self, 'PART_NUMBER', self.__class__.__name__)
        self._cores: Dict[int, CoreTarget] = {}
        self._selected_core: int = -1
        self._new_core_num = 0
        self._elf = None

        # Set our graph node name.
        self.node_name = 'soc'

    @property
    def cores(self) -> Dict[int, CoreTarget]:
        return self._cores

    @property
    def selected_core(self) -> Optional[CoreTarget]:
        """@brief Get the selected CPU core object."""
        if self._selected_core == -1:
            return None
        return self.cores[self._selected_core]

    @selected_core.setter
    def selected_core(self, core_number: int) -> None:  # type:ignore # core_number int type is not the same
                                                                      # as selected_core property return type
        """@brief Set the selected CPU core object."""
        if core_number not in self.cores:
            raise ValueError("invalid core number %d" % core_number) # TODO should be a KeyError
        LOG.debug("selected core #%d" % core_number)
        self._selected_core = core_number

    @property
    def selected_core_or_raise(self) -> CoreTarget:
        """@brief Get the selected CPU core object.

        Like selected_core but will raise an exception if no core is selected rather than returning None.
        @exception KeyError The selected_core property is None.
        """
        if self._selected_core == -1:
            raise KeyError("SoCTarget has no selected core")
        return self.cores[self._selected_core]

    @property
    def primary_core(self) -> CoreTarget:
        """@brief Return the core for the `primary_core` session option.

        @exception KeyError The `primary_core` option is invalid.
        """
        primary_core_number = self.session.options.get('primary_core')
        return self.cores[primary_core_number]

    @property
    def elf(self) -> Optional[ELFBinaryFile]:
        return self._elf

    @elf.setter
    def elf(self, filename: str) -> None: # type:ignore # filename str type is not same as elf property return type
        if filename is None:
            self._elf = None
        else:
            self._elf = ELFBinaryFile(filename, self.memory_map)
            for core_number in range(len(self.cores)):
                self.cores[core_number].elf = self._elf
                if self.session.options['cache.read_code_from_elf']:
                    self.cores[core_number].set_target_context(
                            ElfReaderContext(self.cores[core_number].get_target_context(), self._elf))

    @property
    def supported_security_states(self) -> Sequence[Target.SecurityState]:
        return self.selected_core_or_raise.supported_security_states

    @property
    def core_registers(self) -> CoreRegistersIndex:
        return self.selected_core_or_raise.core_registers

    def add_core(self, core: CoreTarget) -> None:
        core.delegate = self.delegate
        if self.debug_sequence_delegate:
            core.debug_sequence_delegate = self.debug_sequence_delegate
        ctx = CachingDebugContext(
                core,
                enable_memory=self.session.options['cache.enable_memory'],
                enable_register=self.session.options['cache.enable_register'],
                )
        core.set_target_context(ctx)
        self.cores[core.core_number] = core
        self.add_child(core)

        # Always select first added core to ensure some core is selected.
        if self.selected_core is None:
            self.selected_core = core.core_number
        # Otherwise, when the chosen primary core is added, select it. This assumes that cores are only
        # added at init/discovery time.
        elif core.core_number == self.session.options.get('primary_core'):
            self.selected_core = core.core_number

    def create_init_sequence(self) -> CallSequence:
        # Return an empty call sequence. The subclass must override this.
        return CallSequence()

    def init(self) -> None:
        # If we don't have a delegate installed yet but there is a session delegate, use it.
        if (self.delegate is None) and (self.session.delegate is not None):
            self.delegate = self.session.delegate

        # Create and execute the init sequence.
        seq = self.create_init_sequence()
        self.call_delegate('will_init_target', target=self, init_sequence=seq)
        seq.invoke()
        self.call_delegate('did_init_target', target=self)

    def post_connect_hook(self) -> None:
        """@brief Hook function called after post_connect init task.

        This hook lets the target subclass configure the target as necessary.
        """
        pass

    def disconnect(self, resume: bool = True) -> None:
        self.session.notify(Target.Event.PRE_DISCONNECT, self)
        self.call_delegate('will_disconnect', target=self, resume=resume)
        for core in self.cores.values():
            core.disconnect(resume)
        self.call_delegate('did_disconnect', target=self, resume=resume)

    @property
    def run_token(self) -> int:
        return self.selected_core_or_raise.run_token

    def halt(self) -> None:
        return self.selected_core_or_raise.halt()

    def step(self, disable_interrupts: bool = True, start: int = 0, end: int = 0,
            hook_cb: Optional[Callable[[], bool]] = None) -> None:
        return self.selected_core_or_raise.step(disable_interrupts, start, end, hook_cb)

    def resume(self) -> None:
        return self.selected_core_or_raise.resume()

    def mass_erase(self) -> None:
        if not self.call_delegate('mass_erase', target=self):
            # The default mass erase implementation is to simply perform a chip erase.
            eraser = FlashEraser(self.session, FlashEraser.Mode.CHIP)
            eraser._log_chip_erase = False
            eraser.erase()

    def write_memory(self, addr: int, data: int, transfer_size: int = 32) -> None:
        return self.selected_core_or_raise.write_memory(addr, data, transfer_size)

    @overload
    def read_memory(self, addr: int, transfer_size: int = 32) -> int:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int = 32, now: Literal[True] = True) -> int:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: bool) -> Union[int, Callable[[], int]]:
        ...

    def read_memory(self, addr: int, transfer_size: int = 32, now: bool = True) -> Union[int, Callable[[], int]]:
        return self.selected_core_or_raise.read_memory(addr, transfer_size, now)

    def write_memory_block8(self, addr: int, data: Sequence[int]) -> None:
        return self.selected_core_or_raise.write_memory_block8(addr, data)

    def write_memory_block32(self, addr: int, data: Sequence[int]) -> None:
        return self.selected_core_or_raise.write_memory_block32(addr, data)

    def read_memory_block8(self, addr: int, size: int) -> Sequence[int]:
        return self.selected_core_or_raise.read_memory_block8(addr, size)

    def read_memory_block32(self, addr: int, size: int) -> Sequence[int]:
        return self.selected_core_or_raise.read_memory_block32(addr, size)

    def read_core_register(self, id: CoreRegisterNameOrNumberType) -> CoreRegisterValueType:
        return self.selected_core_or_raise.read_core_register(id)

    def write_core_register(self, id: CoreRegisterNameOrNumberType, data: CoreRegisterValueType) -> None:
        return self.selected_core_or_raise.write_core_register(id, data)

    def read_core_register_raw(self, reg: CoreRegisterNameOrNumberType) -> int:
        return self.selected_core_or_raise.read_core_register_raw(reg)

    def read_core_registers_raw(self, reg_list: Sequence[CoreRegisterNameOrNumberType]) -> List[int]:
        return self.selected_core_or_raise.read_core_registers_raw(reg_list)

    def write_core_register_raw(self, reg: CoreRegisterNameOrNumberType, data: int) -> None:
        self.selected_core_or_raise.write_core_register_raw(reg, data)

    def write_core_registers_raw(self, reg_list: Sequence[CoreRegisterNameOrNumberType], data_list: Sequence[int]) -> None:
        self.selected_core_or_raise.write_core_registers_raw(reg_list, data_list)

    def find_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        return self.selected_core_or_raise.find_breakpoint(addr)

    def set_breakpoint(self, addr: int, type: Target.BreakpointType = Target.BreakpointType.AUTO) -> bool:
        return self.selected_core_or_raise.set_breakpoint(addr, type)

    def get_breakpoint_type(self, addr: int) -> Optional[Target.BreakpointType]:
        return self.selected_core_or_raise.get_breakpoint_type(addr)

    def remove_breakpoint(self, addr: int) -> None:
        return self.selected_core_or_raise.remove_breakpoint(addr)

    def set_watchpoint(self, addr: int, size: int, type: Target.WatchpointType) -> bool:
        return self.selected_core_or_raise.set_watchpoint(addr, size, type)

    def remove_watchpoint(self, addr: int, size: Optional[int], type: Optional[Target.WatchpointType]) -> None:
        return self.selected_core_or_raise.remove_watchpoint(addr, size, type)

    def reset(self, reset_type: Optional[Target.ResetType] = None) -> None:
        # Use the probe to reset to perform a hardware reset if there is not a core.
        if self.selected_core is None:
            # Use the probe to reset. (We can't use the DP here because that's a class layering violation;
            # the DP is only created by the CoreSightTarget subclass.)
            assert self.session.probe
            self.session.probe.reset()
            return
        self.selected_core_or_raise.reset(reset_type)

    def reset_and_halt(self, reset_type: Optional[Target.ResetType] = None) -> None:
        return self.selected_core_or_raise.reset_and_halt(reset_type)

    def get_state(self) -> Target.State:
        return self.selected_core_or_raise.get_state()

    def get_security_state(self) -> Target.SecurityState:
        return self.selected_core_or_raise.get_security_state()

    def get_halt_reason(self) -> Target.HaltReason:
        return self.selected_core_or_raise.get_halt_reason()

    def set_vector_catch(self, enable_mask: int) -> None:
        return self.selected_core_or_raise.set_vector_catch(enable_mask)

    def get_vector_catch(self) -> int:
        return self.selected_core_or_raise.get_vector_catch()

    def get_target_context(self, core: Optional[int] = None) -> DebugContext:
        if core is not None:
            core_obj = self.cores[core]
        else:
            core_obj = self.selected_core_or_raise
        return core_obj.get_target_context()

    def trace_start(self):
        self.call_delegate('trace_start', target=self, mode=0)

    def trace_stop(self):
        self.call_delegate('trace_stop', target=self, mode=0)

    def add_target_command_groups(self, command_set: CommandSet):
        """@brief Hook for adding target-specific commands to a command set."""
        self.call_delegate('add_target_command_groups', target=self, command_set=command_set)

