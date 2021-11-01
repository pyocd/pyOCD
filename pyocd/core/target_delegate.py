# pyOCD debugger
# Copyright (c) 2019 Arm Limited
# COpyright (c) 2021-2022 Chris Reed
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

from typing import (Any, Optional, TYPE_CHECKING)

if TYPE_CHECKING:
    from .session import Session
    from .soc_target import SoCTarget
    from .core_target import CoreTarget
    from .target import Target
    from ..board.board import Board
    from ..utility.sequencer import CallSequence
    from ..debug.sequences.delegates import DebugSequenceDelegate
    from ..commands.execution_context import CommandSet

## @brief Return type for some delegate methods.
#
# For certain delegate method, the delegate can reply with a boolean or None, where True means that
# it handled the actions and no further action is to be performed, and False or None means to continue
# processing.
DelegateResult = Optional[bool]


class DelegateHavingMixIn:
    """! @brief Mix-in class adding delegate support.

    There are two types of delegates:
    - Debug sequence delegates
    - Arbitrary delegate classes
    """

    _delegate: Any = None
    _debug_sequence_delegate: Optional["DebugSequenceDelegate"] = None

    @property
    def delegate(self) -> Any:
        return self._delegate

    @delegate.setter
    def delegate(self, the_delegate: Any) -> None:
        self._delegate = the_delegate

    @property
    def debug_sequence_delegate(self) -> Optional["DebugSequenceDelegate"]:
        return self._debug_sequence_delegate

    @debug_sequence_delegate.setter
    def debug_sequence_delegate(self, the_delegate: "DebugSequenceDelegate") -> None:
        self._debug_sequence_delegate = the_delegate

    def delegate_implements(self, method_name: str) -> bool:
        return (self._delegate is not None) and (hasattr(self._delegate, method_name))

    def call_delegate(self, method_name: str, *args: Any, **kwargs: Any) -> Optional[bool]:
        if self.delegate_implements(method_name):
            return getattr(self._delegate, method_name)(*args, **kwargs)
        else:
            # The default action is always taken if None is returned.
            return None

    def has_debug_sequence(self, name: str, pname: Optional[str] = None) -> bool:
        seq_delegate = self.debug_sequence_delegate
        return seq_delegate.has_sequence_with_name(name, pname) if seq_delegate else False


class TargetDelegateInterface:
    """@brief Abstract class defining the delegate interface for targets.

    Note that delegates don't actually have to derive from this class due to Python's
    dynamic method dispatching. The primary purpose of this class is for documentation
    and type checking.
    """

    def __init__(self, session: "Session") -> None:
        self._session = session

    def unlock_device(self, target: "SoCTarget") -> None:
        """! @brief Hook to perform any required unlock sequence.

        Called after the DP is initialised but prior to discovery.

        @param self
        @param target An SoCTarget object about to be initialized.
        @return Ignored.
        """
        pass

    def will_connect(self, board: "Board") -> None:
        """@brief Pre-init hook for the board.
        @param self
        @param board A Board instance that is about to be initialized.
        @return Ignored.
        """
        pass

    def did_connect(self, board: "Board") -> None:
        """@brief Post-initialization hook for the board.
        @param self
        @param board A Board instance.
        @return Ignored.
        """
        pass

    def will_init_target(self, target: "SoCTarget", init_sequence: "CallSequence") -> None:
        """@brief Hook to review and modify init call sequence prior to execution.
        @param self
        @param target An SoCTarget object about to be initialized.
        @param init_sequence The CallSequence that will be invoked. Because call sequences are
            mutable, this parameter can be modified before return to change the init calls.
        @return Ignored.
        """
        pass

    def did_init_target(self, target: "SoCTarget") -> None:
        """@brief Post-initialization hook.
        @param self
        @param target An SoCTarget.
        @return Ignored.
        """
        pass

    def will_start_debug_core(self, core: "CoreTarget") -> None:
        """@brief Notification hook for before core debug is enabled.

        This hook is called during connection, prior to any register accesses being performed on the
        indicated core (aside from the CoreSight peripheral ID registers that were read to identify
        the core's presence during discovery).

        @param self
        @param core A CoreTarget object about to be initialized.
        @return Ignored.
        """
        pass

    def start_debug_core(self, core: "CoreTarget") -> DelegateResult:
        """@brief Core debug initialization hook.
        @param self
        @param core A CoreTarget object.
        @retval True Do not perform the normal procedure to start core debug.
        @retval "False or None" Continue with normal behaviour.
        """
        pass

    def did_start_debug_core(self, core: "CoreTarget") -> None:
        """@brief Notification hook that core debug has been enabled.

        This hook method is called once a debug has been enabled for a core, and it has been fully
        identified.

        @param self
        @param core A CoreTarget object.
        @return Ignored.
        """
        pass

    def will_stop_debug_core(self, core: "CoreTarget") -> None:
        """@brief Pre core disconnect notification hook for the core.
        @param self
        @param core A CoreTarget object.
        @return Ignored.
        """
        pass

    def stop_debug_core(self, core: "CoreTarget") -> DelegateResult:
        """@brief Core debug disable hook.
        @param self
        @param core A CoreTarget object.
        @retval True Do not perform the normal procedure to disable core debug.
        @retval "False or None" Continue with normal behaviour.
        """
        pass

    def did_stop_debug_core(self, core: "CoreTarget") -> None:
        """@brief Post core disconnect notification hook for the core.
        @param self
        @param core A CoreTarget object.
        @return Ignored.
        """
        pass

    def will_disconnect(self, target: "SoCTarget", resume: bool) -> None:
        """@brief Pre-disconnect hook.
        @param self
        @param target Either a CoreSightTarget or CortexM object.
        @param resume The value of the `disconnect_on_resume` option.
        @return Ignored.
        """
        pass

    def did_disconnect(self, target: "SoCTarget", resume: bool) -> None:
        """@brief Post-disconnect hook.
        @param self
        @param target Either a CoreSightTarget or CortexM object.
        @param resume The value of the `disconnect_on_resume` option.
        @return Ignored."""
        pass

    def will_reset(self, core: "Target", reset_type: "Target.ResetType") -> DelegateResult:
        """@brief Pre-reset hook.
        @param self
        @param core A CortexM instance.
        @param reset_type One of the Target.ResetType enumerations.
        @retval True
        @retval "False or None"
        """
        pass

    def did_reset(self, core: "Target", reset_type: "Target.ResetType") -> None:
        """@brief Post-reset hook.
        @param self
        @param core A CortexM instance.
        @param reset_type One of the Target.ResetType enumerations.
        @return Ignored.
        """
        pass

    def set_reset_catch(self, core: "CoreTarget", reset_type: "Target.ResetType") -> DelegateResult:
        """@brief Hook to prepare target for halting on reset.
        @param self
        @param core A CortexM instance.
        @param reset_type One of the Target.ResetType enumerations.
        @retval True
        @retval "False or None"
        """
        pass

    def clear_reset_catch(self, core: "CoreTarget", reset_type: "Target.ResetType") -> None:
        """@brief Hook to clean up target after a reset and halt.
        @param self
        @param core A CortexM instance.
        @param reset_type
        @return Ignored.
        """
        pass

    def mass_erase(self, target: "SoCTarget") -> DelegateResult:
        """@brief Hook to override mass erase.
        @param self
        @param target A CoreSightTarget object.
        @retval True Indicate that mass erase was performed by the hook.
        @retval "False or None" Mass erase was not overridden and the caller should proceed with the standard
            mass erase procedure.
        """
        pass

    def trace_start(self, target: "SoCTarget", mode: int) -> None:
        """@brief Hook to prepare for tracing the target.
        @param self
        @param target A CoreSightTarget object.
        @param mode The trace mode. Currently always 0 to indicate SWO.
        @return Ignored.
        """
        pass

    def trace_stop(self, target: "SoCTarget", mode: int) -> None:
        """@brief Hook to clean up after tracing the target.
        @param self
        @param target A CoreSightTarget object.
        @param mode The trace mode. Currently always 0 to indicate SWO.
        @return Ignored.
        """
        pass

    def add_target_command_groups(self, target: "SoCTarget", command_set: "CommandSet"):
        """@brief Hook for adding target-specific commands to a command set.
        @param self
        @param target A `SoCTarget` object.
        @param command_set The `CommandSet` object to which commands may be added.
        """
        pass

