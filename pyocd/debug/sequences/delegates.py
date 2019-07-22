# pyOCD debugger
# Copyright (c) 2021-2022 Chris Reed
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
from typing import (TYPE_CHECKING, Optional, Set)

from .scope import Scope

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .sequences import (DebugSequence, DebugSequenceExecutionContext)
    from ...target.pack.cmsis_pack import CmsisPackDevice

class DebugSequenceDelegate:
    """@brief Delegate interface for handling sequence operations."""

    @property
    def all_sequences(self) -> Set[DebugSequence]:
        """@brief Returns a set containing all defined debug sequence objects."""
        raise NotImplementedError()

    @property
    def cmsis_pack_device(self) -> CmsisPackDevice:
        """@brief Accessor for the pack device that contains the sequences."""
        raise NotImplementedError()

    def get_root_scope(self, context: DebugSequenceExecutionContext) -> Scope:
        """@brief Return a scope that will be used as the parent of sequences.

        Normally the delegate will return the debugvars scope from this method. It's also possible to
        simply return an empty scope.
        """
        raise NotImplementedError()

    def run_sequence(self, name: str, pname: Optional[str] = None) -> Optional[Scope]:
        """@brief Execute the debug sequence with the specified name.
        @exception NameError No sequence with the given name is defined.
        """
        raise NotImplementedError()

    def has_sequence_with_name(self, name: str, pname: Optional[str] = None) -> bool:
        """@brief Return whether there is a debug sequence with the specified name."""
        raise NotImplementedError()

    def get_sequence_with_name(self, name: str, pname: Optional[str] = None) -> DebugSequence:
        """@brief Return the named debug sequence object.

        Expected to raise if the sequence isn't available.
        """
        raise NotImplementedError()

    def get_protocol(self) -> int:
        """@brief Return the value for the __protocol variable.
        __protocol fields:
        - [15:0] 0=error, 1=JTAG, 2=SWD, 3=cJTAG
        - [16] SWJ-DP present?
        - [17] switch through dormant state?
        """
        raise NotImplementedError()

    def get_connection_type(self) -> int:
        """@brief Return the value for the __connection variable.
        __connection fields:
        - [7:0] connection type: 0=error/disconnected, 1=for debug, 2=for flashing
        - [15:8] reset type: 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
        - [16] connect under reset?
        - [17] pre-connect reset?
        """
        raise NotImplementedError()

    def get_traceout(self) -> int:
        """@brief Return the value for the __traceout variable.
        __traceout fields:
        - [0] SWO enabled?
        - [1] parallel trace enabled?
        - [2] trace buffer enabled?
        - [21:16] selected parallel trace port size
        """
        raise NotImplementedError()

    def get_sequence_functions(self) -> DebugSequenceFunctionsDelegate:
        """@brief Return an instance of the sequence function implementations delegate.

        This method lets the delegate determine the set of built-in sequence functions.
        """
        raise NotImplementedError()

class DebugSequenceFunctionsDelegate:
    """@brief Implements functions provided by the debug sequence environment.

    All defined functions must have type annotations. Any function that has a fixed return value of 0
    should return None. This will be converted to 0 by the interpreter.

    The function names must be all lower-case in order to support case-insensitive symbol lookup.
    Whether this is actually correct debug sequence behaviour is unknown since it's not documented
    in the Open-CMSIS-Pack specification (version 1.7.15) as of late December 2022.
    """

    @property
    def context(self) -> DebugSequenceExecutionContext:
        from .sequences import DebugSequenceExecutionContext
        return DebugSequenceExecutionContext.get_active_context()
