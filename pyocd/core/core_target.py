# pyOCD debugger
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

from typing import (Optional, TYPE_CHECKING)

from .target import (Target, TargetGraphNode)

if TYPE_CHECKING:
    from ..debug.context import DebugContext
    from ..debug.elf.elf import ELFBinaryFile

class CoreTarget(TargetGraphNode):
    """@brief Target base class for CPU cores."""

    @property
    def name(self) -> str:
        """@brief CPU type name."""
        raise NotImplementedError()

    @property
    def core_number(self) -> int:
        raise NotImplementedError()

    @property
    def elf(self) -> Optional["ELFBinaryFile"]:
        raise NotImplementedError()

    @elf.setter
    def elf(self, filename: "ELFBinaryFile") -> None:
        raise NotImplementedError()

    def set_reset_catch(self, reset_type: Target.ResetType) -> None:
        raise NotImplementedError()

    def clear_reset_catch(self, reset_type: Target.ResetType) -> None:
        raise NotImplementedError()

    def set_target_context(self, context: "DebugContext") -> None:
        raise NotImplementedError()

    def exception_number_to_name(self, exc_num: int) -> Optional[str]:
        raise NotImplementedError()
