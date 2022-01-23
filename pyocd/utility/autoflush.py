# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from typing import (Any, TYPE_CHECKING)

from ..core import exceptions

if TYPE_CHECKING:
    from ..core.target import Target
    from types import TracebackType

class Autoflush:
    """@brief Context manager for performing flushes.

    Pass a Target instance to the constructor, and when the context exits, the target will be
    automatically flushed. If a TransferError or subclass, such as TransferFaultError, is raised
    within the context, then the flush will be skipped.

    The parameter passed to the constructor can actually be any object with a `flush()` method,
    due to Python's dynamic dispatch.
    """

    def __init__(self, target: "Target") -> None:
        """@brief Constructor.

        @param self The object.
        @param target Object on which the flush will be performed. Normally this is a Target
            instance.
        """
        self._target = target

    def __enter__(self) -> "Autoflush":
        return self

    def __exit__(self, exc_type: type, value: Any, traceback: "TracebackType") -> bool:
        if exc_type is None or not issubclass(exc_type, exceptions.TransferError):
            self._target.flush()
        return False
    
