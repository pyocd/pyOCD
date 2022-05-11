# pyOCD debugger
# Copyright (c) 2022 Chris Reed
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

import signal
from typing import (Any, Iterable, TYPE_CHECKING)

if TYPE_CHECKING:
    from types import TracebackType

class ThreadSignalBlocker:
    """@brief Context manager class to block all signals on the current thread.

    Can be used either as a context manager or simply by instantiating the class. All signals are blocked
    on the current thread when the class is instantiated (not when entering a context). If used as a context
    manager, those signals blocked in the constructor will be restored on context exit.

    The ThreadSignalBlocked object is returned as the value for the _with_ statement when entering
    a context. Usually it is not needed, but allows for calling restore() to restore blocked signals early
    if necessary.

    This class can be used on Windows too, but does nothing.
    """

    def __init__(self) -> None:
        if hasattr(signal, 'pthread_sigmask'):
            self._saved_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signal.valid_signals())
        else:
            self._saved_mask = set()

    @property
    def saved_signal_mask(self) -> Iterable[int]:
        return self._saved_mask

    def __enter__(self) -> "ThreadSignalBlocker":
        return self

    def __exit__(self, exc_type: type, value: Any, traceback: "TracebackType") -> None:
        self.restore()

    def restore(self) -> None:
        """@brief Restore signals that were blocked in the constructor."""
        if hasattr(signal, 'pthread_sigmask'):
            signal.pthread_sigmask(signal.SIG_SETMASK, self._saved_mask)

            # Prevent restoring a second time on context exit, in case the caller has modified
            # the signal mask after we return.
            self._saved_mask = set()
