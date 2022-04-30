# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from functools import wraps
from typing import (Any, Callable)

def locked(func: Callable) -> Callable:
    """@brief Decorator to automatically lock a method of a class.

    The class is required to have `lock()` and `unlock()` methods.
    """
    @wraps(func)
    def _locking(self, *args: Any, **kwargs: Any) -> Any:
        try:
            self.lock()
            return func(self, *args, **kwargs)
        finally:
            self.unlock()
    return _locking
