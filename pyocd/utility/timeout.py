# pyOCD debugger
# Copyright (c) 2017-2018 Arm Limited
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

from time import time

## @brief Timeout helper context manager.
#
# The recommended way to use this class is demonstrated here. It uses an else block on a
# while loop to handle the timeout. The code in the while loop must use a break statement
# to exit in the successful case.
#
# @code
# with Timeout(5) as t_o:
#     while t_o.check(): # or "while not t_o.did_time_out"
#         # Perform some operation, check, etc.
#         if foobar:
#             break
#         sleep(0.1)
#     else:
#         print("Timed out!")
# @endcode
#
# Another method of using the class is to check the `did_time_out` property from within the
# while loop, as shown below.
#
# @code
# with Timeout(5) as t_o:
#     while perform_some_test():
#         # Check for timeout.
#         if t_o.did_time_out:
#             print("Timed out!")
#             break
#         sleep(0.1)
# @endcode
#
# You may also combine the call to check() in the while loop with other boolean expressions
# related to the operation being performed.
class Timeout(object):
    def __init__(self, timeout):
        self._timeout = timeout
        self._timed_out = False
        self._start = -1

    def __enter__(self):
        self._start = time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def check(self):
        if (time() - self._start) > self._timeout:
            self._timed_out = True
        return not self._timed_out

    @property
    def did_time_out(self):
        self.check()
        return self._timed_out

