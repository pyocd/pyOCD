"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from time import time

## @brief Exception raised when a timeout occurs.
class TimeoutException(Exception):
    pass

## @brief Timeout helper context manager.
#
# One way to use this class is demonstrated here:
# @code
# with Timeout(5) as t_o:
#     while t_o.check():
#         # Perform some operation, check, etc.
#         if foobar:
#             break
#         sleep(0.1)
# if t_o.did_time_out:
#     print "Timed out!"
# @endcode
#
# Another way to detect and handle a timeout occurring is to check for the TimeoutException
# using a try statement inside the with statement block. This is shown below.
# @code
# with Timeout(5) as t_o:
#     try:
#         while t_o.check():
#             # Perform some operation, check, etc.
#             if foobar:
#                 break
#             sleep(0.1)
#     except TimeoutException:
#         print "Timed out!"
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
        # Suppress timeout exceptions from being reraised.
        return (exc_type is TimeoutException)

    def check(self):
        if (time() - self._start) > self._timeout:
            self._timed_out = True
            raise TimeoutException()
        return True

    @property
    def did_time_out(self):
        return self._timed_out

