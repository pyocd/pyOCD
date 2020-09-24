# pyOCD debugger
# Copyright (c) 2017-2020 Arm Limited
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

from time import (time, sleep)

class Timeout(object):
    """! @brief Timeout helper context manager.
    
    The recommended way to use this class is demonstrated here. It uses an else block on a
    while loop to handle the timeout. The code in the while loop must use a break statement
    to exit in the successful case.
    
    @code
    with Timeout(5, sleeptime=0.1) as t_o:
        while t_o.check(): # or "while not t_o.did_time_out"
            # Perform some operation, check, etc.
            if foobar:
                break
        else:
            print("Timed out!")
    @endcode
    
    Another method of using the class is to check the `did_time_out` property from within the
    while loop, as shown below.
    
    @code
    with Timeout(5) as t_o:
        while perform_some_test():
            # Check for timeout.
            if t_o.did_time_out:
                print("Timed out!")
                break
            sleep(0.1)
    @endcode
    
    You may also combine the call to check() in the while loop with other boolean expressions
    related to the operation being performed.
    
    If you pass a non-zero value for _sleeptime_ to the constructor, the check() method will
    automatically sleep by default starting with the second call. You can disable auto-sleep
    by passing `autosleep=False` to check().
    
    Passing a timeout of None to the constructor is allowed. In this case, check() will always return
    True and the loop must be exited via some other means.
    """

    def __init__(self, timeout, sleeptime=0):
        """! @brief Constructor.
        @param self
        @param timeout The timeout in seconds. May be None to indicate no timeout.
        @param sleeptime Time in seconds to sleep during calls to check(). Defaults to 0, thus
            check() will not sleep unless you pass a different value.
        """
        self._sleeptime = sleeptime
        self._timeout = timeout
        self._timed_out = False
        self._start = -1
        self._is_first_check = True

    def __enter__(self):
        self._start = time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def check(self, autosleep=True):
        """! @brief Check for timeout and possibly sleep.
        
        Starting with the second call to this method, it will automatically sleep before returning
        if:
            - The timeout has not yet occurred.
            - A non-zero _sleeptime_ was passed to the constructor.
            - The _autosleep_ parameter is True.
        
        This method is intended to be used as the predicate of a while loop.
        
        @param self
        @param autosleep Whether to sleep if not timed out yet. The sleeptime passed to the
            constructor must have been non-zero.
        @retval True The timeout has _not_ occurred.
        @retval False Timeout is passed and the loop should be exited.
        """
        # Check for a timeout.
        if (self._timeout is not None) and ((time() - self._start) > self._timeout):
            self._timed_out = True
        # Sleep if appropriate.
        elif (not self._is_first_check) and autosleep and self._sleeptime:
            sleep(self._sleeptime)
        self._is_first_check = False
        return not self._timed_out

    @property
    def did_time_out(self):
        """! @brief Whether the timeout has occurred as of the time when this property is accessed."""
        self.check(autosleep=False)
        return self._timed_out

