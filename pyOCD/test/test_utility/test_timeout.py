"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2017 ARM Limited

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

from pyOCD.utility.timeout import (Timeout, TimeoutException)
from time import (time, sleep)
import pytest

class TestTimeout:
    def test_no_timeout(self):
        with Timeout(0.5) as to:
            while to.check():
                sleep(0.4)
                break
        assert not to.did_time_out

    def test_timeout_a(self):
        s = time()
        with Timeout(0.5) as to:
            while to.check():
                sleep(0.1)
        assert to.did_time_out
        assert (time() - s) >= 0.5

    def test_pass_exception(self):
        with pytest.raises(RuntimeError):
            with Timeout(0.5) as to:
                raise RuntimeError()

