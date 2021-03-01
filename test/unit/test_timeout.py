# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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
import pytest

from pyocd.utility.timeout import Timeout

class TestTimeout:
    def test_no_timeout(self):
        with Timeout(0.05) as to:
            cnt = 0
            while to.check():
                sleep(0.01)
                cnt += 1
                if cnt == 2:
                    break
            else:
                assert False
        assert not to.did_time_out

    def test_timeout_a(self):
        s = time()
        with Timeout(0.05) as to:
            while to.check():
                sleep(0.01)
        assert to.did_time_out
        assert (time() - s) >= 0.05
    
    def test_timeout_b(self):
        timedout = False
        s = time()
        with Timeout(0.05) as to:
            cnt = 0
            while cnt < 10:
                if to.did_time_out:
                    timedout = True
                sleep(0.02)
                cnt += 1
        assert timedout
        assert to.did_time_out
        assert (time() - s) >= 0.05
    
    def test_timeout_c(self):
        timedout = False
        with Timeout(0.05) as to:
            cnt = 0
            while cnt < 10:
                if to.did_time_out:
                    timedout = True
                cnt += 1
        assert not timedout
        assert not to.did_time_out

