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
from unittest.mock import Mock

from pyocd.utility.timeout import Timeout

@pytest.fixture(scope='function')
def mock_time(monkeypatch):
    mtime = Mock()
    mtime.return_value = 0
    monkeypatch.setattr('pyocd.utility.timeout.time', mtime)
    return mtime

@pytest.fixture(scope='function')
def mock_sleep(monkeypatch, mock_time):
    def inc_time(offset):
        mock_time.return_value += offset
    msleep = Mock()
    msleep.side_effect = inc_time
    msleep.return_value = None
    monkeypatch.setattr('pyocd.utility.timeout.sleep', msleep)
    return msleep

class TestTimeout:
    def test_no_timeout(self, mock_time, mock_sleep):
        with Timeout(0.05) as to:
            cnt = 0
            while to.check():
                mock_sleep(0.01)
                cnt += 1
                if cnt == 2:
                    break
            else:
                assert False
        assert not to.did_time_out

    def test_timeout_a(self, mock_time, mock_sleep):
        with Timeout(0.05) as to:
            while to.check():
                mock_sleep(0.01)
        assert to.did_time_out

    def test_timeout_b(self, mock_time, mock_sleep):
        timedout = False
        print(repr(time))
        with Timeout(0.05) as to:
            cnt = 0
            while cnt < 10:
                if to.did_time_out:
                    timedout = True
                mock_sleep(0.02)
                cnt += 1
        assert timedout
        assert to.did_time_out

    def test_timeout_c(self, mock_time, mock_sleep):
        timedout = False
        with Timeout(0.05) as to:
            cnt = 0
            while cnt < 10:
                if to.did_time_out:
                    timedout = True
                cnt += 1
        assert not timedout
        assert not to.did_time_out

    def test_timeout_reset(self, mock_time, mock_sleep):
        cnt = 0
        cnta = 0
        with Timeout(0.05) as to:
            cnta = 0
            while cnta < 3:
                cnt = 0
                while to.check():
                    mock_sleep(0.01)
                    if cnta > 1:
                        break
                    cnt += 1
                else:
                    assert to.did_time_out
                    to.clear()
                    to.start()
                cnta += 1
        assert cnta == 3 and cnt == 0
        assert not to.did_time_out

