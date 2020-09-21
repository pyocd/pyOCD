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

import pytest

from pyocd.core.exceptions import *

# Tests for TransferFaultError.
class TestFaultError:
    def test_no_args(self):
        e = TransferFaultError()
        assert str(e) == 'Memory transfer fault'
    
    def test_no_args_set_addr(self):
        e = TransferFaultError()
        e.fault_address = 0x1000
        assert str(e) == 'Memory transfer fault @ 0x00001000'
    
    def test_no_args_set_addr_len(self):
        e = TransferFaultError()
        e.fault_address = 0x1000
        e.fault_length = 0x8
        assert str(e) == 'Memory transfer fault @ 0x00001000-0x00001007'

    def test_msg(self):
        e = TransferFaultError("temporal anomaly")
        assert str(e) == 'Memory transfer fault (temporal anomaly)'

    def test_arg_tuple(self):
        e = TransferFaultError(-1, 1234)
        assert str(e) == 'Memory transfer fault (-1, 1234)'
    
    def test_msg_ctor_addr(self):
        e = TransferFaultError("my bad", fault_address=0x20008400)
        assert e.fault_address == 0x20008400
        assert str(e) == 'Memory transfer fault (my bad) @ 0x20008400'
    
    def test_msg_ctor_addr_len(self):
        e = TransferFaultError("my bad", fault_address=0x20008400, length=32)
        assert e.fault_address == 0x20008400
        assert str(e) == 'Memory transfer fault (my bad) @ 0x20008400-0x2000841f'

# Tests for FlashFailure.
class TestFlashFailure:
    def test_no_args(self):
        e = FlashFailure()
        assert str(e) == ""
        assert e.address == None
        assert e.result_code == None

    def test_msg(self):
        e = FlashFailure("something exploded")
        assert str(e) == "something exploded"
        assert e.address == None
        assert e.result_code == None

    def test_addr(self):
        e = FlashFailure(address=0x4000)
        assert str(e) == "(address 0x00004000)"
        assert e.address == 0x4000
        assert e.result_code == None

    def test_code(self):
        e = FlashFailure(result_code=0x104)
        assert str(e) == "(result code 0x104)"
        assert e.address == None
        assert e.result_code == 0x104

    def test_addr_code(self):
        e = FlashFailure(address=0x4000, result_code=0x104)
        assert str(e) == "(address 0x00004000; result code 0x104)"
        assert e.address == 0x4000
        assert e.result_code == 0x104

    def test_msg_addr_code(self):
        e = FlashFailure("major error", address=0x4000, result_code=0x104)
        assert str(e) == "major error (address 0x00004000; result code 0x104)"
        assert e.address == 0x4000
        assert e.result_code == 0x104

