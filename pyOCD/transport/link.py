"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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
from __future__ import absolute_import

from enum import Enum


class Link(object):

    class MODE(Enum):
        # Start a read.  This must be followed by an 'END' of the
        # same type and in the same order
        START = 1
        # Read immediately
        NOW = 2
        # Get the result of a read started with 'START'
        END = 3

    class PORT(Enum):
        DEFAULT = 0
        SWD = 1
        JTAG = 2

    class REG(Enum):
        DP_0x0 = 0
        DP_0x4 = 1
        DP_0x8 = 2
        DP_0xC = 3
        AP_0x0 = 4
        AP_0x4 = 5
        AP_0x8 = 6
        AP_0xC = 7

    class ID(Enum):
        VENDOR = 1
        PRODUCT = 2
        SER_NUM = 3
        FW_VAR = 4
        DEVICE_VENDOR = 5
        DEVICE_NAME = 6

    class Error(ValueError):
        pass

    @staticmethod
    def get_connected_devices():
        raise NotImplementedError()

    @staticmethod
    def get_device(device_id):
        raise NotImplementedError()

    def __init__(self):
        pass

    # ------------------------------------------- #
    #          Host control functions
    # ------------------------------------------- #
    def open(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def identify(self, item):
        raise NotImplementedError()

    def get_unique_id(self):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

    def assert_reset(self, asserted):
        raise NotImplementedError()

    def set_clock(self, frequency):
        raise NotImplementedError()

    def get_swj_mode(self):
        raise NotImplementedError()

    def set_deferred_transfer(self, enable):
        raise NotImplementedError()

    def flush(self):
        raise NotImplementedError()

    def vendor(self, index):
        raise NotImplementedError()

    # ------------------------------------------- #
    #          Target Access functions
    # ------------------------------------------- #
    def connect(self, port=None):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()

    def write_reg(self, reg_id, value, dap_index=0):
        raise NotImplementedError()

    def read_reg(self, reg_id, dap_index=0, mode=MODE.NOW):
        raise NotImplementedError()

    def reg_write_repeat(self, num_repeats, reg_id, data_array, dap_index=0):
        raise NotImplementedError()

    def reg_read_repeat(self, num_repeats, reg_id, dap_index=0, mode=MODE.NOW):
        raise NotImplementedError()
