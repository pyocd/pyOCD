# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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
from __future__ import print_function
import argparse, os, sys
from time import sleep, time
from random import randrange
import math
import struct
import traceback
import argparse
import logging

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.utility.conversion import float32_to_u32
from pyocd.core.memory_map import MemoryType
from pyocd.flash.loader import (FileProgrammer, FlashEraser, FlashLoader)
from test_util import (Test, TestResult, get_session_options)

addr = 0
size = 0

board = None

class FlashLoaderTestResult(TestResult):
    def __init__(self):
        super(FlashLoaderTestResult, self).__init__(None, None, None)
        self.name = "flashloader"

class FlashLoaderTest(Test):
    def __init__(self):
        super(FlashLoaderTest, self).__init__("Flash Loader Test", flash_loader_test)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = FlashLoaderTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result


def same(d1, d2):
    if len(d1) != len(d2):
        return False
    for i in range(len(d1)):
        if d1[i] != d2[i]:
            return False
    return True

def is_erased(d):
    return all((b == 0xff) for b in d)

def flash_loader_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target = session.target
        target_type = board.target_type

        test_clock = 10000000
        if target_type == "nrf51":
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        if target_type == "ncs36510":
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        session.probe.set_clock(test_clock)

        memory_map = board.target.get_memory_map()
        boot_region = memory_map.get_boot_memory()
        boot_start_addr = boot_region.start
        boot_end_addr = boot_region.end
        boot_blocksize = boot_region.blocksize

        test_pass_count = 0
        test_count = 0
        result = FlashLoaderTestResult()
        
        binary_file_path = os.path.join(parentdir, 'binaries', board.test_binary)
        with open(binary_file_path, "rb") as f:
            data = list(bytearray(f.read()))
        data_length = len(data)
        
        print("\n------ Test Basic Load ------")
        loader = FlashLoader(session, chip_erase=False)
        loader.add_data(boot_start_addr, data)
        loader.commit()
        verify_data = target.read_memory_block8(boot_start_addr, data_length)
        if same(verify_data, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Load Sector Erase ------")
        test_data = [0x55] * boot_blocksize
        addr = (boot_end_addr + 1) - (boot_blocksize * 2)
        loader = FlashLoader(session, chip_erase=False)
        loader.add_data(addr, test_data)
        loader.add_data(addr + boot_blocksize, test_data)
        loader.commit()
        verify_data = target.read_memory_block8(addr, boot_blocksize * 2)
        verify_data2 = target.read_memory_block8(boot_start_addr, data_length)
        if same(verify_data, test_data * 2) and same(verify_data2, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Basic Sector Erase ------")
        eraser = FlashEraser(session, FlashEraser.Mode.SECTOR)
        eraser.erase(["0x%x+0x%x" % (addr, boot_blocksize)])
        verify_data = target.read_memory_block8(addr, boot_blocksize)
        if is_erased(verify_data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Load Chip Erase ------")
        loader = FlashLoader(session, chip_erase=True)
        loader.add_data(boot_start_addr, data)
        loader.commit()
        verify_data = target.read_memory_block8(boot_start_addr, data_length)
        verify_data2 = target.read_memory_block8(addr, boot_blocksize * 2)
        if same(verify_data, data) and is_erased(verify_data2):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Binary File Load ------")
        programmer = FileProgrammer(session)
        programmer.program(binary_file_path, format='bin', base_address=boot_start_addr)
        verify_data = target.read_memory_block8(boot_start_addr, data_length)
        if same(verify_data, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print("\n\nTest Summary:")
        print("Pass count %i of %i tests" % (test_pass_count, test_count))
        if test_pass_count == test_count:
            print("FLASH TEST SCRIPT PASSED")
        else:
            print("FLASH TEST SCRIPT FAILED")

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD flash loader test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    # Set to debug to print some of the decisions made while flashing
    session = ConnectHelper.session_with_chosen_probe(open_session=False, **get_session_options())
    test = FlashLoaderTest()
    result = [test.run(session.board)]

