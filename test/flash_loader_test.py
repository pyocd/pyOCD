# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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

import argparse
import os
import sys
from time import (sleep, time)
from random import randrange
import math
import struct
import traceback
import argparse
import logging

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.utility.conversion import float32_to_u32
from pyocd.utility.mask import same
from pyocd.utility.compatibility import to_str_safe
from pyocd.core.memory_map import MemoryType
from pyocd.flash.loader import FlashLoader
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.flash.eraser import FlashEraser
from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    binary_to_hex_file,
    binary_to_elf_file,
    get_test_binary_path,
    )

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

def flash_loader_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target = session.target
        target_type = board.target_type

        test_params = get_target_test_params(session)
        session.probe.set_clock(test_params['test_clock'])

        memory_map = board.target.get_memory_map()
        boot_region = memory_map.get_boot_memory()
        print(boot_region)
        boot_start_addr = boot_region.start
        boot_end_addr = boot_region.end
        boot_blocksize = boot_region.blocksize
        num_test_sectors = min(2, boot_region.length // boot_blocksize)
        binary_file = get_test_binary_path(board.test_binary)

        # Generate an Intel hex file from the binary test file.
        temp_test_hex_name = binary_to_hex_file(binary_file, boot_region.start)
        
        # Generate ELF file from the binary test file.
        temp_test_elf_name = binary_to_elf_file(binary_file, boot_region.start)

        test_pass_count = 0
        test_count = 0
        result = FlashLoaderTestResult()
        
        with open(binary_file, "rb") as f:
            data = list(bytearray(f.read()))
        data_length = len(data)
        
        print("\n------ Test Basic Load ------")
        loader = FlashLoader(session, chip_erase="sector")
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
        addr = (boot_end_addr + 1) - (boot_blocksize * num_test_sectors)
        if addr < (boot_start_addr + data_length):
            orig_data_length = addr - boot_start_addr
        else:
            orig_data_length = data_length
        
        loader = FlashLoader(session, chip_erase="sector")
        loader.add_data(addr, test_data)
        loader.add_data(addr + boot_blocksize, test_data)
        loader.commit()
        
        verify_data = target.read_memory_block8(addr, boot_blocksize * num_test_sectors)
        verify_data2 = target.read_memory_block8(boot_start_addr, orig_data_length)
        if same(verify_data, test_data * num_test_sectors) and same(verify_data2, data[:orig_data_length]):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Basic Sector Erase ------")
        addr = (boot_end_addr + 1) - (boot_blocksize * num_test_sectors)
        eraser = FlashEraser(session, FlashEraser.Mode.SECTOR)
        eraser.erase(["0x%x+0x%x" % (addr, boot_blocksize)])
        verify_data = target.read_memory_block8(addr, boot_blocksize)
        if target.memory_map.get_region_for_address(addr).is_data_erased(verify_data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Load Chip Erase ------")
        loader = FlashLoader(session, chip_erase="chip")
        loader.add_data(boot_start_addr, data)
        loader.commit()
        verify_data = target.read_memory_block8(boot_start_addr, data_length)
        if same(verify_data, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Binary File Load ------")
        programmer = FileProgrammer(session)
        programmer.program(binary_file, file_format='bin', base_address=boot_start_addr)
        verify_data = target.read_memory_block8(boot_start_addr, data_length)
        if same(verify_data, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test Intel Hex File Load ------")
        programmer = FileProgrammer(session)
        programmer.program(temp_test_hex_name, file_format='hex')
        verify_data = target.read_memory_block8(boot_start_addr, data_length)
        if same(verify_data, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1
        
        print("\n------ Test ELF File Load ------")
        programmer = FileProgrammer(session)
        programmer.program(temp_test_elf_name, file_format='elf')
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
    session = ConnectHelper.session_with_chosen_probe(**get_session_options())
    test = FlashLoaderTest()
    result = [test.run(session.board)]

