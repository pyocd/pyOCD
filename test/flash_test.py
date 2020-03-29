# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.utility.conversion import float32_to_u32
from pyocd.utility.mask import (invert32, same)
from pyocd.core.memory_map import MemoryType
from pyocd.flash.flash import Flash
from pyocd.flash.builder import FlashBuilder
from pyocd.utility.progress import print_progress

from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    get_test_binary_path,
    )

addr = 0
size = 0

board = None

import logging

class FlashTestResult(TestResult):
    def __init__(self):
        super(FlashTestResult, self).__init__(None, None, None)
        self.name = "flash"
        self.chip_erase_rate_erased = None
        self.page_erase_rate_same = None
        self.page_erase_rate = None
        self.analyze = None
        self.analyze_rate = None
        self.chip_erase_rate = None

class FlashTest(Test):
    def __init__(self):
        super(FlashTest, self).__init__("Flash Test", flash_test)

    def print_perf_info(self, result_list, output_file=None):
        result_list = list(filter(lambda x: isinstance(x, FlashTestResult), result_list))

        print("\n\n------ Analyzer Performance ------", file=output_file)
        perf_format_str = "{:<10}{:<12}{:<18}{:<18}"
        print(perf_format_str.format("Target", "Analyzer", "Rate", "Time"),
              file=output_file)
        print("", file=output_file)
        for result in result_list:
            if result.board is None or result.analyze is None:
                continue
            if result.passed:
                analyze_rate = "%.3f KB/s" % (result.analyze_rate / float(1000))
                analyze_time = "%.3f s" % result.analyze_time
            else:
                analyze_rate = "Fail"
                analyze_time = "Fail"
            print(perf_format_str.format(result.board,
                                         result.analyze, analyze_rate,
                                         analyze_time),
                  file=output_file)
        print("", file=output_file)

        print("\n\n------ Test Rate ------", file=output_file)
        rate_format_str = "{:<10}{:<20}{:<20}{:<20}"
        print(rate_format_str.format("Target", "Chip Erase", "Page Erase",
                                     "Page Erase (Same data)"),
              file=output_file)
        print("", file=output_file)
        for result in result_list:
            if result.board is None:
                continue
            if result.passed:
                chip_erase_rate = "%.3f KB/s" % (result.chip_erase_rate / float(1000))
                page_erase_rate = "%.3f KB/s" % (result.page_erase_rate / float(1000))
                page_erase_rate_same = "%.3f KB/s" % (result.page_erase_rate_same / float(1000))
            else:
                chip_erase_rate = "Fail"
                page_erase_rate = "Fail"
                page_erase_rate_same = "Fail"
            print(rate_format_str.format(result.board,
                                         chip_erase_rate, page_erase_rate,
                                         page_erase_rate_same),
                  file=output_file)
        print("", file=output_file)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = FlashTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result


def flash_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target_type = board.target_type

        memory_map = board.target.get_memory_map()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)

        ram_start = ram_region.start
        ram_size = ram_region.length

        target = board.target

        test_params = get_target_test_params(session)
        session.probe.set_clock(test_params['test_clock'])

        test_pass_count = 0
        test_count = 0
        result = FlashTestResult()
        
        # Test each flash region separately.
        for rom_region in memory_map.iter_matching_regions(type=MemoryType.FLASH, is_testable=True):
            rom_start = rom_region.start
            rom_size = rom_region.length

            flash = rom_region.flash
            flash_info = flash.get_flash_info()
            
            # This can be any value, as long as it's not the erased byte value. We take the
            # inverse of the erased value so that for most flash, the unerased value is 0x00.
            unerasedValue = invert32(flash.region.erased_byte_value) & 0xff

            print("\n\n===== Testing flash region '%s' from 0x%08x to 0x%08x ====" % (rom_region.name, rom_region.start, rom_region.end))

            binary_file = get_test_binary_path(board.test_binary)
            with open(binary_file, "rb") as f:
                data = f.read()
            data = struct.unpack("%iB" % len(data), data)
            unused = rom_size - len(data)
            
            # Make sure data doesn't overflow this region.
            if unused < 0:
                data = data[:rom_size]
                unused = 0

            addr = rom_start
            size = len(data)

            # Turn on extra checks for the next 4 tests
            flash.set_flash_algo_debug(True)
            
            print("\n------ Test Erased Value Check ------")
            d = [flash.region.erased_byte_value] * 128
            if flash.region.is_data_erased(d):
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            d = [unerasedValue] + [flash.region.erased_byte_value] * 127
            if not flash.region.is_data_erased(d):
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Basic Page Erase ------")
            info = flash.flash_block(addr, data, False, "sector", progress_cb=print_progress())
            data_flashed = target.read_memory_block8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_SECTOR_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Basic Chip Erase ------")
            info = flash.flash_block(addr, data, False, "chip", progress_cb=print_progress())
            data_flashed = target.read_memory_block8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_CHIP_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Smart Page Erase ------")
            info = flash.flash_block(addr, data, True, "sector", progress_cb=print_progress())
            data_flashed = target.read_memory_block8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_SECTOR_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Smart Chip Erase ------")
            info = flash.flash_block(addr, data, True, "chip", progress_cb=print_progress())
            data_flashed = target.read_memory_block8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_CHIP_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            flash.set_flash_algo_debug(False)

            print("\n------ Test Basic Page Erase (Entire region) ------")
            new_data = list(data)
            new_data.extend(unused * [0x77])
            info = flash.flash_block(addr, new_data, False, "sector", progress_cb=print_progress())
            if info.program_type == FlashBuilder.FLASH_SECTOR_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
                result.page_erase_rate = float(len(new_data)) / float(info.program_time)
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Fast Verify ------")
            info = flash.flash_block(addr, new_data, progress_cb=print_progress(), fast_verify=True)
            if info.program_type == FlashBuilder.FLASH_SECTOR_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Offset Write ------")
            addr = rom_start + rom_size // 2
            page_size = flash.get_page_info(addr).size
            new_data = [0x55] * page_size * 2
            info = flash.flash_block(addr, new_data, progress_cb=print_progress())
            data_flashed = target.read_memory_block8(addr, len(new_data))
            if same(data_flashed, new_data) and info.program_type is FlashBuilder.FLASH_SECTOR_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Multiple Block Writes ------")
            addr = rom_start + rom_size // 2
            page_size = flash.get_page_info(addr).size
            more_data = [0x33] * page_size * 2
            addr = (rom_start + rom_size // 2) + 1 #cover multiple pages
            fb = flash.get_flash_builder()
            fb.add_data(rom_start, data)
            fb.add_data(addr, more_data)
            fb.program(progress_cb=print_progress())
            data_flashed = target.read_memory_block8(rom_start, len(data))
            data_flashed_more = target.read_memory_block8(addr, len(more_data))
            if same(data_flashed, data) and same(data_flashed_more, more_data):
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Overlapping Blocks ------")
            test_pass = False
            addr = (rom_start + rom_size // 2) #cover multiple pages
            page_size = flash.get_page_info(addr).size
            new_data = [0x33] * page_size
            fb = flash.get_flash_builder()
            fb.add_data(addr, new_data)
            try:
                fb.add_data(addr + 1, new_data)
            except ValueError as e:
                print("Exception: %s" % e)
                test_pass = True
            if test_pass:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Empty Block Write ------")
            # Freebee if nothing asserts
            fb = flash.get_flash_builder()
            fb.program()
            print("TEST PASSED")
            test_pass_count += 1
            test_count += 1

            print("\n------ Test Missing Progress Callback ------")
            # Freebee if nothing asserts
            addr = rom_start
            flash.flash_block(rom_start, data, True)
            print("TEST PASSED")
            test_pass_count += 1
            test_count += 1

            # Only run test if the reset handler can be programmed (rom start at address 0)
            if rom_start == 0:
                print("\n------ Test Non-Thumb reset handler ------")
                non_thumb_data = list(data)
                # Clear bit 0 of 2nd word - reset handler
                non_thumb_data[4] = non_thumb_data[4] & ~1
                flash.flash_block(rom_start, non_thumb_data)
                flash.flash_block(rom_start, data)
                print("TEST PASSED")
                test_pass_count += 1
                test_count += 1

            # Note - The decision based tests below are order dependent since they
            # depend on the previous state of the flash

            if rom_start == flash_info.rom_start:
                print("\n------ Test Chip Erase Decision ------")
                new_data = list(data)
                new_data.extend([flash.region.erased_byte_value] * unused) # Pad with erased value
                info = flash.flash_block(addr, new_data, progress_cb=print_progress())
                if info.program_type == FlashBuilder.FLASH_CHIP_ERASE:
                    print("TEST PASSED")
                    test_pass_count += 1
                    result.chip_erase_rate_erased = float(len(new_data)) / float(info.program_time)
                else:
                    print("TEST FAILED")
                test_count += 1

                print("\n------ Test Chip Erase Decision 2 ------")
                new_data = list(data)
                new_data.extend([unerasedValue] * unused) # Pad with unerased value
                info = flash.flash_block(addr, new_data, progress_cb=print_progress())
                if info.program_type == FlashBuilder.FLASH_CHIP_ERASE:
                    print("TEST PASSED")
                    test_pass_count += 1
                    result.chip_erase_rate = float(len(new_data)) / float(info.program_time)
                else:
                    print("TEST FAILED")
                test_count += 1

            print("\n------ Test Page Erase Decision ------")
            new_data = list(data)
            new_data.extend([unerasedValue] * unused) # Pad with unerased value
            info = flash.flash_block(addr, new_data, progress_cb=print_progress())
            if info.program_type == FlashBuilder.FLASH_SECTOR_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
                result.page_erase_rate_same = float(len(new_data)) / float(info.program_time)
                result.analyze = info.analyze_type
                result.analyze_time = info.analyze_time
                result.analyze_rate = float(len(new_data)) / float(info.analyze_time)
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Page Erase Decision 2 ------")
            new_data = list(data)
            size_same = unused * 5 // 6
            size_differ = unused - size_same
            new_data.extend([unerasedValue] * size_same) # Pad 5/6 with unerased value and 1/6 with 0x55
            new_data.extend([0x55] * size_differ)
            info = flash.flash_block(addr, new_data, progress_cb=print_progress())
            if info.program_type == FlashBuilder.FLASH_SECTOR_ERASE:
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
    parser = argparse.ArgumentParser(description='pyOCD flash test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    # Set to debug to print some of the decisions made while flashing
    session = ConnectHelper.session_with_chosen_probe(**get_session_options())
    test = FlashTest()
    result = [test.run(session.board)]
    test.print_perf_info(result)

