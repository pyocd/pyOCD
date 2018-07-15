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
from __future__ import print_function

import argparse, os, sys
from time import sleep, time
from random import randrange
import math
import struct
import traceback
import argparse

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.pyDAPAccess import DAPAccess
from pyOCD.utility.conversion import float32beToU32be
from pyOCD.flash.flash import Flash
from pyOCD.flash.flash_builder import FlashBuilder
from pyOCD.utility.progress import print_progress
from test_util import Test, TestResult

addr = 0
size = 0

board = None

import logging

class FlashTestResult(TestResult):
    def __init__(self):
        super(FlashTestResult, self).__init__(None, None, None)
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
            if result.passed:
                analyze_rate = "%.3f KB/s" % (result.analyze_rate / float(1000))
                analyze_time = "%.3f s" % result.analyze_time
            else:
                analyze_rate = "Fail"
                analyze_time = "Fail"
            print(perf_format_str.format(result.board.target_type,
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
            if result.passed:
                chip_erase_rate = "%.3f KB/s" % (result.chip_erase_rate / float(1000))
                page_erase_rate = "%.3f KB/s" % (result.page_erase_rate / float(1000))
                page_erase_rate_same = "%.3f KB/s" % (result.page_erase_rate_same / float(1000))
            else:
                chip_erase_rate = "Fail"
                page_erase_rate = "Fail"
                page_erase_rate_same = "Fail"
            print(rate_format_str.format(result.board.target_type,
                                         chip_erase_rate, page_erase_rate,
                                         page_erase_rate_same),
                  file=output_file)
        print("", file=output_file)

    def run(self, board):
        try:
            result = self.test_function(board.getUniqueID())
        except Exception as e:
            result = FlashTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
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


def flash_test(board_id):
    with MbedBoard.chooseBoard(board_id=board_id, frequency=1000000) as board:
        target_type = board.getTargetType()

        test_clock = 10000000
        if target_type == "nrf51":
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        if target_type == "ncs36510":
            # Override clock since 10MHz is too fast
            test_clock = 1000000

        memory_map = board.target.getMemoryMap()
        ram_regions = [region for region in memory_map if region.type == 'ram']
        ram_region = ram_regions[0]

        ram_start = ram_region.start
        ram_size = ram_region.length

        target = board.target
        link = board.link
        flash = board.flash
        
        flash_info = flash.getFlashInfo()

        link.set_clock(test_clock)
        link.set_deferred_transfer(True)

        test_pass_count = 0
        test_count = 0
        result = FlashTestResult()
        
        # Test each flash region separately.
        for rom_region in memory_map.getRegionsOfType('flash'):
            if not rom_region.isTestable:
                continue
            rom_start = rom_region.start
            rom_size = rom_region.length

            print("\n\n===== Testing flash region '%s' from 0x%08x to 0x%08x ====" % (rom_region.name, rom_region.start, rom_region.end))

            binary_file = os.path.join(parentdir, 'binaries', board.getTestBinary())
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
            flash.setFlashAlgoDebug(True)

            print("\n------ Test Basic Page Erase ------")
            info = flash.flashBlock(addr, data, False, False, progress_cb=print_progress())
            data_flashed = target.readBlockMemoryUnaligned8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_PAGE_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Basic Chip Erase ------")
            info = flash.flashBlock(addr, data, False, True, progress_cb=print_progress())
            data_flashed = target.readBlockMemoryUnaligned8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_CHIP_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Smart Page Erase ------")
            info = flash.flashBlock(addr, data, True, False, progress_cb=print_progress())
            data_flashed = target.readBlockMemoryUnaligned8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_PAGE_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Smart Chip Erase ------")
            info = flash.flashBlock(addr, data, True, True, progress_cb=print_progress())
            data_flashed = target.readBlockMemoryUnaligned8(addr, size)
            if same(data_flashed, data) and info.program_type is FlashBuilder.FLASH_CHIP_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            flash.setFlashAlgoDebug(False)

            print("\n------ Test Basic Page Erase (Entire region) ------")
            new_data = list(data)
            new_data.extend(unused * [0x77])
            info = flash.flashBlock(addr, new_data, False, False, progress_cb=print_progress())
            if info.program_type == FlashBuilder.FLASH_PAGE_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
                result.page_erase_rate = float(len(new_data)) / float(info.program_time)
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Fast Verify ------")
            info = flash.flashBlock(addr, new_data, progress_cb=print_progress(), fast_verify=True)
            if info.program_type == FlashBuilder.FLASH_PAGE_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Offset Write ------")
            addr = rom_start + rom_size // 2
            page_size = flash.getPageInfo(addr).size
            new_data = [0x55] * page_size * 2
            info = flash.flashBlock(addr, new_data, progress_cb=print_progress())
            data_flashed = target.readBlockMemoryUnaligned8(addr, len(new_data))
            if same(data_flashed, new_data) and info.program_type is FlashBuilder.FLASH_PAGE_ERASE:
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Multiple Block Writes ------")
            addr = rom_start + rom_size // 2
            page_size = flash.getPageInfo(addr).size
            more_data = [0x33] * page_size * 2
            addr = (rom_start + rom_size // 2) + 1 #cover multiple pages
            fb = flash.getFlashBuilder()
            fb.addData(rom_start, data)
            fb.addData(addr, more_data)
            fb.program(progress_cb=print_progress())
            data_flashed = target.readBlockMemoryUnaligned8(rom_start, len(data))
            data_flashed_more = target.readBlockMemoryUnaligned8(addr, len(more_data))
            if same(data_flashed, data) and same(data_flashed_more, more_data):
                print("TEST PASSED")
                test_pass_count += 1
            else:
                print("TEST FAILED")
            test_count += 1

            print("\n------ Test Overlapping Blocks ------")
            test_pass = False
            addr = (rom_start + rom_size // 2) #cover multiple pages
            page_size = flash.getPageInfo(addr).size
            new_data = [0x33] * page_size
            fb = flash.getFlashBuilder()
            fb.addData(addr, new_data)
            try:
                fb.addData(addr + 1, new_data)
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
            fb = flash.getFlashBuilder()
            fb.program()
            print("TEST PASSED")
            test_pass_count += 1
            test_count += 1

            print("\n------ Test Missing Progress Callback ------")
            # Freebee if nothing asserts
            addr = rom_start
            flash.flashBlock(rom_start, data, True)
            print("TEST PASSED")
            test_pass_count += 1
            test_count += 1

            # Only run test if the reset handler can be programmed (rom start at address 0)
            if rom_start == 0:
                print("\n------ Test Non-Thumb reset handler ------")
                non_thumb_data = list(data)
                # Clear bit 0 of 2nd word - reset handler
                non_thumb_data[4] = non_thumb_data[4] & ~1
                flash.flashBlock(rom_start, non_thumb_data)
                flash.flashBlock(rom_start, data)
                print("TEST PASSED")
                test_pass_count += 1
                test_count += 1

            # Note - The decision based tests below are order dependent since they
            # depend on the previous state of the flash

            if rom_start == flash_info.rom_start:
                print("\n------ Test Chip Erase Decision ------")
                new_data = list(data)
                new_data.extend([0xff] * unused) # Pad with 0xFF
                info = flash.flashBlock(addr, new_data, progress_cb=print_progress())
                if info.program_type == FlashBuilder.FLASH_CHIP_ERASE:
                    print("TEST PASSED")
                    test_pass_count += 1
                    result.chip_erase_rate_erased = float(len(new_data)) / float(info.program_time)
                else:
                    print("TEST FAILED")
                test_count += 1

                print("\n------ Test Chip Erase Decision 2 ------")
                new_data = list(data)
                new_data.extend([0x00] * unused) # Pad with 0x00
                info = flash.flashBlock(addr, new_data, progress_cb=print_progress())
                if info.program_type == FlashBuilder.FLASH_CHIP_ERASE:
                    print("TEST PASSED")
                    test_pass_count += 1
                    result.chip_erase_rate = float(len(new_data)) / float(info.program_time)
                else:
                    print("TEST FAILED")
                test_count += 1

            print("\n------ Test Page Erase Decision ------")
            new_data = list(data)
            new_data.extend([0x00] * unused) # Pad with 0x00
            info = flash.flashBlock(addr, new_data, progress_cb=print_progress())
            if info.program_type == FlashBuilder.FLASH_PAGE_ERASE:
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
            new_data.extend([0x00] * size_same) # Pad 5/6 with 0x00 and 1/6 with 0xFF
            new_data.extend([0x55] * size_differ)
            info = flash.flashBlock(addr, new_data, progress_cb=print_progress())
            if info.program_type == FlashBuilder.FLASH_PAGE_ERASE:
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
    board = pyOCD.board.mbed_board.MbedBoard.getAllConnectedBoards(close=True)[0]
    test = FlashTest()
    result = [test.run(board)]
    test.print_perf_info(result)

