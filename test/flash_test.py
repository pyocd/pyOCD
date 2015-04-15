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

import argparse, os, sys
from time import sleep, time
from random import randrange
import math
import struct

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.target.cortex_m import float2int
from pyOCD.flash.flash import FLASH_PAGE_ERASE, FLASH_CHIP_ERASE
from test_util import Test, TestResult

addr = 0
size = 0

interface = None
board = None

import logging

class FlashTestResult(TestResult):
    pass

class FlashTest(Test):
    def __init__(self):
        super(FlashTest, self).__init__("Flash Test", flash_test)

    def run(self, board):
        passed = False
        try:
            passed = self.test_function(board.getUniqueID())
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
        result = FlashTestResult(board, self, passed)
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
        if target_type == "kl25z":
            ram_start = 0x1ffff000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x20000
        elif target_type == "kl46z":
            ram_start = 0x1fffe000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x40000
        elif target_type == "k22f":
            ram_start = 0x1fff0000
            ram_size = 0x20000
            rom_start = 0x00000000
            rom_size = 0x80000
        elif target_type == "k64f":
            ram_start = 0x1FFF0000
            ram_size = 0x40000
            rom_start = 0x00000000
            rom_size = 0x100000
        elif target_type == "lpc11u24":
            ram_start = 0x10000000
            ram_size = 0x2000
            rom_start = 0x00000000
            rom_size = 0x8000
        elif target_type == "lpc1768":
            ram_start = 0x10000000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x80000
        elif target_type == "lpc4330":
            ram_start = 0x10000000
            ram_size = 0x20000
            rom_start = 0x14000000
            rom_size = 0x100000
        elif target_type == "lpc800":
            ram_start = 0x10000000
            ram_size = 0x1000
            rom_start = 0x00000000
            rom_size = 0x4000
        elif target_type == "nrf51822":
            ram_start = 0x20000000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x40000
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        else:
            raise Exception("The board is not supported by this test script.")

        target = board.target
        transport = board.transport
        flash = board.flash
        interface = board.interface

        transport.setClock(test_clock)

        test_pass_count = 0
        test_count = 0

        print "\r\n\r\n------ Test Read / Write Speed ------"
        test_addr = ram_start
        test_size = ram_size
        data = [randrange(1, 50) for x in range(test_size)]
        start = time()
        target.writeBlockMemoryUnaligned8(test_addr, data)
        stop = time()
        diff = stop-start
        print("Writing %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        stop = time()
        diff = stop-start
        print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
        if same(block, data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        def print_progress(progress):
            assert progress >= 0.0
            assert progress <= 1.0
            assert (progress == 0 and print_progress.prev_progress == 1.0) or (progress >= print_progress.prev_progress)

            # Reset state on 0.0
            if progress == 0.0:
                print_progress.prev_progress = 0
                print_progress.backwards_progress = False
                print_progress.done = False

            # Check for backwards progress
            if progress < print_progress.prev_progress:
                print_progress.backwards_progress = True
            print_progress.prev_progress = progress

            # print progress bar
            if not print_progress.done:
                sys.stdout.write('\r')
                i = int(progress*20.0)
                sys.stdout.write("[%-20s] %3d%%" % ('='*i, round(progress * 100)))

            # Finish on 1.0
            if progress >= 1.0:
                if not print_progress.done:
                    print_progress.done = True
                    sys.stdout.write("\n")
                    if print_progress.backwards_progress:
                        print("Progress went backwards during flash")
        print_progress.prev_progress = 0

        binary_file = "l1_"
        binary_file += target_type + ".bin"
        binary_file = os.path.join(parentdir, 'binaries', binary_file)
        with open(binary_file, "rb") as f:
            data = f.read()
        data = struct.unpack("%iB" % len(data), data)
        unused = rom_size - len(data)

        addr = rom_start
        size = len(data)

        print "\r\n\r\n------ Test Basic Page Erase ------"
        operation = flash.flashBlock(addr, data, False, False, progress_cb = print_progress)
        data_flashed = target.readBlockMemoryUnaligned8(addr, size)
        if same(data_flashed, data) and operation is FLASH_PAGE_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Basic Chip Erase ------"
        operation = flash.flashBlock(addr, data, False, True, progress_cb = print_progress)
        data_flashed = target.readBlockMemoryUnaligned8(addr, size)
        if same(data_flashed, data) and operation is FLASH_CHIP_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Smart Page Erase ------"
        operation = flash.flashBlock(addr, data, True, False, progress_cb = print_progress)
        data_flashed = target.readBlockMemoryUnaligned8(addr, size)
        if same(data_flashed, data) and operation is FLASH_PAGE_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Smart Chip Erase ------"
        operation = flash.flashBlock(addr, data, True, True, progress_cb = print_progress)
        data_flashed = target.readBlockMemoryUnaligned8(addr, size)
        if same(data_flashed, data) and operation is FLASH_CHIP_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Offset Write ------"
        new_data = [0x55] * board.flash.page_size * 2
        addr = rom_start + rom_size / 2
        operation = flash.flashBlock(addr, new_data, progress_cb = print_progress)
        data_flashed = target.readBlockMemoryUnaligned8(addr, len(new_data))
        if same(data_flashed, new_data) and operation is FLASH_PAGE_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Multiple Block Writes ------"
        more_data = [0x33] * board.flash.page_size * 2
        addr = (rom_start + rom_size / 2) + 1 #cover multiple pages
        fb = flash.getFlashBuilder()
        fb.addData(rom_start, data)
        fb.addData(addr, more_data)
        fb.program(progress_cb = print_progress)
        data_flashed = target.readBlockMemoryUnaligned8(rom_start, len(data))
        data_flashed_more = target.readBlockMemoryUnaligned8(addr, len(more_data))
        if same(data_flashed, data) and same(data_flashed_more, more_data):
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Overlapping Blocks ------"
        test_pass = False
        new_data = [0x33] * board.flash.page_size
        addr = (rom_start + rom_size / 2) #cover multiple pages
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

        print "\r\n\r\n------ Test Empty Block Write ------"
        # Freebee if nothing asserts
        fb = flash.getFlashBuilder()
        fb.program()
        print("TEST PASSED")
        test_pass_count += 1
        test_count += 1

        print "\r\n\r\n------ Test Missing Progress Callback ------"
        # Freebee if nothing asserts
        addr = rom_start
        flash.flashBlock(rom_start, data, True)
        print("TEST PASSED")
        test_pass_count += 1
        test_count += 1


        # Note - The decision based tests below are order dependent since they
        # depend on the previous state of the flash

        print "\r\n\r\n------ Test Chip Erase Decision ------"
        new_data = list(data)
        new_data.extend([0xff] * unused) # Pad with 0xFF
        operation = flash.flashBlock(0, new_data, progress_cb = print_progress)
        if operation == FLASH_CHIP_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Chip Erase Decision 2 ------"
        new_data = list(data)
        new_data.extend([0x00] * unused) # Pad with 0x00
        operation = flash.flashBlock(0, new_data, progress_cb = print_progress)
        if operation == FLASH_CHIP_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Page Erase Decision ------"
        new_data = list(data)
        new_data.extend([0x00] * unused) # Pad with 0x00
        operation = flash.flashBlock(0, new_data, progress_cb = print_progress)
        if operation == FLASH_PAGE_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print "\r\n\r\n------ Test Page Erase Decision 2 ------"
        new_data = list(data)
        size_same = unused * 5 / 6
        size_differ = unused - size_same
        new_data.extend([0x00] * size_same) # Pad 5/6 with 0x00 and 1/6 with 0xFF
        new_data.extend([0x55] * size_differ)
        operation = flash.flashBlock(0, new_data, progress_cb = print_progress)
        if operation == FLASH_PAGE_ERASE:
            print("TEST PASSED")
            test_pass_count += 1
        else:
            print("TEST FAILED")
        test_count += 1

        print("\r\n\r\nTest Summary:")
        print("Pass count %i of %i tests" % (test_pass_count, test_count))
        if test_pass_count == test_count:
            print("FLASH TEST SCRIPT PASSED")
        else:
            print("FLASH TEST SCRIPT FAILED")

        target.reset()
        return test_count == test_pass_count

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Set to debug to print some of the decisions made while flashing
    flash_test(None)