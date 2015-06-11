"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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
import argparse

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.utility.conversion import float2int
from pyOCD.transport import TransferError
from test_util import Test, TestResult
import logging
from random import randrange

TEST_COUNT = 20

class CortexTestResult(TestResult):
    def __init__(self):
        super(CortexTestResult, self).__init__(None, None, None)

class CortexTest(Test):
    def __init__(self):
        super(CortexTest, self).__init__("Cortex Test", cortex_test)

    def print_perf_info(self, result_list):
        pass

    def run(self, board):
        try:
            result = self.test_function(board.getUniqueID())
        except Exception as e:
            result = CortexTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
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

def test_function(board, function):
    board.transport.flush()
    start = time()
    for i in range(0, TEST_COUNT):
        function()
        board.transport.flush()
    stop = time()
    return (stop-start) / float(TEST_COUNT)

def cortex_test(board_id):
    with MbedBoard.chooseBoard(board_id = board_id, frequency = 1000000) as board:
        addr = 0
        size = 0
        f = None
        binary_file = "l1_"

        interface = None

        target_type = board.getTargetType()

        binary_file = os.path.join(parentdir, 'binaries', board.getTestBinary())

        addr_bin = 0x00000000
        test_clock = 10000000
        addr_invalid = 0x3E000000 # Last 16MB of ARM SRAM region - typically empty
        if target_type == "lpc1768":
            addr = 0x10000000
            size = 0x1102
            addr_flash = 0x10000
        elif target_type == "lpc11u24":
            addr = 0x10000000
            size = 0x502
            addr_flash = 0x4000
        elif target_type == "kl25z":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "kl28z":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "k64f":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "k22f":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "k20d50m":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "kl46z":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "lpc800":
            addr = 0x10000000
            size = 0x502
            addr_flash = 0x2000
        elif target_type == "nrf51":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x20000
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        elif target_type == "lpc4330":
            addr = 0x10000000
            size = 0x1102
            addr_flash = 0x14010000
            addr_bin = 0x14000000
        elif target_type == "maxwsnenv":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "max32600mbed":
            addr = 0x20000000
            size = 0x502
            addr_flash = 0x10000
        elif target_type == "w7500":
            addr = 0x20000000
            size = 0x1102
            addr_flash = 0x00000000
        else:
            raise Exception("A board is not supported by this test script.")


        target = board.target
        transport = board.transport
        flash = board.flash
        interface = board.interface

        transport.setClock(test_clock)
        transport.setDeferredTransfer(True)

        test_pass_count = 0
        test_count = 0
        result = CortexTestResult()

        print "\r\n\r\n----- FLASH NEW BINARY BEFORE TEST -----"
        flash.flashBinary(binary_file, addr_bin)
        # Let the target run for a bit so it
        # can initialize the watchdog if it needs to
        target.resume()
        sleep(0.2)
        target.halt()

        print "PROGRAMMING COMPLETE"


        print "\r\n\r\n----- TESTING CORTEX-M PERFORMANCE -----"
        test_time = test_function(board, target.getTResponse)
        print("Function getTResponse time: %f" % test_time)

        # Step
        test_time = test_function(board, target.step)
        print("Function step time: %f" % test_time)

        # Breakpoint
        def set_remove_breakpoint():
            target.setBreakpoint(0)
            target.removeBreakpoint(0)
        test_time = test_function(board, set_remove_breakpoint)
        print("Add and remove breakpoint: %f" % test_time)

        # getRegisterContext
        test_time = test_function(board, target.getRegisterContext)
        print("Function getRegisterContext: %f" % test_time)

        # setRegisterContext
        context = target.getRegisterContext()
        def set_register_context():
            target.setRegisterContext(context)
        test_time = test_function(board, set_register_context)
        print("Function setRegisterContext: %f" % test_time)

        # Run / Halt
        def run_halt():
            target.resume()
            target.halt()
        test_time = test_function(board, run_halt)
        print("Resume and halt: %f" % test_time)

        # GDB stepping
        def simulate_step():
            target.step()
            target.getTResponse()
            target.setBreakpoint(0)
            target.resume()
            target.halt()
            target.getTResponse()
            target.removeBreakpoint(0)
        test_time = test_function(board, simulate_step)
        print("Simulated GDB step: %f" % test_time)

        # Test passes if there are no exceptions
        test_pass_count += 1
        test_count += 1
        print("TEST PASSED")


        print "\r\n\r\n------ Testing Invalid Memory Access Recovery ------"
        memory_access_pass = True
        try:
            target.readBlockMemoryUnaligned8(addr_invalid, 0x1000)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if target_type != "nrf51":
                memory_access_pass = False
        except TransferError:
            pass

        try:
            target.readBlockMemoryUnaligned8(addr_invalid + 1, 0x1000)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if target_type != "nrf51":
                memory_access_pass = False
        except TransferError:
            pass

        data = [0x00] * 0x1000
        try:
            target.writeBlockMemoryUnaligned8(addr_invalid, data)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if target_type != "nrf51":
                memory_access_pass = False
        except TransferError:
            pass

        data = [0x00] * 0x1000
        try:
            target.writeBlockMemoryUnaligned8(addr_invalid + 1, data)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if target_type != "nrf51":
                memory_access_pass = False
        except TransferError:
            pass

        data = [randrange(0, 255) for x in range(size)]
        target.writeBlockMemoryUnaligned8(addr, data)
        block = target.readBlockMemoryUnaligned8(addr, size)
        if same(data, block):
            print "Aligned access pass"
        else:
            print("Memory read does not match memory written")
            memory_access_pass = False

        data = [randrange(0, 255) for x in range(size)]
        target.writeBlockMemoryUnaligned8(addr + 1, data)
        block = target.readBlockMemoryUnaligned8(addr + 1, size)
        if same(data, block):
            print "Unaligned access pass"
        else:
            print("Unaligned memory read does not match memory written")
            memory_access_pass = False

        test_count += 1
        if memory_access_pass:
            test_pass_count += 1
            print "TEST PASSED"
        else:
            print "TEST FAILED"

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD cpu test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    cortex_test(None)
