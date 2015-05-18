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

import os, sys
from time import sleep, time
from random import randrange

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from test_util import Test, TestResult
import logging

class SpeedTestResult(TestResult):
    pass

class SpeedTest(Test):
    def __init__(self):
        super(SpeedTest, self).__init__("Speed Test", speed_test)

    def print_perf_info(self, result_list):
        result_list = filter(lambda x : isinstance(x, SpeedTestResult), result_list)
        print("\r\n\r\n------ Speed Test Performance ------")
        print("{:<10}{:<20}{:<20}".format("Target","Write Speed B/s","Read Speed B/s"))
        print("")
        for result in result_list:
            if result.passed:
                print("{:<10}{:<20}{:<20}".format(result.board.target_type, result.read_speed, result.write_speed))
            else:
                print("{:<10}{:<20}{:<20}".format(result.board.target_type, "Fail", "Fail"))
        print("")

    def run(self, board):
        passed = False
        read_speed = None
        write_speed = None
        try:
            passed, read_speed, write_speed = self.test_function(board.getUniqueID())
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
        result = SpeedTestResult(board, self, passed)
        result.read_speed = read_speed
        result.write_speed = write_speed
        return result


def speed_test(board_id):
    with MbedBoard.chooseBoard(board_id = board_id, frequency = 1000000) as board:
        target_type = board.getTargetType()

        test_clock = 10000000
        if target_type == "kl25z":
            ram_start = 0x1ffff000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x20000
        elif target_type == "kl28z":
            ram_start = 0x1fffa000
            ram_size = 96*1024
            rom_start = 0x00000000
            rom_size = 512*1024
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
        elif target_type == "lpc800":
            ram_start = 0x10000000
            ram_size = 0x1000
            rom_start = 0x00000000
            rom_size = 0x4000
        elif target_type == "lpc4330":
            ram_start = 0x10000000
            ram_size = 0x20000
            rom_start = 0x14000000
            rom_size = 0x100000
        elif target_type == "nrf51822":
            ram_start = 0x20000000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x40000
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        elif target_type == "maxwsnenv":
            ram_start = 0x20000000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x40000
        elif target_type == "max32600mbed":
            ram_start = 0x20000000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x40000
        else:
            raise Exception("The board is not supported by this test script.")

        target = board.target
        transport = board.transport
        flash = board.flash
        interface = board.interface

        test_pass_count = 0
        test_count = 0

        transport.setClock(test_clock)

        print "\r\n\r\n------ TEST RAM READ / WRITE SPEED ------"
        test_addr = ram_start
        test_size = ram_size
        data = [randrange(1, 50) for x in range(test_size)]
        start = time()
        target.writeBlockMemoryUnaligned8(test_addr, data)
        stop = time()
        diff = stop-start
        write_speed = test_size / diff
        print("Writing %i byte took %s seconds: %s B/s" % (test_size, diff,  write_speed))
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        stop = time()
        diff = stop-start
        read_speed = test_size / diff
        print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  read_speed))
        error = False
        for i in range(len(block)):
            if (block[i] != data[i]):
                error = True
                print "ERROR: 0x%X, 0x%X, 0x%X!!!" % ((addr + i), block[i], data[i])
        if error:
            print "TEST FAILED"
        else:
            print "TEST PASSED"
            test_pass_count += 1
        test_count += 1

        print "\r\n\r\n------ TEST ROM READ SPEED ------"
        test_addr = rom_start
        test_size = rom_size
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        stop = time()
        diff = stop-start
        print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
        print "TEST PASSED"
        test_pass_count += 1
        test_count += 1

        target.reset()

        return (test_count == test_pass_count, write_speed, read_speed)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    speed_test(None)
