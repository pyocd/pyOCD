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

import os, sys
from time import sleep, time
from random import randrange
import traceback
import argparse

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.pyDAPAccess import DAPAccess
from test_util import Test, TestResult
import logging

class SpeedTestResult(TestResult):
    def __init__(self):
        super(SpeedTestResult, self).__init__(None, None, None)

class SpeedTest(Test):
    def __init__(self):
        super(SpeedTest, self).__init__("Speed Test", speed_test)

    def print_perf_info(self, result_list, output_file=None):
        format_str = "{:<10}{:<16}{:<16}"
        result_list = filter(lambda x: isinstance(x, SpeedTestResult), result_list)
        print("\n\n------ Speed Test Performance ------", file=output_file)
        print(format_str.format("Target", "Read Speed", "Write Speed"),
              file=output_file)
        print("", file=output_file)
        for result in result_list:
            if result.passed:
                read_speed = "%.3f KB/s" % (float(result.read_speed) / float(1000))
                write_speed = "%.3f KB/s" % (float(result.write_speed) / float(1000))
            else:
                read_speed = "Fail"
                write_speed = "Fail"
            print(format_str.format(result.board.target_type,
                                    read_speed, write_speed),
                  file=output_file)
        print("", file=output_file)

    def run(self, board):
        passed = False
        read_speed = None
        write_speed = None
        try:
            result = self.test_function(board.getUniqueID())
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
            result = SpeedTestResult()
            result.passed = False
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result


def speed_test(board_id):
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
        rom_region = memory_map.getBootMemory()

        ram_start = ram_region.start
        ram_size = ram_region.length
        rom_start = rom_region.start
        rom_size = rom_region.length

        target = board.target
        link = board.link

        test_pass_count = 0
        test_count = 0
        result = SpeedTestResult()

        link.set_clock(test_clock)
        link.set_deferred_transfer(True)

        print("\n\n------ TEST RAM READ / WRITE SPEED ------")
        test_addr = ram_start
        test_size = ram_size
        data = [randrange(1, 50) for x in range(test_size)]
        start = time()
        target.writeBlockMemoryUnaligned8(test_addr, data)
        target.flush()
        stop = time()
        diff = stop - start
        result.write_speed = test_size / diff
        print("Writing %i byte took %.3f seconds: %.3f B/s" % (test_size, diff, result.write_speed))
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        target.flush()
        stop = time()
        diff = stop - start
        result.read_speed = test_size / diff
        print("Reading %i byte took %.3f seconds: %.3f B/s" % (test_size, diff, result.read_speed))
        error = False
        for i in range(len(block)):
            if (block[i] != data[i]):
                error = True
                print("ERROR: 0x%X, 0x%X, 0x%X!!!" % ((addr + i), block[i], data[i]))
        if error:
            print("TEST FAILED")
        else:
            print("TEST PASSED")
            test_pass_count += 1
        test_count += 1

        print("\n\n------ TEST ROM READ SPEED ------")
        test_addr = rom_start
        test_size = rom_size
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        target.flush()
        stop = time()
        diff = stop - start
        print("Reading %i byte took %.3f seconds: %.3f B/s" % (test_size, diff, test_size / diff))
        print("TEST PASSED")
        test_pass_count += 1
        test_count += 1

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD speed test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    board = pyOCD.board.mbed_board.MbedBoard.getAllConnectedBoards(close=True)[0]
    test = SpeedTest()
    result = [test.run(board)]
    test.print_perf_info(result)
