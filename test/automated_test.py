"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2015 ARM Limited

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

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.target.cortex_m import float2int
import logging
from test_util import TestResult, Test, Logger

from basic_test import basic_test
from speed_test import SpeedTest
from flash_test import FlashTest


if __name__ == "__main__":
    log_file = "automated_test_result.txt"

    # Setup logging
    if os.path.exists(log_file):
        os.remove(log_file)
    logger = Logger(log_file)
    sys.stdout = logger
    sys.stderr = logger

    test_list = []
    board_list = []
    result_list = []

    # Put together list of tests
    test = Test("Basic Test", lambda board: basic_test(board, None))
    test_list.append(test)
    test_list.append(SpeedTest())
    test_list.append(FlashTest())

    # Put together list of boards to test
    board_list = MbedBoard.getAllConnectedBoards(close = True, blocking = False)

    for board in board_list:
        print("--------------------------")
        print("TESTING BOARD %s" % board.getUniqueID())
        print("--------------------------")
        for test in test_list:
            result = test.run(board)
            result_list.append(result)

    for test in test_list:
        test.print_perf_info(result_list)

    Test.print_results(result_list)
    print("")
    if Test.all_tests_pass(result_list):
        print("All tests passed")
    else:
        print("One or more tests has failed!")

    #TODO - check if any threads are still running?
