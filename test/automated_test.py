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
from pyOCD.utility.conversion import float2int
import logging
from time import time
from test_util import TestResult, Test, Logger
import argparse

from basic_test import basic_test
from speed_test import SpeedTest
from cortex_test import CortexTest
from flash_test import FlashTest


if __name__ == "__main__":
    log_file = "automated_test_result.txt"

    parser = argparse.ArgumentParser(description='pyOCD automated testing')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()

    # Setup logging
    if os.path.exists(log_file):
        os.remove(log_file)
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
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
    test_list.append(CortexTest())
    test_list.append(FlashTest())

    # Put together list of boards to test
    board_list = MbedBoard.getAllConnectedBoards(close = True, blocking = False)

    start = time()
    for board in board_list:
        print("--------------------------")
        print("TESTING BOARD %s" % board.getUniqueID())
        print("--------------------------")
        for test in test_list:
            test_start = time()
            result = test.run(board)
            test_stop = time()
            result.time = test_stop - test_start
            result_list.append(result)
    stop = time()

    for test in test_list:
        test.print_perf_info(result_list)

    Test.print_results(result_list)
    print("")
    print("Test Time: %s" % (stop - start))
    if Test.all_tests_pass(result_list):
        print("All tests passed")
    else:
        print("One or more tests has failed!")

    #TODO - check if any threads are still running?
