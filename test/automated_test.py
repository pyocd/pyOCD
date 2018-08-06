#!/usr/bin/env python
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
from __future__ import print_function

import os, sys

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.utility.conversion import float32beToU32be
import logging
from time import time
from test_util import TestResult, Test, Logger
import argparse
from xml.etree import ElementTree

from basic_test import BasicTest
from speed_test import SpeedTest
from cortex_test import CortexTest
from flash_test import FlashTest
from gdb_test import GdbTest
from gdb_server_json_test import GdbServerJsonTest
from connect_test import ConnectTest

XML_RESULTS = "test_results.xml"

def print_summary(test_list, result_list, test_time, output_file=None):
    for test in test_list:
        test.print_perf_info(result_list, output_file=output_file)

    Test.print_results(result_list, output_file=output_file)
    print("", file=output_file)
    print("Test Time: %.3f" % test_time, file=output_file)
    if Test.all_tests_pass(result_list):
        print("All tests passed", file=output_file)
    else:
        print("One or more tests has failed!", file=output_file)

def split_results_by_board(result_list):
    boards = {}
    for result in result_list:
        if result.board_name in boards:
            boards[result.board_name].append(result)
        else:
            boards[result.board_name] = [result]
    return boards

def generate_xml_results(result_list):
    board_results = split_results_by_board(result_list)
    
    suite_id = 0
    total_failures = 0
    total_tests = 0
    total_time = 0
    
    root = ElementTree.Element('testsuites',
            name="pyocd"
            )

    for board_name, results in board_results.items():
        total = 0
        failures = 0
        suite_time = 0
        suite = ElementTree.SubElement(root, 'testsuite',
                    name=board_name,
                    id=str(suite_id))
        suite_id += 1
        
        for result in results:

            total += 1
            if not result.passed:
                failures += 1
            case = result.get_test_case()
            suite.append(case)
            suite_time += result.time

        suite.set('tests', str(total))
        suite.set('failures', str(failures))
        suite.set('time', "%.3f" % suite_time)
        total_tests += total
        total_failures += failures
        total_time += suite_time
    
    root.set('tests', str(total_tests))
    root.set('failures', str(total_failures))
    root.set('time', "%.3f" % total_time)
    
    ElementTree.ElementTree(root).write(XML_RESULTS, encoding="UTF-8", xml_declaration=True)

def main():
    log_file = "automated_test_result.txt"
    summary_file = "automated_test_summary.txt"

    parser = argparse.ArgumentParser(description='pyOCD automated testing')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action="store_true", help='Hide test progress for 1 job')
    parser.add_argument('-j', '--jobs', action="store", default=1, type=int, metavar="JOBS",
        help='Set number of concurrent board tests (default is 1)')
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
    test_list.append(BasicTest())
    test_list.append(GdbServerJsonTest())
    test_list.append(ConnectTest())
    test_list.append(SpeedTest())
    test_list.append(CortexTest())
    test_list.append(FlashTest())
    test_list.append(GdbTest())

    # Put together list of boards to test
    board_list = MbedBoard.getAllConnectedBoards(close=True, blocking=False)

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
    test_time = (stop - start)

    print_summary(test_list, result_list, test_time)
    with open(summary_file, "w") as output_file:
        print_summary(test_list, result_list, test_time, output_file)
    generate_xml_results(result_list)
    
    exit_val = 0 if Test.all_tests_pass(result_list) else -1
    exit(exit_val)

    #TODO - check if any threads are still running?

if __name__ == "__main__":
    main()

