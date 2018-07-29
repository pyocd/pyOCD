#!/usr/bin/env python
"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2018 ARM Limited

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
import multiprocessing as mp

from basic_test import BasicTest
from speed_test import SpeedTest
from cortex_test import CortexTest
from flash_test import FlashTest
from gdb_test import GdbTest
from gdb_server_json_test import GdbServerJsonTest
from connect_test import ConnectTest

XML_RESULTS = "test_results.xml"

LOG_FORMAT = "%(relativeCreated)07d:%(levelname)s:%(module)s:%(message)s"

JOB_TIMEOUT = 30 * 60 # 30 minutes

# Put together list of tests.
test_list = [
             BasicTest(),
             GdbServerJsonTest(),
             ConnectTest(),
             SpeedTest(),
             CortexTest(),
             FlashTest(),
             GdbTest(),
             ]

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

# Function executed in subprocesses to run all tests on a given board.
#
# An loglevel of None indicates we're running in the parent process, and should not
# modify stdout/stderr.
def test_board(board_id, n, loglevel):
    board = MbedBoard.chooseBoard(board_id=board_id, open_board=False)

    originalStdout = sys.stdout
    originalStderr = sys.stderr
    if loglevel is not None:
        log_filename = "automated_test_results_%s_%d.txt" % (board.target_type, n)
        if os.path.exists(log_filename):
            os.remove(log_filename)
        log_file = open(log_filename, "a", buffering=1)
        sys.stdout = log_file
        sys.stderr = log_file
        
        log_handler = logging.FileHandler(log_filename)
        log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root_logger = logging.getLogger()
        root_logger.setLevel(loglevel)
        root_logger.addHandler(log_handler)

    result_list = []
    try:
        print("--------------------------")
        print("TESTING BOARD {} [{}] #{}".format(board.getUniqueID(), board.target_type, n))
        print("--------------------------")
        if loglevel is not None:
            print("TESTING BOARD {} [{}] #{}".format(board.getUniqueID(), board.target_type, n), file=originalStdout)
        for test in test_list:
            print("{} #{}: starting {}...".format(board.target_type, n, test.name), file=originalStdout)
            
            # Set a unique port for the GdbTest.
            if isinstance(test, GdbTest):
                test.n = n
            
            test_start = time()
            result = test.run(board)
            test_stop = time()
            result.time = test_stop - test_start
            result_list.append(result)
            
            passFail = "PASSED" if result.passed else "FAILED"
            print("{} #{}: finished {}... {}".format(board.target_type, n, test.name, passFail), file=originalStdout)
    finally:
        # Restore stdout/stderr in case we're running in the parent process (1 job).
        sys.stdout = originalStdout
        sys.stderr = originalStderr
        
        if loglevel is not None:
            root_logger.removeHandler(log_handler)
            log_handler.flush()
            log_handler.close()
    return result_list

def main():
    log_file = "automated_test_result.txt"
    summary_file = "automated_test_summary.txt"

    parser = argparse.ArgumentParser(description='pyOCD automated testing')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action="store_true", help='Hide test progress for 1 job')
    parser.add_argument('-j', '--jobs', action="store", default=1, type=int, metavar="JOBS",
        help='Set number of concurrent board tests (default is 1)')
    args = parser.parse_args()
    
    # Disable multiple jobs on macOS prior to Python 3.4. By default, multiprocessing uses
    # fork() on Unix, which doesn't work on the Mac because CoreFoundation requires exec()
    # to be used in order to init correctly (CoreFoundation is used in hidapi). Only on Python
    # version 3.4+ is the multiprocessing.set_start_method() API available that lets us
    # switch to the 'spawn' method, i.e. exec().
    if args.jobs > 1 and sys.platform.startswith('darwin') and sys.version_info[0:2] < (3, 4):
        print("WARNING: Cannot support multiple jobs on macOS prior to Python 3.4. Forcing 1 job.")
        args.jobs = 1

    # Setup logging
    level = logging.DEBUG if args.debug else logging.INFO
    if args.jobs == 1 and not args.quiet:
        logging.basicConfig(level=level)
        if os.path.exists(log_file):
            os.remove(log_file)
        logger = Logger(log_file)
        sys.stdout = logger
        sys.stderr = logger

    board_list = []
    result_list = []

    # Put together list of boards to test
    board_list = MbedBoard.getAllConnectedBoards(close=True, blocking=False)
    board_id_list = sorted(b.getUniqueID() for b in board_list)

    # If only 1 job was requested, don't bother spawning processes.
    start = time()
    if args.jobs == 1:
        if not args.quiet:
            level = None
        for board_id in board_id_list:
            result_list += test_board(board_id, 0, level)
    else:
        # Create a pool of processes to run tests.
        try:
            pool = mp.Pool(args.jobs)
            
            # Issue board test job to process pool.
            async_results = [pool.apply_async(test_board, (board_id, n, level))
                             for n, board_id in enumerate(board_id_list)]
            
            # Gather results.
            for r in async_results:
                result_list += r.get(timeout=JOB_TIMEOUT)
        finally:
            pool.close()
            pool.join()
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
    # set_start_method is only available in Python 3.4+.
    if sys.version_info[0:2] >= (3, 4):
        mp.set_start_method('spawn')
    main()

