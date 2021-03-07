#!/usr/bin/env python
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

import os
import sys
import logging
from time import time
import argparse
from xml.etree import ElementTree
import multiprocessing as mp
import io

from pyocd.core.session import Session
from pyocd.core.helpers import ConnectHelper
from pyocd.utility.conversion import float32_to_u32
from pyocd.probe.aggregator import DebugProbeAggregator

from test_util import (
    get_env_file_name,
    TestResult,
    Test,
    IOTee,
    RecordingLogHandler,
    get_session_options,
    ensure_output_dir,
    TEST_OUTPUT_DIR,
    )

from basic_test import BasicTest
from speed_test import SpeedTest
from cortex_test import CortexTest
from flash_test import FlashTest
from flash_loader_test import FlashLoaderTest
from gdb_test import GdbTest
from json_lists_test import JsonListsTest
from connect_test import ConnectTest
from debug_context_test import DebugContextTest
from concurrency_test import ConcurrencyTest
from commands_test import CommandsTest
from commander_test import CommanderTest
from probeserver_test import ProbeserverTest

XML_RESULTS_TEMPLATE = "test_results{}.xml"
LOG_FILE_TEMPLATE = "automated_test_result{}.txt"
SUMMARY_FILE_TEMPLATE = "automated_test_summary{}.txt"

LOG_FORMAT = "%(relativeCreated)07d:%(levelname)s:%(module)s:%(message)s"

JOB_TIMEOUT = 30 * 60 # 30 minutes

# Put together list of all tests.
all_tests = [
             BasicTest(),
             JsonListsTest(),
             ConnectTest(),
             SpeedTest(),
             CortexTest(),
             ConcurrencyTest(),
             FlashTest(),
             FlashLoaderTest(),
             DebugContextTest(),
             GdbTest(),
             CommandsTest(),
             CommanderTest(),
             ProbeserverTest(),
             ]

# Actual list used at runtime, filted by command line args.
test_list = []

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
    root.text = "\n"

    for board_name, results in board_results.items():
        total = 0
        failures = 0
        suite_time = 0
        suite = ElementTree.SubElement(root, 'testsuite',
                    name=board_name,
                    id=str(suite_id))
        suite.text = "\n"
        suite.tail = "\n"
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
    
    xml_results = os.path.join(TEST_OUTPUT_DIR, XML_RESULTS_TEMPLATE.format(get_env_file_name()))
    ElementTree.ElementTree(root).write(xml_results, encoding="UTF-8", xml_declaration=True)

def print_board_header(outputFile, board, n, includeDividers=True, includeLeadingNewline=False):
    header = "TESTING BOARD {name} [{target}] [{uid}] #{n}".format(
        name=board.name, target=board.target_type, uid=board.unique_id, n=n)
    if includeDividers:
        divider = "=" * len(header)
        if includeLeadingNewline:
            print("\n" + divider, file=outputFile)
        else:
            print(divider, file=outputFile)
    print(header, file=outputFile)
    if includeDividers:
        print(divider + "\n", file=outputFile)

def print_test_header(output_file, board, test):
    header = f"Test: {test.name} | {board.name} #{test.n}"
    divider = "-" * 80
    print("\n" + divider, file=output_file)
    print(header, file=output_file)
    print(divider, file=output_file)

def test_board(board_id, n, loglevel, logToConsole, commonLogFile):
    """! @brief Run all tests on a given board.
    
    When multiple test jobs are being used, this function is the entry point executed in
    child processes.
    
    Always writes both stdout and log messages of tests to a board-specific log file, and saves
    the output for each test to a string that is stored in the TestResult object. Depending on
    the logToConsole and commonLogFile parameters, output may also be copied to the console
    (sys.stdout) and/or a common log file for all boards.
    
    @param board_id Unique ID of the board to test.
    @param n Unique index of the test run.
    @param loglevel Log level passed to logger instance. Usually INFO or DEBUG.
    @param logToConsole Boolean indicating whether output should be copied to sys.stdout.
    @param commonLogFile If not None, an open file object to which output should be copied.
    """
    probe = DebugProbeAggregator.get_probe_with_id(board_id)
    assert probe is not None
    session = Session(probe, **get_session_options())
    board = session.board

    originalStdout = sys.stdout
    originalStderr = sys.stderr

    # Set up board-specific output file. A previously existing file is removed.
    env_name = (("_" + os.environ['TOX_ENV_NAME']) if ('TOX_ENV_NAME' in os.environ) else '')
    name_info = "{}_{}_{}".format(env_name, board.name, n)
    log_filename = os.path.join(TEST_OUTPUT_DIR, LOG_FILE_TEMPLATE.format(name_info))
    if os.path.exists(log_filename):
        os.remove(log_filename)
    
    # Skip board if specified in the config.
    if session.options['skip_test']:
        print("Skipping board %s due as specified in config" % board.unique_id)
        return []
    # Skip this board if we don't have a test binary.
    if board.test_binary is None:
        print("Skipping board %s due to missing test binary" % board.unique_id)
        return []

    # Open board-specific output file. This is done after skipping so a skipped board doesn't have a
    # log file created for it (but a previous log file will be removed, above).
    log_file = open(log_filename, "w", buffering=1) # 1=Line buffered
    
    # Setup logging.
    log_handler = RecordingLogHandler(None)
    log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)
    root_logger.addHandler(log_handler)

    result_list = []
    try:
        # Write board header to board log file, common log file, and console.
        print_board_header(log_file, board, n)
        if commonLogFile:
            print_board_header(commonLogFile, board, n, includeLeadingNewline=(n != 0))
        print_board_header(originalStdout, board, n, logToConsole, includeLeadingNewline=(n != 0))

        # Run all tests on this board.
        for test in test_list:
            print("{} #{}: starting {}...".format(board.name, n, test.name), file=originalStdout)
            
            # Set the test number on the test object. Used to get a unique port for the GdbTest.
            test.n = n

            # Print header and divider at the start of every test into the log files.
            print_test_header(log_file, board, test)
            if commonLogFile is not None:
                print_test_header(commonLogFile, board, test)
            
            # Create a StringIO object to record the test's output, an IOTee to copy
            # output to both the log file and StringIO, then set the log handler and
            # stdio to write to the tee.
            testOutput = io.StringIO()
            tee = IOTee(log_file, testOutput)
            if logToConsole:
                tee.add(originalStdout)
            if commonLogFile is not None:
                tee.add(commonLogFile)
            log_handler.stream = tee
            sys.stdout = tee
            sys.stderr = tee
            
            test_start = time()
            result = test.run(board)
            test_stop = time()
            result.time = test_stop - test_start
            tee.flush()
            result.output = testOutput.getvalue()
            result_list.append(result)
            
            passFail = "PASSED" if result.passed else "FAILED"
            print("{} #{}: finished {}... {} ({:.3f} s)".format(
                board.name, n, test.name, passFail, result.time),
                file=originalStdout)
    finally:
        # Restore stdout/stderr in case we're running in the parent process (1 job).
        sys.stdout = originalStdout
        sys.stderr = originalStderr

        root_logger.removeHandler(log_handler)
        log_handler.flush()
        log_handler.close()
    return result_list

def filter_tests(args):
    """! @brief Generate the list of tests to run based on arguments."""
    if args.exclude_tests and args.include_tests:
        print("Please only include or exclude tests, not both simultaneously.")
        sys.exit(1)
    excludes = [t.strip().lower() for t in args.exclude_tests.split(',')] if args.exclude_tests else []
    includes = [t.strip().lower() for t in args.include_tests.split(',')] if args.include_tests else []
    
    for test in all_tests:
        if excludes:
            include_it = (test.name.lower() not in excludes)
        elif includes:
            include_it = (test.name.lower() in includes)
        else:
            include_it = True
        
        if include_it:
            test_list.append(test)

def main():
    parser = argparse.ArgumentParser(description='pyOCD automated testing')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action="store_true", help='Hide test progress for 1 job')
    parser.add_argument('-j', '--jobs', action="store", default=1, type=int, metavar="JOBS",
        help='Set number of concurrent board tests (default is 1)')
    parser.add_argument('-b', '--board', action="append", metavar="ID", help="Limit testing to boards with specified unique IDs. Multiple boards can be listed.")
    parser.add_argument('-l', '--list-tests', action="store_true", help="Print a list of tests that will be run.")
    parser.add_argument('-x', '--exclude-tests', metavar="TESTS", default="", help="Comma-separated list of tests to exclude.")
    parser.add_argument('-i', '--include-tests', metavar="TESTS", default="", help="Comma-separated list of tests to include.")
    args = parser.parse_args()
    
    # Allow CI to override the number of concurrent jobs.
    if 'CI_JOBS' in os.environ:
        args.jobs = int(os.environ['CI_JOBS'])
    
    filter_tests(args)
    
    if args.list_tests:
        for test in test_list:
            print(test.name)
        return
    
    # Disable multiple jobs on macOS prior to Python 3.4. By default, multiprocessing uses
    # fork() on Unix, which doesn't work on the Mac because CoreFoundation requires exec()
    # to be used in order to init correctly (CoreFoundation is used in hidapi). Only on Python
    # version 3.4+ is the multiprocessing.set_start_method() API available that lets us
    # switch to the 'spawn' method, i.e. exec().
    if args.jobs > 1 and sys.platform.startswith('darwin') and sys.version_info[0:2] < (3, 4):
        print("WARNING: Cannot support multiple jobs on macOS prior to Python 3.4. Forcing 1 job.")
        args.jobs = 1

    ensure_output_dir()
    
    # Setup logging based on concurrency and quiet option.
    level = logging.DEBUG if args.debug else logging.INFO
    if args.jobs == 1 and not args.quiet:
        log_file = os.path.join(TEST_OUTPUT_DIR, LOG_FILE_TEMPLATE.format(get_env_file_name()))
        # Create common log file.
        if os.path.exists(log_file):
            os.remove(log_file)
        logToConsole = True
        commonLogFile = open(log_file, "a")
    else:
        logToConsole = False
        commonLogFile = None

    board_list = []
    result_list = []

    # Put together list of boards to test
    board_list = ConnectHelper.get_all_connected_probes(blocking=False)
    board_id_list = sorted(b.unique_id for b in board_list)
    
    # Filter boards.
    if args.board:
        board_id_list = [b for b in board_id_list if any(c for c in args.board if c.lower() in b.lower())]

    # If only 1 job was requested, don't bother spawning processes.
    start = time()
    if args.jobs == 1:
        for n, board_id in enumerate(board_id_list):
            result_list += test_board(board_id, n, level, logToConsole, commonLogFile)
    else:
        # Create a pool of processes to run tests.
        try:
            pool = mp.Pool(args.jobs)
            
            # Issue board test job to process pool.
            async_results = [pool.apply_async(test_board, (board_id, n, level, logToConsole, commonLogFile))
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
    summary_file = os.path.join(TEST_OUTPUT_DIR, SUMMARY_FILE_TEMPLATE.format(get_env_file_name()))
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

