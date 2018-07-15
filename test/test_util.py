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

import pyOCD
import logging, os, sys
import traceback

class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

class TestResult(object):

    def __init__(self, test_board, test, result):
        self.passed = result
        self.board = test_board
        self.test = test

class Test(object):

    def __init__(self, name, function):
        self.name = name
        self.test_function = function

    def run(self, board):
        """
        Run test and return the result

        Override this function to return a custom result
        """
        passed = False
        try:
            self.test_function(board.getUniqueID())
            passed = True
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
            traceback.print_exc(file=sys.stdout)
        return TestResult(board, self, passed)

    def print_perf_info(self, result_list, output_file=None):
        """
        Print performance info if any
        """
        pass

    @staticmethod
    def print_results(result_list, output_file=None):
        msg_format_str = "{:<15}{:<21}{:<15}{:<15}"
        print("\n\n------ TEST RESULTS ------")
        print(msg_format_str .format("Target", "Test", "Result", "Time"),
              file=output_file)
        print("", file=output_file)
        for result in result_list:
            status_str = "Pass" if result.passed else "Fail"
            print(msg_format_str.format(result.board.target_type,
                                        result.test.name,
                                        status_str, "%.3f" % result.time),
                  file=output_file)

    @staticmethod
    def all_tests_pass(result_list):
        passed = True
        for result in result_list:
            if not result.passed:
                passed = False
                break
        if len(result_list) <= 0:
            passed = False
        return passed
