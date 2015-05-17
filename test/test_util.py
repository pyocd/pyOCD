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
import pyOCD
import logging, os, sys

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
        return TestResult(board, self, passed)

    def print_perf_info(self, result_list):
        """
        Print performance info if any
        """
        pass

    @staticmethod
    def print_results(result_list):
        print("\r\n\r\n------ TEST RESULTS ------")
        print("{:<15}{:<15}{:<15}".format("Target","Test","Result"))
        print("")
        for result in result_list:
            print("{:<15}{:<15}{:<15}".format(result.board.target_type, result.test.name, "Pass" if result.passed else "Fail"))

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
