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

import logging
import os
import sys
import traceback
from xml.etree import ElementTree
import six

isPy2 = (sys.version_info[0] == 2)

# Returns common option values passed in when creating test sessions.
def get_session_options():
    return {
        'config_file' : 'test_boards.yaml',
        'frequency' : 1000000, # 1 MHz
        }

class IOTee(object):
    def __init__(self, *args):
        self.outputs = list(args)
    
    def add(self, output):
        self.outputs.append(output)

    def write(self, message):
        if isPy2 and isinstance(message, str):
            message = message.decode('UTF-8')
        for out in self.outputs:
            out.write(message)

    def flush(self):
        for out in self.outputs:
            out.flush()

class RecordingLogHandler(logging.Handler):
    def __init__(self, iostream, level=logging.NOTSET):
        super(RecordingLogHandler, self).__init__(level)
        self.stream = iostream
    
    def emit(self, record):
        try:
            message = self.format(record)
            if isPy2 and isinstance(message, unicode):
                message = message.encode('UTF-8')
            self.stream.write(six.u(message + "\n"))
        except:
            self.handleError(record)

class TestResult(object):

    def __init__(self, test_board, test, result):
        self.passed = result
        self._board = test_board.target_type if test_board else 'unknown'
        self.board_name = test_board.name if test_board else ""
        self.test = test
        self.name = "test"
        self.time = 0
        self.output = ""
    
    @property
    def board(self):
        return self._board
    
    @board.setter
    def board(self, newBoard):
        self._board = newBoard.target_type if newBoard else 'unknown'
        self.board_name = newBoard.name

    def get_test_case(self):
        case = ElementTree.Element('testcase',
                    name=self.name,
                    classname="{}.{}.{}".format(self.board_name, self.board, self.name),
                    status=("passed" if self.passed else "failed"),
                    time="%.3f" % self.time
                    )
        case.text = "\n"
        case.tail = "\n"
        if not self.passed:
            failed = ElementTree.SubElement(case, 'failure',
                        message="failure",
                        type="failure"
                        )
        system_out = ElementTree.SubElement(case, 'system-out')
        system_out.text = self.output
        return case

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
            self.test_function(board.unique_id)
            passed = True
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result = TestResult(board, self, passed)
        result.name = self.name
        return result

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
            print(msg_format_str.format(result.board,
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
            
