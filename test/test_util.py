# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import logging
import os
import sys
import traceback
from xml.etree import ElementTree
import six
import subprocess
import tempfile
import threading
from pyocd.utility.compatibility import to_str_safe

OBJCOPY = "arm-none-eabi-objcopy"

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PYOCD_DIR = os.path.dirname(TEST_DIR)
TEST_DATA_DIR = os.path.join(TEST_DIR, "data")
TEST_OUTPUT_DIR = os.path.join(TEST_DIR, "output")

def get_test_binary_path(binary_name):
    return os.path.join(TEST_DATA_DIR, "binaries", binary_name)

def get_env_name():
    return os.environ.get('TOX_ENV_NAME', '')

def get_env_file_name():
    env_name = get_env_name()
    return ("_" + env_name) if env_name else ''

def ensure_output_dir():
    if not os.path.isdir(TEST_OUTPUT_DIR):
        if os.path.exists(TEST_OUTPUT_DIR):
            raise RuntimeError("path '%s' already exists but is not a directory" % TEST_OUTPUT_DIR)
        os.mkdir(TEST_OUTPUT_DIR)

# Returns common option values passed in when creating test sessions.
def get_session_options():
    return {
        # These options can be overridden by probe config in pyocd.yaml.
        'option_defaults': {
            'frequency': 1000000, # 1 MHz
            'skip_test': False,
            },
        }

# Returns a dict containing some test parameters for the target in the passed-in session.
#
# 'test_clock' : the max supported SWD frequency for the target
# 'error_on_invalid_access' : whether invalid accesses cause a fault
#
def get_target_test_params(session):
    target_type = session.board.target_type
    error_on_invalid_access = True
    if target_type in ("nrf51", "nrf52", "nrf52840"):
        # Override clock since 10MHz is too fast
        test_clock = 1000000
        error_on_invalid_access = False
    elif target_type == "ncs36510":
        # Override clock since 10MHz is too fast
        test_clock = 1000000
    else:
        # Default of 10 MHz. Most probes will not actually run this fast, but this
        # sets them to their max supported frequency.
        test_clock = 10000000
    return {
            'test_clock': test_clock,
            'error_on_invalid_access': error_on_invalid_access,
            }

# Generate an Intel hex file from the binary test file.
def binary_to_hex_file(binary_file, base_address):
    temp_test_hex_name = tempfile.mktemp('.hex')
    objcopyOutput = subprocess.check_output([OBJCOPY,
        "-v", "-I", "binary", "-O", "ihex", "-B", "arm", "-S",
        "--set-start", "0x%x" % base_address,
        "--change-addresses", "0x%x" % base_address,
        binary_file, temp_test_hex_name], stderr=subprocess.STDOUT)
    print(to_str_safe(objcopyOutput))
    # Need to escape backslashes on Windows.
    if sys.platform.startswith('win'):
        temp_test_hex_name = temp_test_hex_name.replace('\\', '\\\\')
    return temp_test_hex_name

# Generate an elf from the binary test file.
def binary_to_elf_file(binary_file, base_address):
    temp_test_elf_name = tempfile.mktemp('.elf')
    objcopyOutput = subprocess.check_output([OBJCOPY,
        "-v", "-I", "binary", "-O", "elf32-littlearm", "-B", "arm", "-S",
        "--set-start", "0x%x" % base_address,
        "--change-addresses", "0x%x" % base_address,
        binary_file, temp_test_elf_name], stderr=subprocess.STDOUT)
    print(to_str_safe(objcopyOutput))
    # Need to escape backslashes on Windows.
    if sys.platform.startswith('win'):
        temp_test_elf_name = temp_test_elf_name.replace('\\', '\\\\')
    return temp_test_elf_name

def run_in_parallel(function, args_list):
    """Create and run a thread in parallel for each element in args_list

    Wait until all threads finish executing. Throw an exception if an exception
    occurred on any of the threads.
    """
    def _thread_helper(idx, func, args):
        """Run the function and set result to True if there was not error"""
        func(*args)
        result_list[idx] = True

    result_list = [False] * len(args_list)
    thread_list = []
    for idx, args in enumerate(args_list):
        thread = threading.Thread(target=_thread_helper,
                                  args=(idx, function, args))
        thread.start()
        thread_list.append(thread)

    for thread in thread_list:
        thread.join()
    for result in result_list:
        if result is not True:
            raise Exception("Running in thread failed")

def wait_with_deadline(process, timeout):
    try:
        from subprocess import TimeoutExpired
        try:
            process.wait(timeout=timeout)
        except TimeoutExpired as e:
            print('Timeout while waiting for process %s to exit: %s' % (process, e))
            process.kill()
            return False
    except ImportError:
        # Python 2.7 doesn't support deadline for wait.
        # Let's wait without deadline, as Python 2.7 support is close to end anyway.
        process.wait()
    return True

class IOTee(object):
    def __init__(self, *args):
        self.outputs = list(args)
    
    def add(self, output):
        self.outputs.append(output)

    def write(self, message):
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
        if 'TOX_ENV_NAME' in os.environ:
            classname = "{}.{}.{}.{}".format(os.environ['TOX_ENV_NAME'], self.board_name, self.board, self.name)
        else:
            classname = "{}.{}.{}".format(self.board_name, self.board, self.name)
        case = ElementTree.Element('testcase',
                    name=self.name,
                    classname=classname,
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
        system_out.text = self.filter_output(self.output)
        return case
    
    def filter_output(self, output):
        """! @brief Hex-encode null byte and control characters."""
        result = six.text_type()
        for c in output:
            if (c not in ('\n', '\r', '\t')) and (0 <= ord(c) <= 31):
                result += u"\\x{:02x}".format(ord(c))
            else:
                result += c
        return result

class Test(object):

    def __init__(self, name, function):
        self.name = name
        self.test_function = function
        self.n = 0

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
            
