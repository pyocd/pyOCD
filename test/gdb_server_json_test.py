"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

import argparse, os, sys
from time import sleep, time
from random import randrange
import math
import argparse
import subprocess
import json
import traceback

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD import __version__
from pyOCD.board import MbedBoard
from pyOCD.utility.conversion import float32beToU32be
from pyOCD.pyDAPAccess import DAPAccess
from test_util import Test, TestResult
import logging
from random import randrange

class GdbServerJsonTestResult(TestResult):
    def __init__(self):
        super(GdbServerJsonTestResult, self).__init__(None, None, None)

class GdbServerJsonTest(Test):
    def __init__(self):
        super(GdbServerJsonTest, self).__init__("Gdb Server Json Test", gdb_server_json_test)

    def print_perf_info(self, result_list, output_file=None):
        pass

    def run(self, board):
        try:
            result = self.test_function(board.getUniqueID())
        except Exception as e:
            result = GdbServerJsonTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def gdb_server_json_test(board_id):

    test_count = 0
    test_pass_count = 0

    def validate_basic_keys(data):
        did_pass = True

        print('pyocd_version', end=' ')
        p = 'pyocd_version' in data
        if p:
            p = data['pyocd_version'] == __version__
        if p:
            print("PASSED")
        else:
            did_pass = False
            print("FAILED")

        print('version', end=' ')
        p = 'version' in data
        if p:
            v = data['version']
            p = 'major' in v and 'minor' in v
        if p:
            p = v['major'] == 1 and v['minor'] == 0
        if p:
            print("PASSED")
        else:
            did_pass = False
            print("FAILED")

        print('status', end=' ')
        p = 'status' in data
        if p:
            p = data['status'] == 0
        if p:
            print("PASSED")
        else:
            did_pass = False
            print("FAILED")

        return did_pass

    def validate_boards(data):
        did_pass = True

        print('boards', end=' ')
        p = 'boards' in data and type(data['boards']) is list
        if p:
            b = data['boards']
        if p:
            print("PASSED")
        else:
            did_pass = False
            print("FAILED")

        try:
            all_mbeds = MbedBoard.getAllConnectedBoards(close=True, blocking=False)
            p = len(all_mbeds) == len(b)
            matching_boards = 0
            if p:
                for mbed in all_mbeds:
                    for brd in b:
                        if mbed.unique_id == brd['unique_id']:
                            matching_boards += 1
                            p = 'info' in brd and 'target' in brd and 'board_name' in brd
                            if not p:
                                break
                    if not p:
                        break
                p = matching_boards == len(all_mbeds)
            if p:
                print("PASSED")
            else:
                did_pass = False
                print("FAILED")
        except Exception as e:
            print("FAILED")
            traceback.print_exc(file=sys.stdout)
            did_pass = False

        return did_pass

    def validate_targets(data):
        did_pass = True

        print('targets', end=' ')
        p = 'targets' in data and type(data['targets']) is list
        if p:
            targets = data['targets']
            for t in targets:
                p = 'name' in t and 'part_number' in t
                if not p:
                    break
        if p:
            print("PASSED")
        else:
            did_pass = False
            print("FAILED")

        return did_pass


    result = GdbServerJsonTestResult()

    print("\n\n----- TESTING BOARDS LIST -----")
    out = subprocess.check_output(['pyocd-gdbserver', '--list', '--json'])
    data = json.loads(out)
    test_count += 2
    if validate_basic_keys(data):
        test_pass_count += 1
    if validate_boards(data):
        test_pass_count += 1

    print("\n\n----- TESTING TARGETS LIST -----")
    out = subprocess.check_output(['pyocd-gdbserver', '--list-targets', '--json'])
    data = json.loads(out)
    test_count += 2
    if validate_basic_keys(data):
        test_pass_count += 1
    if validate_targets(data):
        test_pass_count += 1

    result.passed = test_count == test_pass_count
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyocd-gdbserver json output test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    gdb_server_json_test(None)
