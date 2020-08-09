# pyOCD debugger
# Copyright (c) 2006-2015 Arm Limited
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

from pyocd import __version__
from pyocd.core.helpers import ConnectHelper
from pyocd.utility.conversion import float32_to_u32
from test_util import Test, TestResult
import logging
from random import randrange

class JsonListsTestResult(TestResult):
    def __init__(self):
        super(JsonListsTestResult, self).__init__(None, None, None)
        self.name = "json_lsits"

class JsonListsTest(Test):
    def __init__(self):
        super(JsonListsTest, self).__init__("Json Lists Test", json_lists_test)

    def print_perf_info(self, result_list, output_file=None):
        pass

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = JsonListsTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def json_lists_test(board_id, testing_standalone=False):

    test_count = 0
    test_pass_count = 0

    def validate_basic_keys(data, minor_version=0):
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
            p = v['major'] == 1 and v['minor'] == minor_version
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

        # Only if we're running this test standalone do we want to compare against the list
        # of boards returned by ConnectHelper.get_sessions_for_all_connected_probes(). When running in the full
        # automated test suite, there could be other test jobs running concurrently that have
        # exclusive access to the boards they are testing. Thus, those boards will not show up
        # in the return list and this test will fail.
        if testing_standalone:
            try:
                all_sessions = ConnectHelper.get_sessions_for_all_connected_probes(blocking=False)
                all_mbeds = [x.board for x in all_sessions]
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
        else:
            # Check for required keys in all board info dicts.
            p = True
            for brd in b:
                p = ('unique_id' in brd and
                    'info' in brd and
                    'target' in brd and
                    'board_name' in brd)
                if not p:
                    break
            if p:
                print("PASSED")
            else:
                did_pass = False
                print("FAILED")

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


    result = JsonListsTestResult()

    print("\n\n----- TESTING PROBES LIST -----")
    out = subprocess.check_output(['pyocd', 'json', '--probes'])
    data = json.loads(out)
    test_count += 2
    if validate_basic_keys(data):
        test_pass_count += 1
    if validate_boards(data):
        test_pass_count += 1

    print("\n\n----- TESTING TARGETS LIST -----")
    out = subprocess.check_output(['pyocd', 'json', '--targets'])
    data = json.loads(out)
    test_count += 2
    if validate_basic_keys(data, minor_version=2):
        test_pass_count += 1
    if validate_targets(data):
        test_pass_count += 1

    # Doesn't actually verify returned probes, simply makes sure it doesn't crash.
    print("\n\n----- TESTING BOARDS LIST -----")
    out = subprocess.check_output(['pyocd', 'json', '--boards'])
    data = json.loads(out)
    test_count += 1
    if validate_basic_keys(data, minor_version=1):
        test_pass_count += 1

    # Doesn't actually verify returned features and options, simply makes sure it doesn't crash.
    print("\n\n----- TESTING FEATURES LIST -----")
    out = subprocess.check_output(['pyocd', 'json', '--features'])
    data = json.loads(out)
    test_count += 1
    if validate_basic_keys(data, minor_version=1):
        test_pass_count += 1

    result.passed = test_count == test_pass_count
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyocd json output test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    json_lists_test(None, testing_standalone=True)
