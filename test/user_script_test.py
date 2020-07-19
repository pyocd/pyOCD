# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import argparse
import os
import sys
import traceback
import logging

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.core.memory_map import MemoryType

from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    get_test_binary_path,
    TEST_DIR,
    )

TEST_USER_SCRIPT = os.path.join(TEST_DIR, "test_user_script.py")

class UserScriptTestResult(TestResult):
    def __init__(self):
        super(UserScriptTestResult, self).__init__(None, None, None)
        self.name = "user_script"

class UserScriptTest(Test):
    def __init__(self):
        super(UserScriptTest, self).__init__("User Script Test", user_script_test)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = UserScriptTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def user_script_test(board_id):
    with ConnectHelper.session_with_chosen_probe(
            unique_id=board_id, user_script=TEST_USER_SCRIPT, **get_session_options()) as session:
        board = session.board
        target = session.target

        test_params = get_target_test_params(session)
        session.probe.set_clock(test_params['test_clock'])

        memory_map = target.get_memory_map()
        boot_region = memory_map.get_boot_memory()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)
        binary_file = get_test_binary_path(board.test_binary)
        
        test_pass_count = 0
        test_count = 0
        result = UserScriptTestResult()

        target.reset_and_halt()
        target.resume()
        target.halt()
        target.step()
        
        test_count += 1
        test_pass_count += 1
        
        print("\nTest Summary:")
        print("Pass count %i of %i tests" % (test_pass_count, test_count))
        if test_pass_count == test_count:
            print("USER SCRIPT TEST PASSED")
        else:
            print("USER SCRIPT TEST FAILED")

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD user script test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    # Set to debug to print some of the decisions made while flashing
    session = ConnectHelper.session_with_chosen_probe(**get_session_options())
    test = UserScriptTest()
    result = [test.run(session.board)]

