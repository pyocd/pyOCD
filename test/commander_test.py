# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import argparse
import sys
import traceback
import logging
from types import SimpleNamespace
import os
import tempfile

from pyocd.probe.pydapaccess import DAPAccess
from pyocd.commands.commander import PyOCDCommander
from test_util import (
    Test,
    TestResult,
    PYOCD_DIR,
    )

GDB_TEST_ELF = os.path.join(PYOCD_DIR, "src/gdb_test_program/gdb_test.elf")

class CommanderTestResult(TestResult):
    def __init__(self):
        super(CommanderTestResult, self).__init__(None, None, None)
        self.name = "commander"

class CommanderTest(Test):
    def __init__(self):
        super(CommanderTest, self).__init__("Commander Test", commander_test)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = CommanderTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def commander_test(board_id):
    test_pass_count = 0
    test_count = 0
    failed_commands = []
    result = CommanderTestResult()

    COMMANDS_TO_TEST = [
            # general commands
            "continue",
            "status",
            "halt",
            "status",

            # semicolon separated
            "status ; halt ; continue",
            "halt;continue",
            "halt; continue",

            # Python and shell
            "$ 2+2",
            "!echo 'hi mom'",
            " $ target.vendor",

            # commander command group - these are not tested by commands_test.py.
            "list",
            "exit", # Must be last command!
            ]

    # Set up commander args.
    args = SimpleNamespace()
    args.no_init = False
    args.frequency = 1000000
    args.options = {} #get_session_options()
    args.halt = True
    args.no_wait = True
    args.project_dir = None
    args.config = None
    args.script = None
    args.no_config = False
    args.pack = None
    args.unique_id = board_id
    args.target_override = None
    args.elf = GDB_TEST_ELF
    args.interactive = False

    #
    # Test basic functionality.
    #
    print("\n------ Testing basic functionality ------\n")

    test_count += 1
    try:
        cmdr = PyOCDCommander(args, COMMANDS_TO_TEST)
        cmdr.run()
        test_pass_count += 1
        print("TEST PASSED")

        test_count += 1
        print("Testing exit code")
        print("Exit code:", cmdr.exit_code)
        if cmdr.exit_code == 0:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")
    except Exception:
        print("TEST FAILED")
        traceback.print_exc()

    #
    # Test running command files.
    #
    print("\n------ Testing command files ------\n")

    with tempfile.NamedTemporaryFile('w+') as cmdfile:
        cmdfile.write("""# here is a comment
halt
reg
continue

# semicolons
halt ; status

# Python and system
$ {'a': 1, 'b': 2}
!echo "hello, world!"
$target.part_number
!echo first ; echo second
""")

        # Jump back to the start of the file.
        cmdfile.seek(0, 0)

        test_count += 1
        try:
            cmdr = PyOCDCommander(args, [cmdfile.file])
            cmdr.run()
            test_pass_count += 1
            print("TEST PASSED")

            test_count += 1
            print("Testing exit code")
            print("Exit code:", cmdr.exit_code)
            if cmdr.exit_code == 0:
                test_pass_count += 1
                print("TEST PASSED")
            else:
                print("TEST FAILED")
        except Exception:
            print("TEST FAILED")
            traceback.print_exc()

    print("\n\nTest Summary:")
    print("Pass count %i of %i tests" % (test_pass_count, test_count))
    if failed_commands:
        for c in failed_commands:
            print(" - '" + c + "'")
    if test_pass_count == test_count:
        print("COMMANDER TEST SCRIPT PASSED")
    else:
        print("COMMANDER TEST SCRIPT FAILED")

    result.passed = test_count == test_pass_count
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD commander test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument('-u', '--uid', help='Debug probe unique ID')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    commander_test(args.uid)

