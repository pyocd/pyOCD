"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2017-2018 ARM Limited

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
import traceback
import argparse
from collections import namedtuple

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from pyOCD.core.target import Target
from test_util import Test, TestResult
import logging

STATE_NAMES = {
    Target.TARGET_RUNNING : "running",
    Target.TARGET_HALTED : "halted",
    Target.TARGET_RESET : "reset",
    Target.TARGET_SLEEPING : "sleeping",
    Target.TARGET_LOCKUP : "lockup",
    }

RUNNING = Target.TARGET_RUNNING
HALTED = Target.TARGET_HALTED

class ConnectTestCase(object):
    def __init__(self, prev_exit_state, halt_on_connect, expected_state, disconnect_resume, exit_state):
        self.prev_exit_state = prev_exit_state
        self.halt_on_connect = halt_on_connect
        self.expected_state = expected_state
        self.disconnect_resume = disconnect_resume
        self.exit_state = exit_state

class ConnectTestResult(TestResult):
    def __init__(self):
        super(ConnectTestResult, self).__init__(None, None, None)

class ConnectTest(Test):
    def __init__(self):
        super(ConnectTest, self).__init__("Connect Test", connect_test)

    def run(self, board):
        try:
            result = self.test_function(board)
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
            result = ConnectTestResult()
            result.passed = False
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result


def connect_test(board):
    board_id = board.getUniqueID()
    binary_file = os.path.join(parentdir, 'binaries', board.getTestBinary())
    print("binary file: %s" % binary_file)

    test_pass_count = 0
    test_count = 0
    result = ConnectTestResult()

    # Install binary.
    live_board = MbedBoard.chooseBoard(board_id=board_id, frequency=1000000)
    memory_map = board.target.getMemoryMap()
    rom_region = memory_map.getBootMemory()
    rom_start = rom_region.start

    def test_connect(halt_on_connect, expected_state, resume):
        print("Connecting with halt_on_connect=%s" % halt_on_connect)
        live_board = MbedBoard.chooseBoard(board_id=board_id, frequency=1000000, init_board=False)
        live_board.target.setHaltOnConnect(halt_on_connect)
        live_board.init()
        print("Verifying target is", STATE_NAMES.get(expected_state, "unknown"))
        actualState = live_board.target.getState()
        if actualState == expected_state:
            passed = 1
            print("TEST PASSED")
        else:
            passed = 0
            print("TEST FAILED (state={}, expected={})".format(
                STATE_NAMES.get(actualState, "unknown"),
                STATE_NAMES.get(expected_state, "unknown")))
        print("Disconnecting with resume=%s" % resume)
        live_board.uninit(resume)
        live_board = None
        return passed

    # TEST CASE COMBINATIONS
    test_cases = [
    #                <prev_exit> <halt_on_connect> <expected_state> <disconnect_resume> <exit_state>
    ConnectTestCase( RUNNING,    False,            RUNNING,         False,              RUNNING  ),
    ConnectTestCase( RUNNING,    True,             HALTED,          False,              HALTED   ),
    ConnectTestCase( HALTED,     True,             HALTED,          True,               RUNNING  ),
    ConnectTestCase( RUNNING,    True,             HALTED,          True,               RUNNING  ),
    ConnectTestCase( RUNNING,    False,            RUNNING,         True,               RUNNING  ),
    ConnectTestCase( RUNNING,    True,             HALTED,          False,              HALTED   ),
    ConnectTestCase( HALTED,     False,            HALTED,          False,              HALTED   ),
    ConnectTestCase( HALTED,     True,             HALTED,          False,              HALTED   ),
    ConnectTestCase( HALTED,     False,            HALTED,          True,               RUNNING  ),
    ConnectTestCase( RUNNING,    False,            RUNNING,         False,              RUNNING  ),
    ]

    print("\n\n----- FLASH NEW BINARY -----")
    live_board.flash.flashBinary(binary_file, rom_start)
    live_board.target.reset()
    test_count += 1
    print("Verifying target is running")
    if live_board.target.isRunning():
        test_pass_count += 1
        print("TEST PASSED")
    else:
        print("TEST FAILED")
    print("Disconnecting with resume=True")
    live_board.uninit(resume=True)
    live_board = None
    # Leave running.

    # Run all the cases.
    for case in test_cases:
        test_count += 1
        did_pass = test_connect(
            halt_on_connect=case.halt_on_connect,
            expected_state=case.expected_state,
            resume=case.disconnect_resume
            )
        test_pass_count += did_pass
        case.passed=did_pass

    print("\n\nTest Summary:")
    print("\n{:<4}{:<12}{:<19}{:<12}{:<21}{:<11}{:<10}".format(
        "#", "Prev Exit", "Halt on Connect", "Expected", "Disconnect Resume", "Exit", "Passed"))
    for i, case in enumerate(test_cases):
        print("{:<4}{:<12}{:<19}{:<12}{:<21}{:<11}{:<10}".format(
            i,
            STATE_NAMES[case.prev_exit_state],
            repr(case.halt_on_connect),
            STATE_NAMES[case.expected_state],
            repr(case.disconnect_resume),
            STATE_NAMES[case.exit_state],
            "PASS" if case.passed else "FAIL"))
    print("\nPass count %i of %i tests" % (test_pass_count, test_count))
    if test_pass_count == test_count:
        print("CONNECT TEST SCRIPT PASSED")
    else:
        print("CONNECT TEST SCRIPT FAILED")

    result.passed = (test_count == test_pass_count)
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD connect test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    board = pyOCD.board.mbed_board.MbedBoard.getAllConnectedBoards(close=True)[0]
    test = ConnectTest()
    result = [test.run(board)]
    test.print_perf_info(result)
