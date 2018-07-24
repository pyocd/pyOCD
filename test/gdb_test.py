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

# Note
#  To run this script GNU Tools ARM Embedded must be installed,
#  along with python for the same architecture.  The program
#  "arm-none-eabi-gdb-py.exe" requires python for the same
#  architecture (x86 or 64) to work correctly. Also, on windows
#  the GNU Tools ARM Embedded bin directory needs to be added to
#  your path.

import os
import json
import sys
from subprocess import Popen, STDOUT, PIPE, check_call
import argparse
import logging
import traceback
import tempfile

from pyOCD.tools.gdb_server import GDBServerTool
from pyOCD.board import MbedBoard
from test_util import Test, TestResult

# TODO, c1728p9 - run script several times with
#       with different command line parameters

TEST_PARAM_FILE = "test_params.txt"
TEST_RESULT_FILE = "test_results.txt"
PYTHON_GDB = "arm-none-eabi-gdb-py"
OBJCOPY = "arm-none-eabi-objcopy"

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class GdbTestResult(TestResult):
    def __init__(self):
        super(self.__class__, self).__init__(None, None, None)


class GdbTest(Test):
    def __init__(self):
        super(self.__class__, self).__init__("Gdb Test", test_gdb)

    def print_perf_info(self, result_list, output_file=None):
        pass

    def run(self, board):
        try:
            result = self.test_function(board.getUniqueID())
        except Exception as e:
            result = GdbTestResult()
            result.passed = False
            print("Exception %s when testing board %s" %
                  (e, board.getUniqueID()))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

TEST_RESULT_KEYS = [
    "breakpoint_count",
    "watchpoint_count",
    "step_time_si",
    "step_time_s",
    "step_time_n",
    "fail_count",
]


def test_gdb(board_id=None):
    temp_test_elf_name = None
    result = GdbTestResult()
    with MbedBoard.chooseBoard(board_id=board_id) as board:
        memory_map = board.target.getMemoryMap()
        ram_regions = [region for region in memory_map if region.type == 'ram']
        ram_region = ram_regions[0]
        rom_region = memory_map.getBootMemory()
        target_type = board.getTargetType()
        binary_file = os.path.join(parentdir, 'binaries',
                                   board.getTestBinary())
        if board_id is None:
            board_id = board.getUniqueID()
        test_clock = 10000000
        test_port = 3334
        error_on_invalid_access = True
        # Hardware breakpoints are not supported above 0x20000000 on
        # CortexM devices
        ignore_hw_bkpt_result = 1 if ram_region.start >= 0x20000000 else 0
        if target_type == "nrf51":
            # Override clock since 10MHz is too fast
            test_clock = 1000000
            # Reading invalid ram returns 0 or nrf51
            error_on_invalid_access = False
        if target_type == "ncs36510":
            # Override clock since 10MHz is too fast
            test_clock = 1000000

        # Program with initial test image
        board.flash.flashBinary(binary_file, rom_region.start)
        board.uninit(False)

    # Generate an elf from the binary test file.
    temp_test_elf_name = tempfile.mktemp('.elf')
    check_call([OBJCOPY, "-v", "-I", "binary", "-O", "elf32-littlearm", "-B", "arm", "-S",
        "--set-start", "0x%x" % rom_region.start, binary_file, temp_test_elf_name])
    # Need to escape backslashes on Windows.
    if sys.platform.startswith('win'):
        temp_test_elf_name = temp_test_elf_name.replace('\\', '\\\\')

    # Write out the test configuration
    test_params = {}
    test_params["rom_start"] = rom_region.start
    test_params["rom_length"] = rom_region.length
    test_params["ram_start"] = ram_region.start
    test_params["ram_length"] = ram_region.length
    test_params["invalid_start"] = 0x3E000000
    test_params["invalid_length"] = 0x1000
    test_params["expect_error_on_invalid_access"] = error_on_invalid_access
    test_params["ignore_hw_bkpt_result"] = ignore_hw_bkpt_result
    test_params["test_elf"] = temp_test_elf_name
    with open(TEST_PARAM_FILE, "w") as f:
        f.write(json.dumps(test_params))

    # Run the test
    gdb = [PYTHON_GDB, "--command=gdb_script.py"]
    with open("output.txt", "w") as f:
        program = Popen(gdb, stdin=PIPE, stdout=f, stderr=STDOUT)
        args = ['-p=%i' % test_port, "-f=%i" % test_clock, "-b=%s" % board_id]
        server = GDBServerTool()
        server.run(args)
        program.wait()

    # Read back the result
    with open(TEST_RESULT_FILE, "r") as f:
        test_result = json.loads(f.read())

    # Print results
    if set(TEST_RESULT_KEYS).issubset(test_result):
        print("----------------Test Results----------------")
        print("HW breakpoint count: %s" % test_result["breakpoint_count"])
        print("Watchpoint count: %s" % test_result["watchpoint_count"])
        print("Average instruction step time: %s" %
              test_result["step_time_si"])
        print("Average single step time: %s" % test_result["step_time_s"])
        print("Average over step time: %s" % test_result["step_time_n"])
        print("Failure count: %i" % test_result["fail_count"])
        result.passed = test_result["fail_count"] == 0
    else:
        result.passed = False

    # Cleanup
    if temp_test_elf_name and os.path.exists(temp_test_elf_name):
        os.remove(temp_test_elf_name)
    os.remove(TEST_RESULT_FILE)
    os.remove(TEST_PARAM_FILE)

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD gdb test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    test_gdb()
