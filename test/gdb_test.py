# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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
from subprocess import (
    Popen,
    STDOUT,
    PIPE,
    check_output,
    )
import argparse
import logging
import traceback

from pyocd.__main__ import PyOCDTool
from pyocd.core.helpers import ConnectHelper
from pyocd.utility.compatibility import to_str_safe
from pyocd.core.memory_map import MemoryType
from pyocd.flash.file_programmer import FileProgrammer
from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    binary_to_elf_file,
    get_env_file_name
    )

# TODO, c1728p9 - run script several times with
#       with different command line parameters

PYTHON_GDB = "arm-none-eabi-gdb-py"

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class GdbTestResult(TestResult):
    def __init__(self):
        super(self.__class__, self).__init__(None, None, None)
        self.name = "gdbserver"


class GdbTest(Test):
    def __init__(self):
        super(self.__class__, self).__init__("Gdb Test", test_gdb)
        self.n = 0

    def print_perf_info(self, result_list, output_file=None):
        pass

    def run(self, board):
        try:
            result = self.test_function(board.unique_id, self.n)
        except Exception as e:
            result = GdbTestResult()
            result.passed = False
            print("Exception %s when testing board %s" %
                  (e, board.unique_id))
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


def test_gdb(board_id=None, n=0):
    temp_test_elf_name = None
    result = GdbTestResult()
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        memory_map = board.target.get_memory_map()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)
        rom_region = memory_map.get_boot_memory()
        target_type = board.target_type
        binary_file = os.path.join(parentdir, 'binaries',
                                   board.test_binary)
        if board_id is None:
            board_id = board.unique_id
        target_test_params = get_target_test_params(session)
        test_port = 3333 + n
        telnet_port = 4444 + n
        # Hardware breakpoints are not supported above 0x20000000 on
        # CortexM devices
        ignore_hw_bkpt_result = 1 if ram_region.start >= 0x20000000 else 0

        # Program with initial test image
        FileProgrammer(session).program(binary_file, base_address=rom_region.start)

    # Generate an elf from the binary test file.
    temp_test_elf_name = binary_to_elf_file(binary_file, rom_region.start)

    # Write out the test configuration
    test_params = {
        "test_port" : test_port,
        "rom_start" : rom_region.start,
        "rom_length" : rom_region.length,
        "ram_start" : ram_region.start,
        "ram_length" : ram_region.length,
        "invalid_start" : 0x3E000000,
        "invalid_length" : 0x1000,
        "expect_error_on_invalid_access" : target_test_params['error_on_invalid_access'],
        "ignore_hw_bkpt_result" : ignore_hw_bkpt_result,
        "test_elf" : temp_test_elf_name,
        }
    test_param_filename = "gdb_test_params%s_%d.txt" % (get_env_file_name(), n)
    with open(test_param_filename, "w") as f:
        f.write(json.dumps(test_params))

    # Run the test
    gdb = [PYTHON_GDB, "--nh", "-ex", "set $testn=%d" % n, "--command=gdb_script.py"]
    output_filename = "gdb_output%s_%s_%d.txt" % (get_env_file_name(), board.target_type, n)
    with open(output_filename, "w") as f:
        program = Popen(gdb, stdin=PIPE, stdout=f, stderr=STDOUT)
        args = ['gdbserver',
                '--port=%i' % test_port,
                "--telnet-port=%i" % telnet_port,
                "--frequency=%i" % target_test_params['test_clock'],
                "--uid=%s" % board_id,
                ]
        server = PyOCDTool()
        server.run(args)
        program.wait()

    # Read back the result
    test_result_filename = "gdb_test_results%s_%d.txt" % (get_env_file_name(), n)
    with open(test_result_filename, "r") as f:
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
    os.remove(test_result_filename)
    os.remove(test_param_filename)

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD gdb test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    test_gdb()
