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
import sys
import traceback
import logging
import tempfile

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.utility.mask import round_up_div
from pyocd.utility import conversion
from pyocd.core.memory_map import MemoryType
from pyocd.commands.execution_context import CommandExecutionContext
from pyocd.commands import commands
from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    binary_to_hex_file,
    binary_to_elf_file,
    get_test_binary_path,
    )

class CommandsTestResult(TestResult):
    def __init__(self):
        super(CommandsTestResult, self).__init__(None, None, None)
        self.name = "commands"

class CommandsTest(Test):
    def __init__(self):
        super(CommandsTest, self).__init__("Commands Test", commands_test)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = CommandsTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def commands_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target = session.target
        target_type = board.target_type

        test_params = get_target_test_params(session)
        session.probe.set_clock(test_params['test_clock'])

        memory_map = board.target.get_memory_map()
        boot_region = memory_map.get_boot_memory()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)
        ram_base = ram_region.start
        boot_start_addr = boot_region.start
        boot_end_addr = boot_region.end
        boot_blocksize = boot_region.blocksize
        binary_file = get_test_binary_path(board.test_binary)

        # Generate an Intel hex file from the binary test file.
        temp_test_hex_name = binary_to_hex_file(binary_file, boot_region.start)

        temp_bin_file = tempfile.mktemp('.bin')
        
        with open(binary_file, "rb") as f:
            test_data = list(bytearray(f.read()))
        test_data_length = len(test_data)
        test_file_sectors = round_up_div(test_data_length, boot_blocksize)
        boot_first_free_block_addr = boot_start_addr + test_file_sectors * boot_blocksize
        reset_handler_addr = conversion.byte_list_to_u32le_list(test_data[4:8])[0]

        test_pass_count = 0
        test_count = 0
        failed_commands = []
        result = CommandsTestResult()
        
        context = CommandExecutionContext()
        context.attach_session(session)
        
        COMMANDS_TO_TEST = [
                "status",
                "reset",
                "reset halt",
                "reg",
                "reg general",
                "reg all",
                "reg r0",
                "wreg r0 0x12345678",
#                 "d pc", # Disable disasm because capstone is not installed by default.
#                 "d --center pc 32",
                "read32 0x%08x" % (boot_start_addr + boot_blocksize),
                "read16 0x%08x" % (boot_start_addr + boot_blocksize),
                "read8 0x%08x" % (boot_start_addr + boot_blocksize),
                "rw 0x%08x 16" % ram_base,
                "rh 0x%08x 16" % ram_base,
                "rb 0x%08x 16" % ram_base,
                "write32 0x%08x 0x11223344 0x55667788" % ram_base,
                "write16 0x%08x 0xabcd" % (ram_base + 8),
                "write8 0x%08x 0 1 2 3 4 5 6" % (ram_base + 10),
                "savemem 0x%08x 128 '%s'" % (boot_start_addr, temp_bin_file),
                "loadmem 0x%08x '%s'" % (ram_base, temp_bin_file),
                "loadmem 0x%08x '%s'" % (boot_start_addr, binary_file),
                "load '%s'" % temp_test_hex_name,
                "load '%s' 0x%08x" % (binary_file, boot_start_addr),
                "compare 0x%08x '%s'" % (ram_base, temp_bin_file),
                "compare 0x%08x 32 '%s'" % (ram_base, temp_bin_file),
                "fill 0x%08x 128 0xa5" % ram_base,
                "fill 16 0x%08x 64 0x55aa" % (ram_base + 64),
                "find 0x%08x 128 0xaa 0x55" % ram_base, # find that will pass
                "find 0x%08x 128 0xff" % ram_base, # find that will fail
                "erase 0x%08x" % (boot_first_free_block_addr),
                "erase 0x%08x 1" % (boot_first_free_block_addr + boot_blocksize),
                "go",
                "halt",
                "step",
                "s 4",
                "continue",
                "h",
                "break 0x%08x" % reset_handler_addr,
                "lsbreak",
                "rmbreak 0x%08x" % reset_handler_addr,
                "watch 0x%08x" % ram_base,
                "lswatch",
                "rmwatch 0x%08x" % ram_base,
                "watch 0x%08x rw 2" % ram_base,
                "rmwatch 0x%08x" % ram_base,
                "core",
                "core 0",
                "readdp 0", # read DPIDR
                "writedp 0 0x1e", # write ABORT to clear error flags
                "readap 0xfc", # read IDR
                "readap 0 0xfc", # read IDR of AP#0
                "writeap 0x4 0", # set TAR to 0
                "writeap 0 0x4 0", # set TAR to 0 on AP#0
                "gdbserver start",
                "gdbserver status",
                "gdbserver stop",
                "probeserver start",
                "probeserver status",
                "probeserver stop",
                "show probe-uid",
                "show target",
                "show cores",
                "show map",
                "show peripherals",
                "show fault",
                "show nreset",
                "set nreset 1",
                "show option reset_type",
                "set option reset_type=sw",
                "show mem-ap",
                "set mem-ap 0",
                "show hnonsec",
                "set hnonsec 0",
                "show hprot",
                "set hprot 0x3", # set default hprot: data, priv
                "show graph",
                "show locked",
                "show register-groups",
                "show vector-catch",
                "set vector-catch all",
                "show step-into-interrupts",
                "set step-into-interrupts 1",
                "set log info",
                "set frequency %d" % test_params['test_clock'],
                
                # Semicolon-separated commands.
                'rw 0x%08x ; rw 0x%08x' % (ram_base, ram_base + 4),
                
                # Python and system commands.
                '$2+ 2',
                '!echo hello',
                '!echo hi \; echo there', # using escaped semicolon in a sytem command

                # Commands not tested:
#                 "list",
#                 "erase", # chip erase
#                 "unlock",
#                 "exit",
#                 "initdp",
#                 "makeap",
#                 "reinit",
#                 "where",
#                 "symbol",
                ]
        
        # For now we just verify that the commands run without raising an exception.
        print("\n------ Testing commands ------")
        
        def test_command(cmd):
            try:
                print("\nTEST: %s" % cmd)
                context.process_command_line(cmd)
            except:
                print("TEST FAILED")
                failed_commands.append(cmd)
                traceback.print_exc(file=sys.stdout)
                return False
            else:
                print("TEST PASSED")
                return True

        for cmd in COMMANDS_TO_TEST:
            if test_command(cmd):
                test_pass_count += 1
            test_count += 1

        print("\n\nTest Summary:")
        print("Pass count %i of %i tests" % (test_pass_count, test_count))
        if failed_commands:
            for c in failed_commands:
                print(" - '" + c + "'")
        if test_pass_count == test_count:
            print("COMMANDS TEST SCRIPT PASSED")
        else:
            print("COMMANDS TEST SCRIPT FAILED")

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD commands test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument('-u', '--uid', help='Debug probe unique ID')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    commands_test(args.uid)

