#!/usr/bin/env python
"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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

import argparse
import logging
import traceback

from pyOCD import __version__
from pyOCD.gdbserver import GDBServer
from pyOCD.board import MbedBoard
import pyOCD.board.mbed_board

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

supported_targets = pyOCD.target.TARGET.keys()
debug_levels = LEVELS.keys()

# Keep args in snyc with flash_tool.py when possible
parser = argparse.ArgumentParser(description='PyOCD GDB Server')
parser.add_argument('--version', action='version', version=__version__)
parser.add_argument("-p", "--port", dest = "port_number", type=int, default = 3333, help = "Write the port number that GDB server will open.")
parser.add_argument("-c", "--cmd-port", dest = "cmd_port", default = 4444, help = "Command port number. pyOCD doesn't open command port, but it's required to be compatible with OpenOCD and Eclipse.")
parser.add_argument("-b", "--board", dest = "board_id", default = None, help="Connect to board by board id.  Use -l to list all connected boards.")
parser.add_argument("-l", "--list", action = "store_true", dest = "list_all", default = False, help = "List all connected boards.")
parser.add_argument("-d", "--debug", dest = "debug_level", choices = debug_levels, default = 'info', help = "Set the level of system logging output. Supported choices are: "+", ".join(debug_levels), metavar="LEVEL")
parser.add_argument("-t", "--target", dest = "target_override", choices=supported_targets, default = None, help = "Override target to debug.  Supported targets are: "+", ".join(supported_targets), metavar="TARGET")
parser.add_argument("-n", "--nobreak", dest = "break_at_hardfault", default = True, action="store_false", help = "Disable halt at hardfault handler." )
parser.add_argument("-r", "--reset-break", dest = "break_on_reset", default = False, action="store_true", help = "Halt the target when reset." )
parser.add_argument("-s", "--step-int", dest = "step_into_interrupt", default = False, action="store_true", help = "Allow single stepping to step into interrupts." )
parser.add_argument("-f", "--frequency", dest = "frequency", default = 1000000, type=int, help = "Set the SWD clock frequency in Hz." )
parser.add_argument("-o", "--persist", dest = "persist", default = False, action="store_true", help = "Keep GDB server running even after remote has detached.")
parser.add_argument("-bh", "--soft-bkpt-as-hard", dest = "soft_bkpt_as_hard", default = False, action = "store_true", help = "Replace software breakpoints with hardware breakpoints.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-ce", "--chip_erase", action="store_true",help="Use chip erase when programming.")
group.add_argument("-se", "--sector_erase", action="store_true",help="Use sector erase when programming.")
# -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked
parser.add_argument("-u", "--unlock", action="store_true", default=False, help="Unlock the device.")
# reserved: "-a", "--address"
# reserved: "-s", "--skip"
parser.add_argument("-hp", "--hide_progress", action="store_true", help = "Don't display programming progress." )
parser.add_argument("-fp", "--fast_program", action="store_true", help = "Use only the CRC of each page to determine if it already has the same data.")


def get_chip_erase(args):
    # Determine programming mode
    chip_erase = None
    if args.chip_erase:
        chip_erase = True
    elif args.sector_erase:
        chip_erase = False
    return chip_erase


def get_gdb_server_settings(args):
    # Set gdb server settings
    return {
        'break_at_hardfault' : args.break_at_hardfault,
        'step_into_interrupt' : args.step_into_interrupt,
        'break_on_reset' : args.break_on_reset,
        'persist' : args.persist,
        'soft_bkpt_as_hard' : args.soft_bkpt_as_hard,
        'chip_erase': get_chip_erase(args),
        'hide_programming_progress' : args.hide_progress,
        'fast_program' : args.fast_program,
    }


def setup_logging(args):
    level = LEVELS.get(args.debug_level, logging.NOTSET)
    logging.basicConfig(level=level)


def main():
    args = parser.parse_args()
    gdb_server_settings = get_gdb_server_settings(args)
    setup_logging(args)

    gdb = None
    if args.list_all == True:
        MbedBoard.listConnectedBoards()
    else:
        try:
            board_selected = MbedBoard.chooseBoard(
                board_id=args.board_id,
                target_override=args.target_override,
                frequency=args.frequency)
            with board_selected as board:
                # Boost speed with deferred transfers
                board.transport.setDeferredTransfer(True)
                gdb = GDBServer(board, args.port_number, gdb_server_settings)
                while gdb.isAlive():
                    gdb.join(timeout=0.5)
        except KeyboardInterrupt:
            if gdb != None:
                gdb.stop()
        except Exception as e:
            print "uncaught exception: %s" % e
            traceback.print_exc()
            if gdb != None:
                gdb.stop()

if __name__ == '__main__':
    main()
