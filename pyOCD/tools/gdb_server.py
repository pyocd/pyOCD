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

from __future__ import print_function
import sys
import logging
import traceback
import argparse
import json
import pkg_resources

from .. import __version__
from .. import target
from ..debug.svd import isCmsisSvdAvailable
from ..gdbserver import GDBServer
from ..board.mbed_board import MbedBoard
from ..utility.cmdline import (split_command_line, VECTOR_CATCH_CHAR_MAP, convert_vector_catch)
from ..pyDAPAccess.dap_access_cmsis_dap import DAPAccessCMSISDAP
from ..pyDAPAccess import DAPAccess

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

supported_targets = list(target.TARGET.keys())
debug_levels = list(LEVELS.keys())

class InvalidArgumentError(RuntimeError):
    pass

## @brief Argparse type function to validate the supplied target device name.
#
# If the target name is valid, it is returned unmodified to become the --target option's
# attribute value.
def validate_target(value):
    if value.lower() not in supported_targets:
        raise InvalidArgumentError("invalid target option '{}'".format(value))
    return value

class GDBServerTool(object):
    def __init__(self):
        self.args = None
        self.gdb_server_settings = None
        self.echo_msg = None

    def build_parser(self):
        # Build epilog with list of targets.
        epilog = "Available targets for use with --target option: " + ", ".join(supported_targets)

        # Keep args in snyc with flash_tool.py when possible
        parser = argparse.ArgumentParser(description='PyOCD GDB Server', epilog=epilog)
        parser.add_argument('--version', action='version', version=__version__)
        parser.add_argument("-p", "--port", dest="port_number", type=int, default=3333, help="Set the port number that GDB server will open (default 3333).")
        parser.add_argument("-sc", "--semihost-console", dest="semihost_console_type", default="telnet", choices=('telnet', 'stdx'), help="Console for semihosting.")
        parser.add_argument("-T", "--telnet-port", dest="telnet_port", type=int, default=4444, help="Specify the telnet port for semihosting (default 4444).")
        parser.add_argument("--allow-remote", dest="serve_local_only", default=True, action="store_false", help="Allow remote TCP/IP connections (default is no).")
        parser.add_argument("-b", "--board", dest="board_id", default=None, help="Connect to board by board ID. Use -l to list all connected boards. Only a unique part of the board ID needs to be provided.")
        parser.add_argument("-l", "--list", action="store_true", dest="list_all", default=False, help="List all connected boards.")
        parser.add_argument("--list-targets", action="store_true", dest="list_targets", default=False, help="List all available targets.")
        parser.add_argument("--json", action="store_true", dest="output_json", default=False, help="Output lists in JSON format. Only applies to --list and --list-targets.")
        parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='info', help="Set the level of system logging output. Supported choices are: " + ", ".join(debug_levels), metavar="LEVEL")
        parser.add_argument("-t", "--target", dest="target_override", default=None, help="Override target to debug.", metavar="TARGET", type=validate_target)
        parser.add_argument("-n", "--nobreak", dest="no_break_at_hardfault", action="store_true", help="Disable halt at hardfault handler. (Deprecated)")
        parser.add_argument("-r", "--reset-break", dest="break_on_reset", action="store_true", help="Halt the target when reset. (Deprecated)")
        parser.add_argument("-C", "--vector-catch", default='h', help="Enable vector catch sources, one letter per enabled source in any order, or 'all' or 'none'. (h=hard fault, b=bus fault, m=mem fault, i=irq err, s=state err, c=check err, p=nocp, r=reset, a=all, n=none). (Default is hard fault.)")
        parser.add_argument("-s", "--step-int", dest="step_into_interrupt", default=False, action="store_true", help="Allow single stepping to step into interrupts.")
        parser.add_argument("-f", "--frequency", dest="frequency", default=1000000, type=int, help="Set the SWD clock frequency in Hz.")
        parser.add_argument("-o", "--persist", dest="persist", default=False, action="store_true", help="Keep GDB server running even after remote has detached.")
        parser.add_argument("-bh", "--soft-bkpt-as-hard", dest="soft_bkpt_as_hard", default=False, action="store_true", help="Replace software breakpoints with hardware breakpoints.")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-ce", "--chip_erase", action="store_true", help="Use chip erase when programming.")
        group.add_argument("-se", "--sector_erase", action="store_true", help="Use sector erase when programming.")
        # -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked
        parser.add_argument("-u", "--unlock", action="store_true", default=False, help="Unlock the device.")
        # reserved: "-a", "--address"
        # reserved: "-s", "--skip"
        parser.add_argument("-hp", "--hide_progress", action="store_true", help="Don't display programming progress.")
        parser.add_argument("-fp", "--fast_program", action="store_true", help="Use only the CRC of each page to determine if it already has the same data.")
        parser.add_argument("-S", "--semihosting", dest="enable_semihosting", action="store_true", help="Enable semihosting.")
        parser.add_argument("-G", "--gdb-syscall", dest="semihost_use_syscalls", action="store_true", help="Use GDB syscalls for semihosting file I/O.")
        parser.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+', help="Run command (OpenOCD compatibility).")
        parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
        self.parser = parser
        return parser

    def get_chip_erase(self, args):
        # Determine programming mode
        chip_erase = None
        if args.chip_erase:
            chip_erase = True
        elif args.sector_erase:
            chip_erase = False
        return chip_erase

    def get_vector_catch(self, args):
        vector_catch = args.vector_catch.lower()

        # Handle deprecated options.
        if args.break_on_reset:
            vector_catch += 'r'
        if args.no_break_at_hardfault:
            # Must handle all case specially since we can't just filter 'h'.
            if vector_catch == 'all' or 'a' in vector_catch:
                vector_catch = 'bmiscpr' # Does not include 'h'.
            else:
                vector_catch = vector_catch.replace('h', '')

        try:
            return convert_vector_catch(vector_catch)
        except ValueError as e:
            # Reraise as an invalid argument error.
            raise InvalidArgumentError(e.message)

    def get_gdb_server_settings(self, args):
        # Set gdb server settings
        return {
            'step_into_interrupt' : args.step_into_interrupt,
            'persist' : args.persist,
            'soft_bkpt_as_hard' : args.soft_bkpt_as_hard,
            'chip_erase': self.get_chip_erase(args),
            'hide_programming_progress' : args.hide_progress,
            'fast_program' : args.fast_program,
            'server_listening_callback' : self.server_listening,
            'enable_semihosting' : args.enable_semihosting,
            'semihost_console_type' : args.semihost_console_type,
            'telnet_port' : args.telnet_port,
            'semihost_use_syscalls' : args.semihost_use_syscalls,
            'serve_local_only' : args.serve_local_only,
            'vector_catch' : self.get_vector_catch(args),
        }


    def setup_logging(self, args):
        format = "%(relativeCreated)07d:%(levelname)s:%(module)s:%(message)s"
        level = LEVELS.get(args.debug_level, logging.NOTSET)
        logging.basicConfig(level=level, format=format)

    ## @brief Handle OpenOCD commands for compatibility.
    def process_commands(self, commands):
        if commands is None:
            return
        for cmd_list in commands:
            try:
                cmd_list = split_command_line(cmd_list)
                cmd = cmd_list[0]
                if cmd == 'gdb_port':
                    if len(cmd_list) < 2:
                        print("Missing port argument")
                    else:
                        self.args.port_number = int(cmd_list[1], base=0)
                elif cmd == 'telnet_port':
                    if len(cmd_list) < 2:
                        print("Missing port argument")
                    else:
                        self.gdb_server_settings['telnet_port'] = int(cmd_list[1], base=0)
                elif cmd == 'echo':
                    self.echo_msg = ' '.join(cmd_list[1:])
                else:
                    print("Unsupported command: %s" % ' '.join(cmd_list))
            except IndexError:
                pass

    def server_listening(self, server):
        if self.echo_msg is not None:
            print(self.echo_msg, file=sys.stderr)
            sys.stderr.flush()

    def disable_logging(self):
        logging.getLogger().setLevel(logging.FATAL)

    def list_boards(self):
        self.disable_logging()

        if not self.args.output_json:
            MbedBoard.listConnectedBoards()
        else:
            try:
                all_mbeds = MbedBoard.getAllConnectedBoards(close=True, blocking=False)
                status = 0
                error = ""
            except Exception as e:
                all_mbeds = []
                status = 1
                error = str(e)
                if not self.args.output_json:
                    raise

            boards = []
            obj = {
                'pyocd_version' : __version__,
                'version' : { 'major' : 1, 'minor' : 0 },
                'status' : status,
                'boards' : boards,
                }

            if status != 0:
                obj['error'] = error

            for mbed in all_mbeds:
                d = {
                    'unique_id' : mbed.unique_id,
                    'info' : mbed.getInfo(),
                    'board_name' : mbed.getBoardName(),
                    'target' : mbed.getTargetType(),
                    'vendor_name' : '',
                    'product_name' : '',
                    }

                # Reopen the link so we can access the USB vendor and product names from the inteface.
                # If it's not a USB based link, then we don't attempt this.
                if isinstance(mbed.link, DAPAccessCMSISDAP):
                    try:
                        mbed.link.open()
                        d['vendor_name'] = mbed.link._interface.vendor_name
                        d['product_name'] = mbed.link._interface.product_name
                        mbed.link.close()
                    except Exception:
                        pass
                boards.append(d)

            print(json.dumps(obj, indent=4))

    def list_targets(self):
        self.disable_logging()

        if self.args.output_json:
            targets = []
            obj = {
                'pyocd_version' : __version__,
                'version' : { 'major' : 1, 'minor' : 0 },
                'status' : 0,
                'targets' : targets
                }

            for name in supported_targets:
                t = target.TARGET[name](None)
                d = {
                    'name' : name,
                    'part_number' : t.part_number,
                    }
                if t._svd_location is not None and isCmsisSvdAvailable:
                    if t._svd_location.is_local:
                        d['svd_path'] = t._svd_location.filename
                    else:
                        resource = "data/{vendor}/{filename}".format(
                            vendor=t._svd_location.vendor,
                            filename=t._svd_location.filename
                        )
                        d['svd_path'] = pkg_resources.resource_filename("cmsis_svd", resource)
                targets.append(d)

            print(json.dumps(obj, indent=4)) #, sys.stdout)
        else:
            for t in supported_targets:
                print(t)

    def run(self, args=None):
        try:
            self.args = self.build_parser().parse_args(args)
            self.gdb_server_settings = self.get_gdb_server_settings(self.args)
            self.setup_logging(self.args)
            DAPAccess.set_args(self.args.daparg)

            self.process_commands(self.args.commands)

            gdb = None
            gdbs = []
            if self.args.list_all == True:
                self.list_boards()
            elif self.args.list_targets == True:
                self.list_targets()
            else:
                try:
                    board_selected = MbedBoard.chooseBoard(
                        board_id=self.args.board_id,
                        target_override=self.args.target_override,
                        frequency=self.args.frequency)
                    if board_selected is None:
                        print("No board selected")
                        return 1
                    with board_selected as board:
                        baseTelnetPort = self.gdb_server_settings['telnet_port']
                        for core_number, core in board.target.cores.items():
                            self.gdb_server_settings['telnet_port'] = baseTelnetPort + core_number
                            gdb = GDBServer(board, self.args.port_number + core_number, self.gdb_server_settings, core=core_number)
                            gdbs.append(gdb)
                        gdb = gdbs[0]
                        while gdb.isAlive():
                            gdb.join(timeout=0.5)
                except KeyboardInterrupt:
                    for gdb in gdbs:
                        gdb.stop()
                except Exception as e:
                    print("uncaught exception: %s" % e)
                    traceback.print_exc()
                    for gdb in gdbs:
                        gdb.stop()
                    return 1

            # Successful exit.
            return 0
        except InvalidArgumentError as e:
            self.parser.error(e)
            return 1

def main():
    sys.exit(GDBServerTool().run())

if __name__ == '__main__':
    main()
