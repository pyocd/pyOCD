#!/usr/bin/env python
# pyOCD debugger
# Copyright (c) 2006-2018 Arm Limited
# Copyright (c) 2020 Cypress Semiconductor Corporation
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

import sys
import os
import logging
import argparse
import json

from .. import __version__
from .. import target
from ..core.session import Session
from ..core.helpers import ConnectHelper
from ..gdbserver import GDBServer
from ..utility.cmdline import (split_command_line, convert_session_options)
from ..probe.pydapaccess import DAPAccess
from ..core.session import Session
from ..coresight.generic_mem_ap import GenericMemAPTarget

LOG = logging.getLogger(__name__)

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

SUPPORTED_TARGETS = list(sorted(target.TARGET.keys()))
DEBUG_LEVELS = list(LEVELS.keys())

class GDBServerTool(object):
    def __init__(self):
        self.args = None
        self.gdb_server_settings = None
        self.echo_msg = None

    def build_parser(self):
        # Build epilog with list of targets.
        epilog = "Available targets for use with --target option: " + ", ".join(SUPPORTED_TARGETS)

        # Keep args in snyc with flash_tool.py when possible
        parser = argparse.ArgumentParser(description='PyOCD GDB Server', epilog=epilog)
        parser.add_argument('--version', action='version', version=__version__)
        parser.add_argument('--config', metavar="PATH", default=None, help="Use a YAML config file.")
        parser.add_argument("--no-config", action="store_true", default=None, help="Do not use a configuration file.")
        parser.add_argument("--pack", metavar="PATH", help="Path to a CMSIS Device Family Pack")
        parser.add_argument("-p", "--port", dest="port_number", type=int, default=3333, help="Set the port number that GDB server will open (default 3333).")
        parser.add_argument("-sc", "--semihost-console", dest="semihost_console_type", default=None, choices=('telnet', 'stdx'), help="Console for semihosting.")
        parser.add_argument("-T", "--telnet-port", dest="telnet_port", type=int, default=4444, help="Specify the telnet port for semihosting (default 4444).")
        parser.add_argument("--allow-remote", dest="serve_local_only", default=True, action="store_false", help="Allow remote TCP/IP connections (default is no).")
        parser.add_argument("-b", "--board", dest="board_id", default=None, help="Connect to board by board ID. Use -l to list all connected boards. Only a unique part of the board ID needs to be provided.")
        parser.add_argument("-l", "--list", action="store_true", dest="list_all", default=False, help="List all connected boards.")
        parser.add_argument("--list-targets", action="store_true", dest="list_targets", default=False, help="List all available targets.")
        parser.add_argument("--json", action="store_true", dest="output_json", default=False, help="Output lists in JSON format. Only applies to --list and --list-targets.")
        parser.add_argument("-d", "--debug", dest="debug_level", choices=DEBUG_LEVELS, default='info', help="Set the level of system logging output. Supported choices are: " + ", ".join(DEBUG_LEVELS), metavar="LEVEL")
        parser.add_argument("-t", "--target", dest="target_override", default=None, help="Override target to debug.", metavar="TARGET")
        parser.add_argument("-n", "--nobreak", dest="no_break_at_hardfault", action="store_true", help="Disable halt at hardfault handler. (Deprecated)")
        parser.add_argument("-r", "--reset-break", dest="break_on_reset", action="store_true", help="Halt the target when reset. (Deprecated)")
        parser.add_argument("-C", "--vector-catch", default='h', help="Enable vector catch sources, one letter per enabled source in any order, or 'all' or 'none'. (h=hard fault, b=bus fault, m=mem fault, i=irq err, s=state err, c=check err, p=nocp, r=reset, a=all, n=none). (Default is hard fault.)")
        parser.add_argument("-s", "--step-int", dest="step_into_interrupt", default=None, action="store_true", help="Allow single stepping to step into interrupts.")
        parser.add_argument("-f", "--frequency", dest="frequency", default=None, type=int, help="Set the SWD clock frequency in Hz.")
        parser.add_argument("-o", "--persist", dest="persist", default=None, action="store_true", help="Keep GDB server running even after remote has detached.")
        parser.add_argument("-bh", "--soft-bkpt-as-hard", dest="soft_bkpt_as_hard", default=False, action="store_true", help="Replace software breakpoints with hardware breakpoints (ignored).")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-ce", "--chip_erase", action="store_true", help="Use chip erase when programming.")
        group.add_argument("-se", "--sector_erase", action="store_true", help="Use sector erase when programming.")
        # -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked
        parser.add_argument("-u", "--unlock", action="store_true", default=False, help="Unlock the device.")
        # reserved: "-a", "--address"
        # reserved: "-s", "--skip"
        parser.add_argument("-hp", "--hide_progress", action="store_true", default=None, help="Don't display programming progress.")
        parser.add_argument("-fp", "--fast_program", action="store_true", default=None, help="Use only the CRC of each page to determine if it already has the same data.")
        parser.add_argument("-S", "--semihosting", dest="enable_semihosting", action="store_true", default=None, help="Enable semihosting.")
        parser.add_argument("-G", "--gdb-syscall", dest="semihost_use_syscalls", action="store_true", default=None, help="Use GDB syscalls for semihosting file I/O.")
        parser.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+', help="Run command (OpenOCD compatibility).")
        parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
        parser.add_argument("--elf", metavar="PATH", help="Optionally specify ELF file being debugged.")
        parser.add_argument("-O", "--option", metavar="OPTION", action="append", help="Set session option of form 'OPTION=VALUE'.")
        parser.add_argument("--no-deprecation-warning", action="store_true", help="Do not warn about pyocd-gdbserver being deprecated.")
        self.parser = parser
        return parser

    def get_chip_erase(self, args):
        # Determine programming mode
        chip_erase = "auto"
        if args.chip_erase:
            chip_erase = "chip"
        elif args.sector_erase:
            chip_erase = "sector"
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

        return vector_catch

    def get_gdb_server_settings(self, args):
        # Set gdb server settings
        return {
            'gdbserver_port' : self.args.port_number,
            'step_into_interrupt' : args.step_into_interrupt,
            'persist' : args.persist,
            'chip_erase': self.get_chip_erase(args),
            'hide_programming_progress' : args.hide_progress,
            'fast_program' : args.fast_program,
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

    def process_commands(self, commands):
        """! @brief Handle OpenOCD commands for compatibility."""
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

    def server_listening(self, note):
        if self.echo_msg is not None:
            print(self.echo_msg, file=sys.stderr)
            sys.stderr.flush()

    def disable_logging(self):
        logging.getLogger().setLevel(logging.FATAL)

    def list_boards(self):
        self.disable_logging()

        if not self.args.output_json:
            ConnectHelper.list_connected_probes()
        else:
            status = 0
            error = ""
            try:
                all_mbeds = ConnectHelper.get_sessions_for_all_connected_probes(blocking=False)
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
                    'unique_id' : mbed.probe.unique_id,
                    'info' : mbed.board.description,
                    'board_name' : mbed.board.name,
                    'target' : mbed.board.target_type,
                    'vendor_name' : mbed.probe.vendor_name,
                    'product_name' : mbed.probe.product_name,
                    }
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

            for name in SUPPORTED_TARGETS:
                s = Session(None) # Create empty session
                t = target.TARGET[name](s)
                d = {
                    'name' : name,
                    'part_number' : t.part_number,
                    }
                if t._svd_location is not None:
                    svdPath = t._svd_location.filename
                    if os.path.exists(svdPath):
                        d['svd_path'] = svdPath
                targets.append(d)

            print(json.dumps(obj, indent=4))
        else:
            for t in SUPPORTED_TARGETS:
                print(t)

    def run(self, args=None):
        self.args = self.build_parser().parse_args(args)
        self.gdb_server_settings = self.get_gdb_server_settings(self.args)
        self.setup_logging(self.args)
        DAPAccess.set_args(self.args.daparg)

        if not self.args.no_deprecation_warning:
            LOG.warning("pyocd-gdbserver is deprecated; please use the new combined pyocd tool.")
    
        self.process_commands(self.args.commands)

        gdb = None
        gdbs = []
        if self.args.list_all == True:
            self.list_boards()
        elif self.args.list_targets == True:
            self.list_targets()
        else:
            try:
                # Build dict of session options.
                sessionOptions = convert_session_options(self.args.option)
                sessionOptions.update(self.gdb_server_settings)
                
                session = ConnectHelper.session_with_chosen_probe(
                    config_file=self.args.config,
                    no_config=self.args.no_config,
                    pack=self.args.pack,
                    unique_id=self.args.board_id,
                    target_override=self.args.target_override,
                    frequency=self.args.frequency,
                    **sessionOptions)
                if session is None:
                    print("No board selected")
                    return 1
                with session:
                    # Set ELF if provided.
                    if self.args.elf:
                        session.board.target.elf = self.args.elf
                    for core_number, core in session.board.target.cores.items():
                        if isinstance(session.board.target.cores[core_number], GenericMemAPTarget):
                            continue
                            
                        gdb = GDBServer(session, core=core_number)
                        # Only subscribe to the server for the first core, so echo messages aren't printed
                        # multiple times.
                        if not gdbs:
                            session.subscribe(self.server_listening, GDBServer.GDBSERVER_START_LISTENING_EVENT, gdb)
                        session.gdbservers[core_number] = gdb
                        gdbs.append(gdb)
                        gdb.start()
                    gdb = gdbs[0]
                    while gdb.is_alive():
                        gdb.join(timeout=0.5)
            except KeyboardInterrupt:
                for gdb in gdbs:
                    gdb.stop()
            except Exception as e:
                LOG.error("uncaught exception: %s" % e, exc_info=Session.get_current().log_tracebacks)
                for gdb in gdbs:
                    gdb.stop()
                return 1

        # Successful exit.
        return 0

def main():
    sys.exit(GDBServerTool().run())

if __name__ == '__main__':
    main()
