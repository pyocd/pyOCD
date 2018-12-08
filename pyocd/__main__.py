#!/usr/bin/env python

# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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
import sys
import logging
import traceback
import argparse
import json
import colorama

from . import __version__
from .core.helpers import ConnectHelper
from .target import TARGET
from .gdbserver import GDBServer
from .utility.cmdline import (
    split_command_line,
    VECTOR_CATCH_CHAR_MAP,
    convert_vector_catch,
    convert_session_options
    )
from .probe.pydapaccess import DAPAccess
from .tools.lists import ListGenerator
from .tools.pyocd import PyOCDCommander
from .flash import loader
from .core import options
from .utility.cmdline import split_command_line

## @brief List of built-in targets, sorted by name.
SUPPORTED_TARGETS = sorted(list(TARGET.keys()))

## @brief Default log format for all subcommands.
LOG_FORMAT = "%(relativeCreated)07d:%(levelname)s:%(module)s:%(message)s"

## @brief Logger for this module.
LOG = logging.getLogger("pyocd.tool")

## @brief Default log levels for each of the subcommands.
DEFAULT_CMD_LOG_LEVEL = {
    'list':         logging.INFO,
    'json':         logging.FATAL + 1,
    'flash':        logging.WARNING,
    'erase':        logging.WARNING,
    'gdbserver':    logging.INFO,
    'gdb':          logging.INFO,
    'commander':    logging.WARNING,
    'cmd':          logging.WARNING,
    }

## @brief map to convert erase mode to chip_erase option for gdbserver.
ERASE_OPTIONS = {
    'auto': None,
    'chip': True,
    'sector': False,
    }

class InvalidArgumentError(RuntimeError):
    """! @brief Exception class raised for invalid target names."""
    pass

def validate_target(value):
    """! @brief Argparse type function to validate the supplied target device name.
    
    If the target name is valid, it is returned unmodified to become the --target option's
    attribute value.
    """
    if value.lower() not in TARGET:
        raise InvalidArgumentError("invalid target option '{}'".format(value))
    return value

def convert_frequency(value):
    """! @brief Applies scale suffix to frequency value string."""
    value = value.strip()
    suffix = value[-1].lower()
    if suffix in ('k', 'm'):
        value = int(value[:-1])
        if suffix == 'k':
            value *= 1000
        elif suffix == 'm':
            value *= 1000000
        return value
    else:
        return int(value)

def flatten_args(args):
    """! @brief Converts a list of lists to a single list."""
    return [item for sublist in args for item in sublist]

def int_base_0(x):
    return int(x, base=0)

class PyOCDTool(object):
    """! @brief Main class for the pyocd tool and subcommands.
    """
    def __init__(self):
        self._args = None
        self._log_level_delta = 0
        self._parser = None
        self.echo_msg = None
        
        self._commands = {
            'list':         self.do_list,
            'json':         self.do_json,
            'flash':        self.do_flash,
            'erase':        self.do_erase,
            'gdbserver':    self.do_gdbserver,
            'gdb':          self.do_gdbserver,
            'commander':    self.do_commander,
            'cmd':          self.do_commander,
            }

    def build_parser(self):
        # Create top level argument parser.
        parser = argparse.ArgumentParser(
            description='PyOCD debug tools for Arm Cortex devices')
        subparsers = parser.add_subparsers(title="subcommands", metavar="", dest='cmd')
        
        parser.add_argument('-V', '--version', action='version', version=__version__)
        parser.add_argument('--help-options', action='store_true',
            help="Display available session options.")
        
        # Define common options for all subcommands, excluding --verbose and --quiet.
        commonOptionsNoLogging = argparse.ArgumentParser(description='common', add_help=False)
        commonOptionsNoLogging.add_argument('--config', metavar="PATH",
            help="Specify YAML configuration file. Default is pyocd.yaml or pyocd.yml.")
        commonOptionsNoLogging.add_argument("--no-config", action="store_true",
            help="Do not use a configuration file.")
        commonOptionsNoLogging.add_argument('-O', action='append', dest='options', metavar="OPTION=VALUE",
            help="Set named option.")
        commonOptionsNoLogging.add_argument("-da", "--daparg", dest="daparg", nargs='+',
            help="Send setting to DAPAccess layer.")
        
        # Define common options for all subcommands with --verbose and --quiet.
        commonOptions = argparse.ArgumentParser(description='common', parents=[commonOptionsNoLogging], add_help=False)
        commonOptions.add_argument('-v', '--verbose', action='count', default=0,
            help="More logging. Can be specified multiple times.")
        commonOptions.add_argument('-q', '--quiet', action='count', default=0,
            help="Less logging. Can be specified multiple times.")
        
        # Common connection related options.
        connectOptions = argparse.ArgumentParser(description='common', add_help=False)
        connectOptions.add_argument("-u", "--uid", dest="unique_id",
            help="Choose a probe by its unique ID or a substring thereof.")
        connectOptions.add_argument("-b", "--board", dest="board_override", metavar="BOARD",
            help="Set the board type (not yet implemented).")
        connectOptions.add_argument("-t", "--target", dest="target_override", metavar="TARGET", type=validate_target,
            help="Set the target type.")
        connectOptions.add_argument("-f", "--frequency", dest="frequency", default=1000000, type=convert_frequency,
            help="SWD/JTAG clock frequency in Hz, with optional k/K or m/M suffix for kHz or MHz.")
        connectOptions.add_argument("-W", "--no-wait", action="store_true",
            help="Do not wait for a probe to be connected if none are available.")

        # Create *commander* subcommand parser.
        commandOptions = argparse.ArgumentParser(description='command', add_help=False)
        commandOptions.add_argument("-H", "--halt", action="store_true",
            help="Halt core upon connect.")
        commandOptions.add_argument("-N", "--no-init", action="store_true",
            help="Do not init debug system.")
        commandOptions.add_argument("--elf", metavar="PATH",
            help="Optionally specify ELF file being debugged.")
        commandOptions.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+',
            help="Run commands.")
        subparsers.add_parser('commander', parents=[commonOptions, connectOptions, commandOptions],
            help="Interactive command console.")
        subparsers.add_parser('cmd', parents=[commonOptions, connectOptions, commandOptions],
            help="Alias for 'commander'.")

        # Create *erase* subcommand parser.
        eraseParser = subparsers.add_parser('erase', parents=[commonOptions, connectOptions],
            help="Erase entire device flash or specified sectors.",
            epilog="If no position arguments are listed, then no action will be taken unless the --chip or "
            "--mass-erase options are provided. Otherwise, the positional arguments should be the addresses of flash "
            "sectors or address ranges. The end address of a range is exclusive, meaning that it will not be "
            "erased. Thus, you should specify the address of the sector after the last one "
            "to be erased. If a '+' is used instead of '-' in a range, this indicates that the "
            "second value is a length rather than end address. "
            "Examples: 0x1000 (erase single sector starting at 0x1000) "
            "0x800-0x2000 (erase sectors starting at 0x800 up to but not including 0x2000) "
            "0+8192 (erase 8 kB starting at address 0)")
        eraseParser.add_argument("-c", "--chip", dest="erase_mode", action="store_const", const=loader.FlashEraser.Mode.CHIP,
            help="Perform a chip erase.")
        eraseParser.add_argument("-s", "--sector", dest="erase_mode", action="store_const", const=loader.FlashEraser.Mode.SECTOR,
            help="Erase the sectors listed as positional arguments.")
        eraseParser.add_argument("--mass-erase", dest="erase_mode", action="store_const", const=loader.FlashEraser.Mode.MASS,
            help="Perform a mass erase. On some devices this is different than a chip erase.")
        eraseParser.add_argument("addresses", metavar="<sector-address>", action='append', nargs='*',
            help="List of sector addresses or ranges to erase.")

        # Create *flash* subcommand parser.
        flashParser = subparsers.add_parser('flash', parents=[commonOptions, connectOptions],
            help="Program an image to device flash.")
        flashParser.add_argument("-e", "--erase", choices=ERASE_OPTIONS.keys(), default='auto',
            help="Choose flash erase method. Default is auto.")
        flashParser.add_argument("-a", "--base-address", metavar="ADDR", type=int_base_0,
            help="Base address used for the address where to flash a binary. Defaults to start of flash.")
        flashParser.add_argument("--trust-crc", action="store_true",
            help="Use only the CRC of each page to determine if it already has the same data.")
        flashParser.add_argument("--format", choices=("bin", "hex", "elf"),
            help="File format. Default is to use the file's extension.")
        flashParser.add_argument("--skip", metavar="BYTES", default=0, type=int_base_0,
            help="Skip programming the first N bytes. This can only be used with binary files.")
        flashParser.add_argument("file", metavar="PATH",
            help="File to program into flash.")
        
        # Create *gdbserver* subcommand parser.
        gdbserverOptions = argparse.ArgumentParser(description='gdbserver', add_help=False)
        gdbserverOptions.add_argument("-p", "--port", dest="port_number", type=int, default=3333,
            help="Set the port number that GDB server will open (default 3333).")
        gdbserverOptions.add_argument("-T", "--telnet-port", dest="telnet_port", type=int, default=4444,
            help="Specify the telnet port for semihosting (default 4444).")
        gdbserverOptions.add_argument("--allow-remote", dest="serve_local_only", default=True, action="store_false",
            help="Allow remote TCP/IP connections (default is no).")
        gdbserverOptions.add_argument("--persist", dest="persist", default=False, action="store_true",
            help="Keep GDB server running even after remote has detached.")
        gdbserverOptions.add_argument("--elf", metavar="PATH",
            help="Optionally specify ELF file being debugged.")
        gdbserverOptions.add_argument("-e", "--erase", choices=('auto', 'chip', 'sector'), default='auto',
            help="Choose flash erase method. Default is auto.")
        gdbserverOptions.add_argument("--trust-crc", action="store_true",
            help="Use only the CRC of each page to determine if it already has the same data.")
        gdbserverOptions.add_argument("-C", "--vector-catch", default='h',
            help="Enable vector catch sources, one letter per enabled source in any order, or 'all' "
                "or 'none'. (h=hard fault, b=bus fault, m=mem fault, i=irq err, s=state err, "
                "c=check err, p=nocp, r=reset, a=all, n=none). Default is hard fault.")
        gdbserverOptions.add_argument("-S", "--semihosting", dest="enable_semihosting", action="store_true",
            help="Enable semihosting.")
        gdbserverOptions.add_argument("--step-into-interrupts", dest="step_into_interrupt", default=False, action="store_true",
            help="Allow single stepping to step into interrupts.")
        gdbserverOptions.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+',
            help="Run command (OpenOCD compatibility).")
        subparsers.add_parser('gdbserver', parents=[commonOptions, connectOptions, gdbserverOptions],
            help="Run the gdb remote server(s).")
        subparsers.add_parser('gdb', parents=[commonOptions, connectOptions, gdbserverOptions],
            help="Alias for 'gdbserver'.")

        # Create *json* subcommand parser.
        #
        # The json subcommand does not support --verbose or --quiet since all logging is disabled.
        jsonParser = subparsers.add_parser('json', parents=[commonOptionsNoLogging],
            help="Output information as JSON.")
        group = jsonParser.add_mutually_exclusive_group()
        group.add_argument('-p', '--probes', action='store_true',
            help="List available probes.")
        group.add_argument('-t', '--targets', action='store_true',
            help="List all known targets.")
        group.add_argument('-b', '--boards', action='store_true',
            help="List all known boards.")
        jsonParser.set_defaults(verbose=0, quiet=0)

        # Create *list* subcommand parser.
        listParser = subparsers.add_parser('list', parents=[commonOptions],
            help="List information about probes, targets, or boards.")
        group = listParser.add_mutually_exclusive_group()
        group.add_argument('-p', '--probes', action='store_true',
            help="List available probes.")
        group.add_argument('-t', '--targets', action='store_true',
            help="List all known targets.")
        group.add_argument('-b', '--boards', action='store_true',
            help="List all known boards.")
        
        self._parser = parser
        return parser

    def _setup_logging(self, defaultLogLevel):
        self._log_level_delta = (self._args.quiet * 10) - (self._args.verbose * 10)
        level = max(1, defaultLogLevel + self._log_level_delta)
        logging.basicConfig(level=level, format=LOG_FORMAT)
    
    def _increase_logging(self, loggers):
        if self._log_level_delta <= 0:
            for logger in loggers:
                logging.getLogger(logger).setLevel(logging.INFO)

    def run(self, args=None):
        try:
            self._args = self.build_parser().parse_args(args)
            
            # Running without a subcommand will print usage.
            if self._args.cmd is None:
                if self._args.help_options:
                    self.show_options_help()
                else:
                    self._parser.print_help()
                return 1
            
            # The default log level differs for some subcommands.
            defaultLogLevel = DEFAULT_CMD_LOG_LEVEL[self._args.cmd]
            self._setup_logging(defaultLogLevel)
            
            # Pass any options to DAPAccess.
            DAPAccess.set_args(self._args.daparg)

            # Invoke subcommand.
            self._commands[self._args.cmd]()

            # Successful exit.
            return 0
        except InvalidArgumentError as e:
            self._parser.error(e)
            return 1
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            LOG.error("uncaught exception: %s", e, exc_info=True)
            return 1
    
    def show_options_help(self):
        for infoName in sorted(options.OPTIONS_INFO.keys()):
            info = options.OPTIONS_INFO[infoName]
            print((colorama.Fore.BLUE + "{name}"
                + colorama.Style.RESET_ALL + colorama.Fore.GREEN + " ({typename})"
                + colorama.Style.RESET_ALL + " {help}").format(
                name=info.name, typename=info.type.__name__, help=info.help))
    
    def do_list(self):
        # Default to listing probes.
        if (self._args.probes, self._args.targets, self._args.boards) == (False, False, False):
            self._args.probes = True
        
        if self._args.probes:
            ConnectHelper.list_connected_probes()
        elif self._args.targets:
            obj = ListGenerator.list_targets()
            for info in obj['targets']:
                print("{name}\t{part_number}".format(**info))
        elif self._args.boards:
            obj = ListGenerator.list_boards()
            for info in obj['boards']:
                print("{id}\t{name}\t{target}\t{binary}".format(**info))
    
    def do_json(self):
        # Default to listing probes.
        if (self._args.probes, self._args.targets, self._args.boards) == (False, False, False):
            self._args.probes = True
        
        if self._args.probes:
            obj = ListGenerator.list_probes()
            print(json.dumps(obj, indent=4))
        elif self._args.targets:
            obj = ListGenerator.list_targets()
            print(json.dumps(obj, indent=4))
        elif self._args.boards:
            obj = ListGenerator.list_boards()
            print(json.dumps(obj, indent=4))
    
    def do_flash(self):
        self._increase_logging(["pyocd.tools.loader", "pyocd", "flash", "flash_builder"])
        
        session = ConnectHelper.session_with_chosen_probe(
                            config_file=self._args.config,
                            no_config=self._args.no_config,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=False,
                            **convert_session_options(self._args.options))
        if session is None:
            sys.exit(1)
        with session:
            programmer = loader.FileProgrammer(session,
                                                chip_erase=ERASE_OPTIONS[self._args.erase],
                                                trust_crc=self._args.trust_crc)
            programmer.program(self._args.file,
                                base_address=self._args.base_address,
                                skip=self._args.skip,
                                format=self._args.format)
    
    def do_erase(self):
        self._increase_logging(["pyocd.tools.loader", "pyocd"])
        
        session = ConnectHelper.session_with_chosen_probe(
                            config_file=self._args.config,
                            no_config=self._args.no_config,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=False,
                            **convert_session_options(self._args.options))
        if session is None:
            sys.exit(1)
        with session:
            mode = self._args.erase_mode or loader.FlashEraser.Mode.SECTOR
            eraser = loader.FlashEraser(session, mode)
            
            addresses = flatten_args(self._args.addresses)
            eraser.erase(addresses)

    ## @brief Handle OpenOCD commands for compatibility.
    def _process_commands(self, commands):
        if commands is None:
            return
        for cmd_list in commands:
            try:
                cmd_list = split_command_line(cmd_list)
                cmd = cmd_list[0]
                if cmd == 'gdb_port':
                    if len(cmd_list) < 2:
                        LOG.error("Missing port argument")
                    else:
                        self._args.port_number = int(cmd_list[1], base=0)
                elif cmd == 'telnet_port':
                    if len(cmd_list) < 2:
                        LOG.error("Missing port argument")
                    else:
                        self._args.telnet_port = int(cmd_list[1], base=0)
                elif cmd == 'echo':
                    self.echo_msg = ' '.join(cmd_list[1:])
                else:
                    LOG.error("Unsupported command: %s" % ' '.join(cmd_list))
            except IndexError:
                pass

    def server_listening(self, server):
        if self.echo_msg is not None:
            print(self.echo_msg, file=sys.stderr)
            sys.stderr.flush()
    
    def do_gdbserver(self):
        self._process_commands(self._args.commands)

        gdbs = []
        try:
            # Build dict of session options.
            sessionOptions = convert_session_options(self._args.options)
            sessionOptions.update({
                'gdbserver_port' : self._args.port_number,
                'telnet_port' : self._args.telnet_port,
                'persist' : self._args.persist,
                'step_into_interrupt' : self._args.step_into_interrupt,
                'chip_erase': ERASE_OPTIONS[self._args.erase],
                'fast_program' : self._args.trust_crc,
                'enable_semihosting' : self._args.enable_semihosting,
                'serve_local_only' : self._args.serve_local_only,
                'vector_catch' : self._args.vector_catch,
                })
            
            session = ConnectHelper.session_with_chosen_probe(
                blocking=(not self._args.no_wait),
                config_file=self._args.config,
                no_config=self._args.no_config,
                unique_id=self._args.unique_id,
                target_override=self._args.target_override,
                frequency=self._args.frequency,
                **sessionOptions)
            if session is None:
                LOG.error("No probe selected.")
                return
            with session:
                # Set ELF if provided.
                if self._args.elf:
                    session.board.target.elf = self._args.elf
                for core_number, core in session.board.target.cores.items():
                    gdb = GDBServer(session,
                        core=core_number,
                        server_listening_callback=self.server_listening)
                    gdbs.append(gdb)
                gdb = gdbs[0]
                while gdb.isAlive():
                    gdb.join(timeout=0.5)
        except Exception as e:
            for gdb in gdbs:
                gdb.stop()
            raise
    
    def do_commander(self):
        # Flatten commands list then extract primary command and its arguments.
        if self._args.commands is not None:
            cmds = []
            for cmd in self._args.commands:
                cmds.append(flatten_args(split_command_line(arg) for arg in cmd))
        else:
            cmds = None

        # Enter REPL.
        PyOCDCommander(self._args, cmds).run()

def main():
    sys.exit(PyOCDTool().run())

if __name__ == '__main__':
    main()
