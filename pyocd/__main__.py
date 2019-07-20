#!/usr/bin/env python

# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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
import argparse
import json
import colorama
import os
import fnmatch
import re
import prettytable

from . import __version__
from .core.session import Session
from .core.helpers import ConnectHelper
from .core import exceptions
from .target import TARGET
from .target.pack import pack_target
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

try:
    import cmsis_pack_manager
    CPM_AVAILABLE = True
except ImportError:
    CPM_AVAILABLE = False

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
    'pack':         logging.INFO,
    }

## @brief Valid erase mode options.
ERASE_OPTIONS = [
    'auto',
    'chip',
    'sector',
    ]

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
    """! @brief Converts a string to an int with support for base prefixes."""
    return int(x, base=0)

class PyOCDTool(object):
    """! @brief Main class for the pyocd tool and subcommands.
    """
    def __init__(self):
        self._args = None
        self._default_log_level = logging.INFO
        self._log_level_delta = 0
        self._parser = None
        self.echo_msg = None

    def build_parser(self):
        """! @brief Construct the command line parser with all subcommands and options."""
        # Create top level argument parser.
        parser = argparse.ArgumentParser(
            description='PyOCD debug tools for Arm Cortex devices')
        subparsers = parser.add_subparsers(title="subcommands", metavar="", dest='cmd')
        
        parser.add_argument('-V', '--version', action='version', version=__version__)
        parser.add_argument('--help-options', action='store_true',
            help="Display available user options.")
        
        # Define logging related options.
        loggingOptions = argparse.ArgumentParser(description='logging', add_help=False)
        loggingOptions.add_argument('-v', '--verbose', action='count', default=0,
            help="More logging. Can be specified multiple times.")
        loggingOptions.add_argument('-q', '--quiet', action='count', default=0,
            help="Less logging. Can be specified multiple times.")
        
        # Define common options for all subcommands, excluding --verbose and --quiet.
        commonOptionsNoLogging = argparse.ArgumentParser(description='common', add_help=False)
        commonOptionsNoLogging.add_argument('-j', '--dir', metavar="PATH", dest="project_dir",
            help="Set the project directory. Defaults to the directory where pyocd was run.")
        commonOptionsNoLogging.add_argument('--config', metavar="PATH",
            help="Specify YAML configuration file. Default is pyocd.yaml or pyocd.yml.")
        commonOptionsNoLogging.add_argument("--no-config", action="store_true", default=None,
            help="Do not use a configuration file.")
        commonOptionsNoLogging.add_argument('--script', metavar="PATH",
            help="Use the specified user script. Defaults to pyocd_user.py.")
        commonOptionsNoLogging.add_argument('-O', action='append', dest='options', metavar="OPTION=VALUE",
            help="Set named option.")
        commonOptionsNoLogging.add_argument("-da", "--daparg", dest="daparg", nargs='+',
            help="Send setting to DAPAccess layer.")
        commonOptionsNoLogging.add_argument("--pack", metavar="PATH", action="append",
            help="Path to a CMSIS Device Family Pack.")
        
        # Define common options for all subcommands with --verbose and --quiet.
        commonOptions = argparse.ArgumentParser(description='common',
            parents=[loggingOptions, commonOptionsNoLogging], add_help=False)
        
        # Common connection related options.
        connectOptions = argparse.ArgumentParser(description='common', add_help=False)
        connectOptions.add_argument("-u", "--uid", dest="unique_id",
            help="Choose a probe by its unique ID or a substring thereof.")
        connectOptions.add_argument("-b", "--board", dest="board_override", metavar="BOARD",
            help="Set the board type (not yet implemented).")
        connectOptions.add_argument("-t", "--target", dest="target_override", metavar="TARGET",
            help="Set the target type.")
        connectOptions.add_argument("-f", "--frequency", dest="frequency", default=None, type=convert_frequency,
            help="SWD/JTAG clock frequency in Hz, with optional k/K or m/M suffix for kHz or MHz.")
        connectOptions.add_argument("-W", "--no-wait", action="store_true",
            help="Do not wait for a probe to be connected if none are available.")

        # Create *commander* subcommand parser.
        commandOptions = argparse.ArgumentParser(description='command', add_help=False)
        commandOptions.add_argument("-H", "--halt", action="store_true", default=None,
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
        flashParser.add_argument("-e", "--erase", choices=ERASE_OPTIONS, default='sector',
            help="Choose flash erase method. Default is sector.")
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
        gdbserverOptions.add_argument("-e", "--erase", choices=ERASE_OPTIONS, default='sector',
            help="Choose flash erase method. Default is sector.")
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
        listParser.add_argument('-n', '--name',
            help="Restrict listing to items matching the given name. Applies to targets and boards.")
        listParser.add_argument('-r', '--vendor',
            help="Restrict listing to items whose vendor matches the given name. Applies to targets.")
        listParser.add_argument('-s', '--source', choices=('builtin', 'pack'),
            help="Restrict listing to targets from the specified source. Applies to targets.")
        listParser.add_argument('-H', '--no-header', action='store_true',
            help="Don't print a table header.")

        # Create *pack* subcommand parser.
        packParser = subparsers.add_parser('pack', parents=[loggingOptions],
            help="Manage CMSIS-Packs for target support.")
        packParser.add_argument("-c", "--clean", action='store_true',
            help="Erase all stored pack information.")
        packParser.add_argument("-u", "--update", action='store_true',
            help="Update the pack index.")
        packParser.add_argument("-s", "--show", action='store_true',
            help="Show the list of installed packs.")
        packParser.add_argument("-f", "--find", dest="find_devices", metavar="GLOB", action='append',
            help="Look up a device part number in the index using a glob pattern. The pattern is "
                "suffixed with '*'. Can be specified multiple times.")
        packParser.add_argument("-i", "--install", dest="install_devices", metavar="GLOB", action='append',
            help="Download and install pack(s) to support targets matching the glob pattern. "
                "The pattern is suffixed with '*'. Can be specified multiple times.")
        packParser.add_argument("-n", "--no-download", action='store_true',
            help="Just list the pack(s) that would be downloaded, don't actually download anything.")
        packParser.add_argument('-H', '--no-header', action='store_true',
            help="Don't print a table header.")
        
        self._parser = parser
        return parser

    def _setup_logging(self):
        """! @brief Configure the logging module.
        
        The quiet and verbose argument counts are used to set the log verbosity level.
        """
        self._log_level_delta = (self._args.quiet * 10) - (self._args.verbose * 10)
        level = max(1, self._default_log_level + self._log_level_delta)
        logging.basicConfig(level=level, format=LOG_FORMAT)
    
    def _increase_logging(self, loggers):
        """! @brief Increase logging level for a set of subloggers."""
        if self._log_level_delta <= 0:
            level = max(1, self._default_log_level + self._log_level_delta - 10)
            for logger in loggers:
                logging.getLogger(logger).setLevel(level)

    def run(self, args=None):
        """! @brief Main entry point for command line processing."""
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
            self._default_log_level = DEFAULT_CMD_LOG_LEVEL[self._args.cmd]
            self._setup_logging()
            
            # Pass any options to DAPAccess.
            if hasattr(self._args, 'daparg'):
                DAPAccess.set_args(self._args.daparg)

            # Invoke subcommand.
            self._COMMANDS[self._args.cmd](self)

            # Successful exit.
            return 0
        except KeyboardInterrupt:
            return 0
        except (exceptions.Error, ValueError, IndexError) as e:
            LOG.critical(e, exc_info=Session.get_current().log_tracebacks)
            return 1
        except Exception as e:
            LOG.critical("uncaught exception: %s", e, exc_info=Session.get_current().log_tracebacks)
            return 1
    
    def show_options_help(self):
        """! @brief Display help for user options."""
        for infoName in sorted(options.OPTIONS_INFO.keys()):
            info = options.OPTIONS_INFO[infoName]
            if isinstance(info.type, tuple):
                typename = ", ".join(t.__name__ for t in info.type)
            else:
                typename = info.type.__name__
            print((colorama.Fore.BLUE + "{name}"
                + colorama.Style.RESET_ALL + colorama.Fore.GREEN + " ({typename})"
                + colorama.Style.RESET_ALL + " {help}").format(
                name=info.name, typename=typename, help=info.help))
    
    def _get_pretty_table(self, fields):
        """! @brief Returns a PrettyTable object with formatting options set."""
        pt = prettytable.PrettyTable(fields)
        pt.align = 'l'
        pt.header = not self._args.no_header
        pt.border = True
        pt.hrules = prettytable.HEADER
        pt.vrules = prettytable.NONE
        return pt
    
    def do_list(self):
        """! @brief Handle 'list' subcommand."""
        # Default to listing probes.
        if not any((self._args.probes, self._args.targets, self._args.boards)):
            self._args.probes = True
        
        # Create a session with no device so we load any config.
        session = Session(None,
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            **convert_session_options(self._args.options)
                            )
        
        if self._args.probes:
            ConnectHelper.list_connected_probes()
        elif self._args.targets:
            # Create targets from provided CMSIS pack.
            if session.options['pack'] is not None:
                pack_target.PackTargets.populate_targets_from_pack(session.options['pack'])

            obj = ListGenerator.list_targets(name_filter=self._args.name,
                                            vendor_filter=self._args.vendor,
                                            source_filter=self._args.source)
            pt = self._get_pretty_table(["Name", "Vendor", "Part Number", "Families", "Source"])
            for info in sorted(obj['targets'], key=lambda i: i['name']):
                pt.add_row([
                            info['name'],
                            info['vendor'],
                            info['part_number'],
                            ', '.join(info['part_families']),
                            info['source'],
                            ])
            print(pt)
        elif self._args.boards:
            obj = ListGenerator.list_boards(name_filter=self._args.name)
            pt = self._get_pretty_table(["ID", "Name", "Target", "Test Binary"])
            for info in sorted(obj['boards'], key=lambda i: i['id']):
                pt.add_row([
                            info['id'],
                            info['name'],
                            info['target'],
                            info['binary']
                            ])
            print(pt)
    
    def do_json(self):
        """! @brief Handle 'json' subcommand."""
        # Default to listing probes.
        if not any((self._args.probes, self._args.targets, self._args.boards)):
            self._args.probes = True
        
        # Create a session with no device so we load any config.
        session = Session(None,
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            **convert_session_options(self._args.options)
                            )
        
        if self._args.targets or self._args.boards:
            # Create targets from provided CMSIS pack.
            if session.options['pack'] is not None:
                pack_target.PackTargets.populate_targets_from_pack(session.options['pack'])

        if self._args.probes:
            obj = ListGenerator.list_probes()
        elif self._args.targets:
            obj = ListGenerator.list_targets()
        elif self._args.boards:
            obj = ListGenerator.list_boards()
        else:
            assert False
        print(json.dumps(obj, indent=4))
    
    def do_flash(self):
        """! @brief Handle 'flash' subcommand."""
        self._increase_logging(["pyocd.flash.loader"])
        
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=False,
                            options=convert_session_options(self._args.options))
        if session is None:
            sys.exit(1)
        with session:
            programmer = loader.FileProgrammer(session,
                                                chip_erase=self._args.erase,
                                                trust_crc=self._args.trust_crc)
            programmer.program(self._args.file,
                                base_address=self._args.base_address,
                                skip=self._args.skip,
                                file_format=self._args.format)
    
    def do_erase(self):
        """! @brief Handle 'erase' subcommand."""
        self._increase_logging(["pyocd.flash.loader"])
        
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=False,
                            options=convert_session_options(self._args.options))
        if session is None:
            sys.exit(1)
        with session:
            mode = self._args.erase_mode or loader.FlashEraser.Mode.SECTOR
            eraser = loader.FlashEraser(session, mode)
            
            addresses = flatten_args(self._args.addresses)
            eraser.erase(addresses)

    def _process_commands(self, commands):
        """! @brief Handle OpenOCD commands for compatibility."""
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
        """! @brief Callback invoked when the gdbserver starts listening on its port."""
        if self.echo_msg is not None:
            print(self.echo_msg, file=sys.stderr)
            sys.stderr.flush()
    
    def do_gdbserver(self):
        """! @brief Handle 'gdbserver' subcommand."""
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
                'chip_erase': self._args.erase,
                'fast_program' : self._args.trust_crc,
                'enable_semihosting' : self._args.enable_semihosting,
                'serve_local_only' : self._args.serve_local_only,
                'vector_catch' : self._args.vector_catch,
                })
            
            session = ConnectHelper.session_with_chosen_probe(
                blocking=(not self._args.no_wait),
                project_dir=self._args.project_dir,
                user_script=self._args.script,
                config_file=self._args.config,
                no_config=self._args.no_config,
                pack=self._args.pack,
                unique_id=self._args.unique_id,
                target_override=self._args.target_override,
                frequency=self._args.frequency,
                options=sessionOptions)
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
        except (KeyboardInterrupt, Exception):
            for gdb in gdbs:
                gdb.stop()
            raise
    
    def do_commander(self):
        """! @brief Handle 'commander' subcommand."""
        # Flatten commands list then extract primary command and its arguments.
        if self._args.commands is not None:
            cmds = []
            for cmd in self._args.commands:
                cmds.append(flatten_args(split_command_line(arg) for arg in cmd))
        else:
            cmds = None

        # Enter REPL.
        PyOCDCommander(self._args, cmds).run()
    
    def do_pack(self):
        """! @brief Handle 'pack' subcommand."""
        if not CPM_AVAILABLE:
            LOG.error("'pack' command is not available because cmsis-pack-manager is not installed")
            return
        
        verbosity = self._args.verbose - self._args.quiet
        cache = cmsis_pack_manager.Cache(verbosity < 0, False)
        
        if self._args.clean:
            LOG.info("Removing all pack data...")
            cache.cache_clean()
        
        if self._args.update:
            LOG.info("Updating pack index...")
            cache.cache_descriptors()
        
        if self._args.show:
            packs = pack_target.ManagedPacks.get_installed_packs()
            pt = self._get_pretty_table(["Vendor", "Pack", "Version"])
            for ref in packs:
                pt.add_row([
                            ref.vendor,
                            ref.pack,
                            ref.version,
                            ])
            print(pt)

        if self._args.find_devices or self._args.install_devices:
            if not cache.index:
                LOG.info("No pack index present, downloading now...")
                cache.cache_descriptors()
            
            patterns = self._args.find_devices or self._args.install_devices
            
            # Find matching part numbers.
            matches = set()
            for pattern in patterns:
                # Using fnmatch.fnmatch() was failing to match correctly.
                pat = re.compile(fnmatch.translate(pattern + "*"), re.IGNORECASE)
                results = {name for name in cache.index.keys() if pat.match(name)}
                matches.update(results)
            
            if not matches:
                LOG.warning("No matching devices. Please make sure the pack index is up to date.")
                return
            
            if self._args.find_devices:
                pt = self._get_pretty_table(["Part", "Vendor", "Pack", "Version"])
                for name in sorted(matches):
                    info = cache.index[name]
                    ref, = cache.packs_for_devices([info])
                    pt.add_row([
                                info['name'],
                                ref.vendor,
                                ref.pack,
                                ref.version,
                                ])
                print(pt)
            elif self._args.install_devices:
                devices = [cache.index[dev] for dev in matches]
                packs = cache.packs_for_devices(devices)
                if not self._args.no_download:
                    print("Downloading packs (press Control-C to cancel):")
                else:
                    print("Would download packs:")
                for pack in packs:
                    print("    " + str(pack))
                if not self._args.no_download:
                    cache.download_pack_list(packs)

    ## @brief Table of handler methods for subcommands.
    _COMMANDS = {
        'list':         do_list,
        'json':         do_json,
        'flash':        do_flash,
        'erase':        do_erase,
        'gdbserver':    do_gdbserver,
        'gdb':          do_gdbserver,
        'commander':    do_commander,
        'cmd':          do_commander,
        'pack':         do_pack,
        }

def main():
    sys.exit(PyOCDTool().run())

if __name__ == '__main__':
    main()
