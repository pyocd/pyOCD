#!/usr/bin/env python

# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
# Copyright (c) 2020 Cypress Semiconductor Corporation
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
from time import sleep

from . import __version__
from .core.session import Session
from .core.helpers import ConnectHelper
from .core.target import Target
from .core import exceptions
from .target import TARGET
from .target.pack import pack_target
from .gdbserver import GDBServer
from .utility.cmdline import (
    split_command_line,
    VECTOR_CATCH_CHAR_MAP,
    convert_vector_catch,
    convert_session_options,
    convert_reset_type,
    convert_frequency,
    )
from .probe.pydapaccess import DAPAccess
from .probe.tcp_probe_server import DebugProbeServer
from .probe.shared_probe_proxy import SharedDebugProbeProxy
from .tools.lists import ListGenerator
from .commands.commander import PyOCDCommander
from .flash.eraser import FlashEraser
from .flash.file_programmer import FileProgrammer
from .core import options
from .coresight.generic_mem_ap import GenericMemAPTarget

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
    'reset':        logging.WARNING,
    'erase':        logging.WARNING,
    'gdbserver':    logging.INFO,
    'gdb':          logging.INFO,
    'commander':    logging.WARNING,
    'cmd':          logging.WARNING,
    'pack':         logging.INFO,
    'server':       logging.INFO,
    }

## @brief Valid erase mode options.
ERASE_OPTIONS = [
    'auto',
    'chip',
    'sector',
    ]

## @brief Map to convert plugin groups to user friendly names.
PLUGIN_GROUP_NAMES = {
    'pyocd.probe': "Debug Probe",
    'pyocd.rtos': "RTOS",
    }

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
            help="Display available session options.")
        
        # Define logging related options.
        loggingOptions = argparse.ArgumentParser(description='logging', add_help=False)
        loggingOptions.add_argument('-v', '--verbose', action='count', default=0,
            help="More logging. Can be specified multiple times.")
        loggingOptions.add_argument('-q', '--quiet', action='count', default=0,
            help="Less logging. Can be specified multiple times.")
        
        # Define common options for all subcommands, excluding --verbose and --quiet.
        commonOptionsNoLoggingParser = argparse.ArgumentParser(description='common', add_help=False)
        commonOptionsNoLogging = commonOptionsNoLoggingParser.add_argument_group("configuration")
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
            parents=[loggingOptions, commonOptionsNoLoggingParser], add_help=False)
        
        # Common connection related options.
        connectParser = argparse.ArgumentParser(description='common', add_help=False)
        connectOptions = connectParser.add_argument_group("connection")
        connectOptions.add_argument("-u", "--uid", "--probe", dest="unique_id",
            help="Choose a probe by its unique ID or a substring thereof. Optionally prefixed with "
            "'<probe-type>:' where <probe-type> is the name of a probe plugin.")
        connectOptions.add_argument("-b", "--board", dest="board_override", metavar="BOARD",
            help="Set the board type (not yet implemented).")
        connectOptions.add_argument("-t", "--target", dest="target_override", metavar="TARGET",
            help="Set the target type.")
        connectOptions.add_argument("-f", "--frequency", dest="frequency", default=None, type=convert_frequency,
            help="SWD/JTAG clock frequency in Hz. Accepts a float or int with optional case-"
                "insensitive K/M suffix and optional Hz. Examples: \"1000\", \"2.5khz\", \"10m\".")
        connectOptions.add_argument("-W", "--no-wait", action="store_true",
            help="Do not wait for a probe to be connected if none are available.")
        connectOptions.add_argument("-M", "--connect", dest="connect_mode", metavar="MODE",
            help="Select connect mode from one of (halt, pre-reset, under-reset, attach).")

        # Create *commander* subcommand parser.
        commanderParser = argparse.ArgumentParser(description='commander', add_help=False)
        commanderOptions = commanderParser.add_argument_group("commander options")
        commanderOptions.add_argument("-H", "--halt", action="store_true", default=None,
            help="Halt core upon connect. (Deprecated, see --connect.)")
        commanderOptions.add_argument("-N", "--no-init", action="store_true",
            help="Do not init debug system.")
        commanderOptions.add_argument("--elf", metavar="PATH",
            help="Optionally specify ELF file being debugged.")
        commanderOptions.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+',
            help="Run commands.")
        subparsers.add_parser('commander', parents=[commonOptions, connectParser, commanderParser],
            help="Interactive command console.")
        subparsers.add_parser('cmd', parents=[commonOptions, connectParser, commanderParser],
            help="Alias for 'commander'.")

        # Create *erase* subcommand parser.
        eraseParser = argparse.ArgumentParser(description='erase', add_help=False)
        eraseOptions = eraseParser.add_argument_group("erase options")
        eraseOptions.add_argument("-c", "--chip", dest="erase_mode", action="store_const", const=FlashEraser.Mode.CHIP,
            help="Perform a chip erase.")
        eraseOptions.add_argument("-s", "--sector", dest="erase_mode", action="store_const", const=FlashEraser.Mode.SECTOR,
            help="Erase the sectors listed as positional arguments.")
        eraseOptions.add_argument("--mass", dest="erase_mode", action="store_const", const=FlashEraser.Mode.MASS,
            help="Perform a mass erase. On some devices this is different than a chip erase.")
        eraseOptions.add_argument("addresses", metavar="<sector-address>", action='append', nargs='*',
            help="List of sector addresses or ranges to erase.")
        subparsers.add_parser('erase', parents=[commonOptions, connectParser, eraseParser],
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

        # Create *flash* subcommand parser.
        flashParser = argparse.ArgumentParser(description='flash', add_help=False)
        flashOptions = flashParser.add_argument_group("flash options")
        flashOptions.add_argument("-e", "--erase", choices=ERASE_OPTIONS, default='sector',
            help="Choose flash erase method. Default is sector.")
        flashOptions.add_argument("-a", "--base-address", metavar="ADDR", type=int_base_0,
            help="Base address used for the address where to flash a binary. Defaults to start of flash.")
        flashOptions.add_argument("--trust-crc", action="store_true",
            help="Use only the CRC of each page to determine if it already has the same data.")
        flashOptions.add_argument("--format", choices=("bin", "hex", "elf"),
            help="File format. Default is to use the file's extension.")
        flashOptions.add_argument("--skip", metavar="BYTES", default=0, type=int_base_0,
            help="Skip programming the first N bytes. This can only be used with binary files.")
        flashOptions.add_argument("file", metavar="PATH",
            help="File to program into flash.")
        subparsers.add_parser('flash', parents=[commonOptions, connectParser, flashParser],
            help="Program an image to device flash.")

        # Create *reset* subcommand parser.
        resetParser = argparse.ArgumentParser(description='reset', add_help=False)
        resetOptions = resetParser.add_argument_group("reset options")
        resetOptions.add_argument("-m", "--method", default='hw', dest='reset_type', metavar="METHOD",
            help="Reset method to use ('hw', 'sw', and others). Default is 'hw'.")
        subparsers.add_parser('reset', parents=[commonOptions, connectParser, resetParser],
            help="Reset a device.")
        
        # Create *gdbserver* subcommand parser.
        gdbserverParser = argparse.ArgumentParser(description='gdbserver', add_help=False)
        gdbserverOptions = gdbserverParser.add_argument_group("gdbserver options")
        gdbserverOptions.add_argument("-p", "--port", metavar="PORT", dest="port_number", type=int,
            default=3333,
            help="Set starting port number for the GDB server (default 3333). Additional cores "
                "will have a port number of this parameter plus the core number.")
        gdbserverOptions.add_argument("-T", "--telnet-port", metavar="PORT", dest="telnet_port",
            type=int, default=4444,
            help="Specify starting telnet port for semihosting (default 4444).")
        gdbserverOptions.add_argument("-R", "--probe-server-port",
            dest="probe_server_port", metavar="PORT", type=int, default=5555,
            help="Specify the telnet port for semihosting (default 4444).")
        gdbserverOptions.add_argument("--allow-remote", dest="serve_local_only", default=True, action="store_false",
            help="Allow remote TCP/IP connections (default is no).")
        gdbserverOptions.add_argument("--persist", action="store_true",
            help="Keep GDB server running even after remote has detached.")
        gdbserverOptions.add_argument("-r", "--probe-server", action="store_true", dest="enable_probe_server",
            help="Enable the probe server in addition to the GDB server.")
        gdbserverOptions.add_argument("--core", metavar="CORE_LIST",
            help="Comma-separated list of cores for which gdbservers will be created. Default is all cores.")
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
        subparsers.add_parser('gdbserver', parents=[commonOptions, connectParser, gdbserverParser],
            help="Run the gdb remote server(s).")
        subparsers.add_parser('gdb', parents=[commonOptions, connectParser, gdbserverParser],
            help="Alias for 'gdbserver'.")

        # Create *json* subcommand parser.
        #
        # The json subcommand does not support --verbose or --quiet since all logging is disabled.
        jsonParser = argparse.ArgumentParser(description='json', add_help=False)
        jsonOptions = jsonParser.add_argument_group('json output')
        jsonOptions.add_argument('-p', '--probes', action='store_true',
            help="List available probes.")
        jsonOptions.add_argument('-t', '--targets', action='store_true',
            help="List all known targets.")
        jsonOptions.add_argument('-b', '--boards', action='store_true',
            help="List all known boards.")
        jsonOptions.add_argument('-f', '--features', action='store_true',
            help="List available features and options.")
        jsonSubparser = subparsers.add_parser('json', parents=[commonOptionsNoLoggingParser, jsonParser],
            help="Output information as JSON.")
        jsonSubparser.set_defaults(verbose=0, quiet=0)

        # Create *list* subcommand parser.
        listParser = argparse.ArgumentParser(description='list', add_help=False)
        listOutput = listParser.add_argument_group("list output")
        listOutput.add_argument('-p', '--probes', action='store_true',
            help="List available probes.")
        listOutput.add_argument('-t', '--targets', action='store_true',
            help="List all known targets.")
        listOutput.add_argument('-b', '--boards', action='store_true',
            help="List all known boards.")
        listOutput.add_argument('--plugins', action='store_true',
            help="List available plugins.")
        listOptions = listParser.add_argument_group('list options')
        listOptions.add_argument('-n', '--name',
            help="Restrict listing to items matching the given name. Applies to targets and boards.")
        listOptions.add_argument('-r', '--vendor',
            help="Restrict listing to items whose vendor matches the given name. Applies to targets.")
        listOptions.add_argument('-s', '--source', choices=('builtin', 'pack'),
            help="Restrict listing to targets from the specified source. Applies to targets.")
        listOptions.add_argument('-H', '--no-header', action='store_true',
            help="Don't print a table header.")
        subparsers.add_parser('list', parents=[commonOptions, listParser],
            help="List information about probes, targets, or boards.")

        # Create *pack* subcommand parser.
        packParser = argparse.ArgumentParser(description='pack', add_help=False)
        packOperations = packParser.add_argument_group('pack operations')
        packOperations.add_argument("-c", "--clean", action='store_true',
            help="Erase all stored pack information.")
        packOperations.add_argument("-u", "--update", action='store_true',
            help="Update the pack index.")
        packOperations.add_argument("-s", "--show", action='store_true',
            help="Show the list of installed packs.")
        packOperations.add_argument("-f", "--find", dest="find_devices", metavar="GLOB", action='append',
            help="Report pack(s) in the index containing matching device part numbers.")
        packOperations.add_argument("-i", "--install", dest="install_devices", metavar="GLOB", action='append',
            help="Download and install pack(s) containing matching device part numbers.")
        packOptions = packParser.add_argument_group('pack options')
        packOptions.add_argument("-n", "--no-download", action='store_true',
            help="Just list the pack(s) that would be downloaded, don't actually download anything.")
        packOptions.add_argument('-H', '--no-header', action='store_true',
            help="Don't print a table header.")
        subparsers.add_parser('pack', parents=[loggingOptions, packParser],
            help="Manage CMSIS-Packs for target support.")

        # Create *server* subcommand parser.
        serverParser = subparsers.add_parser('server', parents=[loggingOptions],
            help="Run debug probe server.")
        serverParser.add_argument('-O', action='append', dest='options', metavar="OPTION=VALUE",
            help="Set named option.")
        serverParser.add_argument("-da", "--daparg", dest="daparg", nargs='+',
            help="Send setting to DAPAccess layer.")
        serverParser.add_argument("-p", "--port", dest="port_number", type=int, default=None,
            help="Set the server's port number (default 5555).")
        serverParser.add_argument("--local-only", dest="serve_local_only", default=False, action="store_true",
            help="Allow remote TCP/IP connections (default is yes).")
        serverParser.add_argument("-u", "--uid", dest="unique_id",
            help="Serve only the specified probe. Can be used multiple times.")
        serverParser.set_defaults(verbose=0, quiet=0)
        
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
        """! @brief Display help for session options."""
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
        all_outputs = (self._args.probes, self._args.targets, self._args.boards, self._args.plugins)
        
        # Default to listing probes.
        if not any(all_outputs):
            self._args.probes = True
        
        # Check for more than one output option being selected.
        if sum(int(x) for x in all_outputs) > 1:
            LOG.error("Only one of the output options '--probes', '--targets', '--boards', "
                      "or '--plugins' may be selected at a time.")
            return
        
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
        elif self._args.plugins:
            obj = ListGenerator.list_plugins()
            pt = self._get_pretty_table(["Type", "Plugin Name", "Version", "Description"])
            for group_info in sorted(obj['plugins'], key=lambda i: i['plugin_type']):
                for plugin_info in sorted(group_info['plugins'], key=lambda i: i['name']):
                    pt.add_row([
                                PLUGIN_GROUP_NAMES[group_info['plugin_type']],
                                plugin_info['name'],
                                plugin_info['version'],
                                plugin_info['description'],
                                ])
            print(pt)
    
    def do_json(self):
        """! @brief Handle 'json' subcommand."""
        all_outputs = (self._args.probes, self._args.targets, self._args.boards, self._args.features)
        
        # Default to listing probes.
        if not any(all_outputs):
            self._args.probes = True
        
        # Check for more than one output option being selected.
        if sum(int(x) for x in all_outputs) > 1:
            # Because we're outputting JSON we can't just log the error, but must report the error
            # via the JSON format.
            obj = {
                'pyocd_version' : __version__,
                'version' : { 'major' : 1, 'minor' : 0 },
                'status' : 1,
                'error' : "More than one output data selected.",
                }

            print(json.dumps(obj, indent=4))
            return
        
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
        elif self._args.features:
            obj = ListGenerator.list_features()
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
                            blocking=(not self._args.no_wait),
                            connect_mode=self._args.connect_mode,
                            options=convert_session_options(self._args.options))
        if session is None:
            LOG.error("No device available to flash")
            sys.exit(1)
        with session:
            programmer = FileProgrammer(session,
                            chip_erase=self._args.erase,
                            trust_crc=self._args.trust_crc)
            programmer.program(self._args.file,
                            base_address=self._args.base_address,
                            skip=self._args.skip,
                            file_format=self._args.format)
    
    def do_erase(self):
        """! @brief Handle 'erase' subcommand."""
        self._increase_logging(["pyocd.flash.eraser"])
        
        # Display a nice, helpful error describing why nothing was done and how to correct it.
        if (self._args.erase_mode is None) or not self._args.addresses:
            LOG.error("No erase operation specified. Please specify one of '--chip', '--sector', "
                        "or '--mass' to indicate the desired erase mode. For sector erases, a list "
                        "of sector addresses to erase must be provided. "
                        "See 'pyocd erase --help' for more.")
            return
        
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=(not self._args.no_wait),
                            connect_mode=self._args.connect_mode,
                            options=convert_session_options(self._args.options))
        if session is None:
            LOG.error("No device available to erase")
            sys.exit(1)
        with session:
            mode = self._args.erase_mode or FlashEraser.Mode.SECTOR
            eraser = FlashEraser(session, mode)
            
            addresses = flatten_args(self._args.addresses)
            eraser.erase(addresses)
    
    def do_reset(self):
        """! @brief Handle 'reset' subcommand."""
        # Verify selected reset type.
        try:
            the_reset_type = convert_reset_type(self._args.reset_type)
        except ValueError:
            LOG.error("Invalid reset method: %s", self._args.reset_type)
            return
        
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=(not self._args.no_wait),
                            connect_mode=self._args.connect_mode,
                            options=convert_session_options(self._args.options))
        if session is None:
            LOG.error("No device available to reset")
            sys.exit(1)
        try:
            # Handle hw reset specially using the probe, so we don't need a valid connection
            # and can skip discovery.
            is_hw_reset = the_reset_type == Target.ResetType.HW
            
            # Only init the board if performing a sw reset.
            session.open(init_board=(not is_hw_reset))
            
            LOG.info("Performing '%s' reset...", self._args.reset_type)
            if is_hw_reset:
                session.probe.reset()
            else:
                session.target.reset(reset_type=the_reset_type)
            LOG.info("Done.")
        finally:
            session.close()

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

        probe_server = None
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
            
            # Split list of cores to serve.
            if self._args.core is not None:
                try:
                    core_list = {int(x) for x in self._args.core.split(',')}
                except ValueError as err:
                    LOG.error("Invalid value passed to --core")
                    return
            else:
                core_list = None
            
            # Get the probe.
            probe = ConnectHelper.choose_probe(
                        blocking=(not self._args.no_wait),
                        return_first=False,
                        unique_id=self._args.unique_id,
                        )
            if probe is None:
                LOG.error("No probe selected.")
                return
            
            # Create a proxy so the probe can be shared between the session and probe server.
            probe_proxy = SharedDebugProbeProxy(probe)
            
            # Create the session.
            session = Session(probe_proxy,
                project_dir=self._args.project_dir,
                user_script=self._args.script,
                config_file=self._args.config,
                no_config=self._args.no_config,
                pack=self._args.pack,
                unique_id=self._args.unique_id,
                target_override=self._args.target_override,
                frequency=self._args.frequency,
                connect_mode=self._args.connect_mode,
                options=sessionOptions)
            if session is None:
                LOG.error("No probe selected.")
                return
            with session:
                # Validate the core selection.
                all_cores = set(session.target.cores.keys())
                if core_list is None:
                    core_list = all_cores
                bad_cores = core_list.difference(all_cores)
                if len(bad_cores):
                    LOG.error("Invalid core number%s: %s",
                        "s" if len(bad_cores) > 1 else "",
                        ", ".join(str(x) for x in bad_cores))
                    return
                
                # Set ELF if provided.
                if self._args.elf:
                    session.board.target.elf = os.path.expanduser(self._args.elf)
                    
                # Run the probe server is requested.
                if self._args.enable_probe_server:
                    probe_server = DebugProbeServer(session, session.probe,
                            self._args.probe_server_port, self._args.serve_local_only)
                    session.probeserver = probe_server
                    probe_server.start()
                    
                # Start up the gdbservers.
                for core_number, core in session.board.target.cores.items():
                    # Don't create a server for CPU-less memory Access Port. 
                    if isinstance(session.board.target.cores[core_number], GenericMemAPTarget):
                        continue
                    # Don't create a server if this core is not listed by the user.
                    if core_number not in core_list:
                        continue
                    gdb = GDBServer(session,
                        core=core_number,
                        server_listening_callback=self.server_listening)
                    session.gdbservers[core_number] = gdb
                    gdbs.append(gdb)
                    gdb.start()
                gdb = gdbs[0]
                while any(g.is_alive() for g in gdbs):
                    sleep(0.1)
                if probe_server:
                    probe_server.stop()
        except (KeyboardInterrupt, Exception):
            for server in gdbs:
                server.stop()
            if probe_server:
                probe_server.stop()
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
            packs = pack_target.ManagedPacks.get_installed_packs(cache)
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
                pat = re.compile(fnmatch.translate(pattern).rsplit('\\Z')[0], re.IGNORECASE)
                results = {name for name in cache.index.keys() if pat.search(name)}
                matches.update(results)
            
            if not matches:
                LOG.warning("No matching devices. Please make sure the pack index is up to date.")
                return
            
            if self._args.find_devices:
                # Get the list of installed pack targets.
                installed_targets = pack_target.ManagedPacks.get_installed_targets(cache=cache)
                installed_target_names = [target.part_number.lower() for target in installed_targets]
                
                pt = self._get_pretty_table(["Part", "Vendor", "Pack", "Version", "Installed"])
                for name in sorted(matches):
                    info = cache.index[name]
                    ref, = cache.packs_for_devices([info])
                    pt.add_row([
                                info['name'],
                                ref.vendor,
                                ref.pack,
                                ref.version,
                                info['name'].lower() in installed_target_names,
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

    def do_server(self):
        """! @brief Handle 'server' subcommand."""
        # Create a session to load config, particularly logging config. Even though we do have a
        # probe, we don't set it in the session because we don't want the board, target, etc objects
        # to be created.
        session_options = convert_session_options(self._args.options)
        session = Session(probe=None, options=session_options)
        
        # The ultimate intent is to serve all available probes by default. For now we just serve
        # a single probe.
        probe = ConnectHelper.choose_probe(unique_id=self._args.unique_id)
        if probe is None:
            return
        
        # Assign the session to the probe.
        probe.session = session
        
        # Create the server instance.
        server = DebugProbeServer(session, probe, self._args.port_number, self._args.serve_local_only)
        session.probeserver = server
        LOG.debug("Starting debug probe server")
        server.start()
        
        # Loop as long as the probe is running. The server thread is a daemon, so the main thread
        # must continue to exist.
        try:
            while server.is_running:
                sleep(0.1)
        except (KeyboardInterrupt, Exception):
            server.stop()
            raise

    ## @brief Table of handler methods for subcommands.
    _COMMANDS = {
        'list':         do_list,
        'json':         do_json,
        'flash':        do_flash,
        'erase':        do_erase,
        'reset':        do_reset,
        'gdbserver':    do_gdbserver,
        'gdb':          do_gdbserver,
        'commander':    do_commander,
        'cmd':          do_commander,
        'pack':         do_pack,
        'server':       do_server,
        }

def main():
    sys.exit(PyOCDTool().run())

if __name__ == '__main__':
    main()
