# pyOCD debugger
# Copyright (c) 2021-2023 Chris Reed
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

import argparse
import logging
import prettytable
from typing import (Any, Dict, List, Optional, Type)

from ..utility.cmdline import convert_frequency

class SubcommandBase:
    """@brief Base class for pyocd command line subcommand."""

    # Subcommand descriptors.
    NAMES: List[str] = []
    HELP: str = ""
    EPILOG: Optional[str] = None
    DEFAULT_LOG_LEVEL = logging.INFO
    SUBCOMMANDS: List[Type["SubcommandBase"]] = []

    ## Class attribute to store the built subcommand argument parser.
    parser: Optional[argparse.ArgumentParser] = None

    class CommonOptions:
        """@brief Namespace with parsers for repeated option groups."""

        # Define logging related options.
        LOGGING = argparse.ArgumentParser(description='logging', add_help=False)
        LOGGING_GROUP = LOGGING.add_argument_group("logging")
        LOGGING_GROUP.add_argument('-v', '--verbose', action='count', default=0,
            help="Increase logging level. Can be specified multiple times.")
        LOGGING_GROUP.add_argument('-q', '--quiet', action='count', default=0,
            help="Decrease logging level. Can be specified multiple times.")
        LOGGING_GROUP.add_argument('-L', '--log-level', action='append', metavar="LOGGERS=LEVEL", default=[],
            help="Set log level of loggers whose name matches any of the comma-separated list of glob-style "
            "patterns. Log level must be one of (critical, error, warning, info, debug). Can be "
            "specified multiple times. Example: -L*.trace,pyocd.core.*=debug")
        LOGGING_GROUP.add_argument('--color', choices=("always", "auto", "never"), default=None, nargs='?',
            const="auto", help="Control color logging. Default is auto.")

        # Define config related options for all subcommands.
        CONFIG = argparse.ArgumentParser(description='common', add_help=False)
        CONFIG_GROUP = CONFIG.add_argument_group("configuration")
        CONFIG_GROUP.add_argument('-j', '--project', '--dir', metavar="PATH", dest="project_dir",
            help="Set the project directory. Defaults to the directory where pyocd was run.")
        CONFIG_GROUP.add_argument('--config', metavar="PATH",
            help="Specify YAML configuration file. Defaults to pyocd.yaml or pyocd.yml in the project directory.")
        CONFIG_GROUP.add_argument("--no-config", action="store_true", default=None,
            help="Do not use a configuration file.")
        CONFIG_GROUP.add_argument('--script', metavar="PATH",
            help="Use the specified user script. Defaults to pyocd_user.py in the project directory.")
        CONFIG_GROUP.add_argument('-O', action='append', dest='options', metavar="OPTION=VALUE",
            help="Set named option.")
        CONFIG_GROUP.add_argument("-da", "--daparg", dest="daparg", nargs='+',
            help="(Deprecated) Send setting to DAPAccess layer.")
        CONFIG_GROUP.add_argument("--pack", metavar="PATH", action="append",
            help="Path to the .pack file for a CMSIS Device Family Pack.")

        # Define common options for all subcommands, including logging options.
        COMMON = argparse.ArgumentParser(description='common',
            parents=[LOGGING, CONFIG], add_help=False)

        # Common connection related options.
        CONNECT = argparse.ArgumentParser(description='common', add_help=False)
        CONNECT_GROUP = CONNECT.add_argument_group("connection")
        CONNECT_GROUP.add_argument("-u", "--uid", "--probe", dest="unique_id",
            help="Select the debug probe by its full or partial unique ID. Optionally prefixed with "
            "'<probe-type>:' where <probe-type> is the name of a probe plugin.")
        # Reserved --board argument.
        # CONNECT_GROUP.add_argument("-b", "--board", dest="board_override", metavar="BOARD",
        #     help="Set the board type (not yet implemented).")
        CONNECT_GROUP.add_argument("-t", "--target", dest="target_override", metavar="TARGET",
            help="Set the target type. See available target types with 'pyocd list --targets'.")
        CONNECT_GROUP.add_argument("-f", "--frequency", dest="frequency", default=None, type=convert_frequency,
            help="SWD/JTAG clock frequency in Hz. Accepts a float or int with optional case-"
                "insensitive K/M suffix and optional Hz. Examples: \"1000\", \"2.5khz\", \"10m\".")
        CONNECT_GROUP.add_argument("-W", "--no-wait", action="store_true",
            help="Do not wait for a probe to be connected if none are available.")
        CONNECT_GROUP.add_argument("-M", "--connect", dest="connect_mode", metavar="MODE",
            help="Select connect mode from one of (halt, pre-reset, under-reset, attach).")

    @classmethod
    def add_subcommands(cls, parser: argparse.ArgumentParser) -> None:
        """@brief Add declared subcommands to the given parser."""
        if cls.SUBCOMMANDS:
            subparsers = parser.add_subparsers(title="subcommands", metavar="", dest='cmd')
            for subcmd_class in cls.SUBCOMMANDS:
                parsers = subcmd_class.get_args()
                subcmd_class.parser = parsers[-1]

                subparser = subparsers.add_parser(
                                subcmd_class.NAMES[0],
                                aliases=subcmd_class.NAMES[1:],
                                parents=parsers,
                                help=subcmd_class.HELP,
                                epilog=subcmd_class.EPILOG)
                subparser.set_defaults(command_class=subcmd_class)
                subcmd_class.customize_subparser(subparser)

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object.
        @return List of argument parsers. The last element in the list _must_ be the parser for the subcommand
            class itself, as it is saved by the caller in cls.parser.
        """
        raise NotImplementedError()

    @classmethod
    def customize_subparser(cls, subparser: argparse.ArgumentParser) -> None:
        """@brief Optionally modify a subparser after it is created."""
        pass

    def __init__(self, args: argparse.Namespace):
        """@brief Constructor.

        @param self This object.
        @param args Namespace of parsed argument values.
        """
        self._args = args

    def invoke(self) -> int:
        """@brief Run the subcommand.
        @return Process status code for the command.
        """
        if self.parser is not None:
            self.parser.print_help()
        return 0

    def _get_log_level_delta(self) -> int:
        """@brief Compute the logging level delta sum from quiet and verbose counts."""
        return (self._args.quiet * 10) - (self._args.verbose * 10)

    def _increase_logging(self, loggers: List[str]) -> None:
        """@brief Increase logging level for a set of subloggers.
        @param self This object.
        @param loggers
        """
        delta = self._get_log_level_delta()
        if delta <= 0:
            level = max(1, self.DEFAULT_LOG_LEVEL + delta - 10)
            for logger in loggers:
                logging.getLogger(logger).setLevel(level)

    def _get_pretty_table(self, fields: List[str], header: bool = None) -> prettytable.PrettyTable:
        """@brief Returns a PrettyTable object with formatting options set."""
        pt = prettytable.PrettyTable(fields)
        pt.align = 'l'
        if header is not None:
            pt.header = header
        elif hasattr(self._args, 'no_header'):
            pt.header = not self._args.no_header
        else:
            pt.header = True
        pt.border = True
        pt.hrules = prettytable.HEADER
        pt.vrules = prettytable.NONE
        return pt

    def _modified_option_defaults(self) -> Dict[str, Any]:
        """@brief Returns a dict of session option defaults.

        @return A dict containing updated default values for session options, based on common
            subcommand arguments. It is intended to be passed as the `option_defaults` argument when
            creating a `Session` instance.
        @precondition Logging must have been configured.
        """
        return {
            # Change 'debug.traceback' default to True if debug logging is enabled.
            'debug.traceback': logging.getLogger('pyocd').isEnabledFor(logging.DEBUG),
        }


