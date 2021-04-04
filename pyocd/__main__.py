#!/usr/bin/env python

# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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
import logging
import argparse
import colorama
import fnmatch
from typing import (Any, Optional, Sequence)

from . import __version__
from .core.session import Session
from .core import exceptions
from .probe.pydapaccess import DAPAccess
from .core import options
from .subcommands.base import SubcommandBase
from .subcommands.commander_cmd import CommanderSubcommand
from .subcommands.erase_cmd import EraseSubcommand
from .subcommands.flash_cmd import FlashSubcommand
from .subcommands.gdbserver_cmd import GdbserverSubcommand
from .subcommands.json_cmd import JsonSubcommand
from .subcommands.list_cmd import ListSubcommand
from .subcommands.pack_cmd import PackSubcommand
from .subcommands.reset_cmd import ResetSubcommand
from .subcommands.server_cmd import ServerSubcommand

## @brief Default log format for all subcommands.
LOG_FORMAT = "%(relativeCreated)07d:%(levelname)s:%(module)s:%(message)s"

## @brief Logger for this module.
LOG = logging.getLogger("pyocd.tool")

class PyOCDTool(SubcommandBase):
    """! @brief Main class for the pyocd tool and subcommands.
    """
    
    HELP = "PyOCD debug tools for Arm Cortex devices"
    
    ## List of subcommand classes.
    SUBCOMMANDS = [
        CommanderSubcommand,
        EraseSubcommand,
        FlashSubcommand,
        GdbserverSubcommand,
        JsonSubcommand,
        ListSubcommand,
        PackSubcommand,
        ResetSubcommand,
        ServerSubcommand,
        ]
    
    ## @brief Logging level names.
    LOG_LEVEL_NAMES = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL,
            }

    def __init__(self):
        # Start with an empty namespace.
        super().__init__(argparse.Namespace())
        self._parser = self.build_parser()

    def build_parser(self) -> argparse.ArgumentParser:
        """! @brief Construct the command line parser with all subcommands and options."""
        # Create top level argument parser.
        parser = argparse.ArgumentParser(description=self.HELP)
        parser.set_defaults(command_class=self, quiet=0, verbose=0, log_level=[])

        parser.add_argument('-V', '--version', action='version', version=__version__)
        parser.add_argument('--help-options', action='store_true',
            help="Display available session options.")
            
        self.add_subcommands(parser)

        return parser

    def _setup_logging(self) -> None:
        """! @brief Configure the logging module.
        
        The quiet and verbose argument counts are used to set the log verbosity level.
        
        Log level for specific loggers are also configured here.
        """
        level = max(1, self._args.command_class.DEFAULT_LOG_LEVEL + self._get_log_level_delta())
        logging.basicConfig(level=level, format=LOG_FORMAT)
        
        # Handle settings for individual loggers from --log-level arguments.
        for logger_setting in self._args.log_level:
            try:
                loggers, level_name = logger_setting.split('=')[:2]
                level = self.LOG_LEVEL_NAMES[level_name.strip().lower()]
                for logger_pattern in loggers.split(','):
                    matching_loggers = fnmatch.filter(logging.root.manager.loggerDict.keys(), logger_pattern.strip()) # type:ignore
                    LOG.debug('setting log level %s for %s', level_name, matching_loggers)
                    for logger in matching_loggers:
                        log = logging.getLogger(logger)
                        log.setLevel(level)
                        log.disabled = False
            except (ValueError, KeyError):
                raise exceptions.CommandError(f"invalid --log-level argument '{logger_setting}'")
            except AttributeError:
                LOG.warning("Failed to set logger levels; logging module may have changed.")
                break

    def invoke(self) -> int:
        """! @brief Show help when pyocd is run with no subcommand."""
        if self._args.help_options:
            self.show_options_help()
        else:
            self._parser.print_help()
        return 0
    
    def __call__(self, *args: Any, **kwds: Any) -> "PyOCDTool":
        """! @brief Hack to allow the root command object instance to be used as default command class."""
        return self

    def run(self, args: Optional[Sequence[str]] = None) -> int:
        """! @brief Main entry point for command line processing."""
        try:
            self._args = self._parser.parse_args(args)
            
            self._setup_logging()
            
            # Pass any options to DAPAccess.
            if hasattr(self._args, 'daparg'):
                DAPAccess.set_args(self._args.daparg)
            
            # Create an instance of the subcommand and invoke it.
            cmd = self._args.command_class(self._args)
            status = cmd.invoke()

            # Successful exit.
            return status
        except KeyboardInterrupt:
            return 0
        except (exceptions.Error, ValueError, IndexError) as e:
            LOG.critical(e, exc_info=Session.get_current().log_tracebacks)
            return 1
        except Exception as e:
            LOG.critical("uncaught exception: %s", e, exc_info=Session.get_current().log_tracebacks)
            return 1
    
    def show_options_help(self) -> None:
        """! @brief Display help for session options."""
        for info_name in sorted(options.OPTIONS_INFO.keys()):
            info = options.OPTIONS_INFO[info_name]
            if isinstance(info.type, tuple):
                typename = ", ".join(t.__name__ for t in info.type)
            else:
                typename = info.type.__name__
            print((colorama.Fore.CYAN + colorama.Style.BRIGHT + "{name}" + colorama.Style.RESET_ALL  # type:ignore
                + colorama.Fore.GREEN + " ({typename})" + colorama.Style.RESET_ALL
                + " {help}").format(
                name=info.name, typename=typename, help=info.help))

def main():
    sys.exit(PyOCDTool().run())

if __name__ == '__main__':
    main()
