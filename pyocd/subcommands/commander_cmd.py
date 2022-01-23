# pyOCD debugger
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

import argparse
import logging
import io
from typing import List

from .base import SubcommandBase
from ..commands.commander import PyOCDCommander

class CommanderSubcommand(SubcommandBase):
    """@brief `pyocd commander` subcommand."""

    NAMES = ['commander', 'cmd']
    HELP = "Interactive command console."
    DEFAULT_LOG_LEVEL = logging.WARNING

    EPILOG = """Commands specified by the -c/--command and -x/--execute arguments are run in the order they are listed
        on the command line, and the two types can be mixed freely and in any order. Normally, pyOCD will exit after
        running such commands. If the -i/--interactive flag is set, then the interactive REPL will be instead be
        started when the commands have finished. In command files each line is either a complete command, a comment
        started with '#', or empty.
        """

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""
        commander_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        commander_options = commander_parser.add_argument_group("commander options")
        commander_options.add_argument("-H", "--halt", action="store_true", default=None,
            help="Halt core upon connect. (Deprecated, see --connect.)")
        commander_options.add_argument("-N", "--no-init", action="store_true",
            help="Do not init debug system.")
        commander_options.add_argument("--elf", metavar="PATH",
            help="Optionally specify ELF file being debugged.")
        commander_options.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+',
            help="Run commands.")
        commander_options.add_argument("-x", "--execute", dest="commands", metavar="FILE", action='append',
            type=argparse.FileType('r'),
            help="Execute commands from file. Pass - for stdin.")
        commander_options.add_argument("-i", "--interactive", action="store_true",
            help="Stay in interactive mode after running commands specified from command line or file.")

        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, commander_parser]

    def invoke(self) -> int:
        """@brief Handle 'commander' subcommand."""
        # Flatten commands list then extract primary command and its arguments.
        if self._args.commands is not None:
            cmds = []
            for cmd in self._args.commands:
                if isinstance(cmd, io.IOBase):
                    cmds.append(cmd)
                else:
                    cmds.append(" ".join(cmd))
        else:
            cmds = None

        # Enter REPL.
        PyOCDCommander(self._args, cmds).run()

        return 0


