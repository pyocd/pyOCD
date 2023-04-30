# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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

from __future__ import annotations

import logging
import sys
from typing import (Any, Callable, cast, Dict, IO, Iterator, List, NamedTuple, Optional, Sequence,
        TYPE_CHECKING)
import six
import pprint
import subprocess
from shutil import get_terminal_size

from ..core import exceptions
from ..coresight.ap import MEM_AP
from ..utility.strings import UniquePrefixMatcher
from ..utility.cmdline import split_command_line

if TYPE_CHECKING:
    from ..debug.svd.model import SVDPeripheral
    from ..core.session import Session
    from ..core.core_target import CoreTarget
    from ..core.soc_target import SoCTarget
    from ..board.board import Board
    from ..coresight.ap import (APAddressBase, AccessPort)
    from ..coresight.coresight_target import CoreSightTarget
    from ..probe.debug_probe import DebugProbe

LOG = logging.getLogger(__name__)

class CommandSet:
    """@brief Holds a set of command classes."""

    ## Whether command and infos modules have been loaded yet.
    DID_LOAD_COMMAND_MODULES = False

    def __init__(self):
        self._commands = {} # Dict of all available commands.
        self._command_classes = set()
        self._command_matcher = UniquePrefixMatcher()
        self._values = {}
        self._value_classes = set()
        self._value_matcher = UniquePrefixMatcher()

        # Ensure these modules get loaded so the ALL_COMMANDS dicts are filled.
        self._load_modules()

    @classmethod
    def _load_modules(cls):
        # Load these modules in order to populate the dicts with standard commands. This must be
        # done lazily because the commands import lots of modules from pyocd that would cause import
        # cycles otherwise.
        if not cls.DID_LOAD_COMMAND_MODULES:
            from . import commands
            from . import values
            cls.DID_LOAD_COMMAND_MODULES = True

    @property
    def commands(self):
        return self._commands

    @property
    def command_classes(self):
        return self._command_classes

    @property
    def command_matcher(self):
        return self._command_matcher

    @property
    def values(self):
        return self._values

    @property
    def value_classes(self):
        return self._value_classes

    @property
    def value_matcher(self):
        return self._value_matcher

    def add_command_group(self, group_name):
        """@brief Add commands belonging to a group to the command set.
        @param self The command set.
        @param group_name String with the name of the group to add.
        """
        from .base import ALL_COMMANDS
        self.add_commands(ALL_COMMANDS.get(group_name, set()))

    def add_commands(self, commands):
        """@brief Add some commands to the command set.
        @param self The command set.
        @param commands List of command classes.
        """
        from .base import ValueBase
        value_classes = {klass for klass in commands if issubclass(klass, ValueBase)}
        cmd_classes = commands - value_classes
        cmd_names = {name: klass for klass in cmd_classes for name in klass.INFO['names']}
        self._commands.update(cmd_names)
        self._command_classes.update(cmd_classes)
        self._command_matcher.add_items(cmd_names.keys())

        value_names = {name: klass for klass in value_classes for name in klass.INFO['names']}
        self._values.update(value_names)
        self._value_classes.update(value_classes)
        self._value_matcher.add_items(value_names.keys())

class CommandInvocation(NamedTuple):
    """@brief Groups the command name with an iterable of args and a handler function.

    The handler is a callable that will evaluate the command. It accepts a single argument of the
    CommandInvocation instance.
    """
    cmd: str
    args: Sequence[str]
    handler: Callable[["CommandInvocation"], None] # type:ignore # mypy doesn't support recursive types yet!

class CommandExecutionContext:
    """@brief Manages command execution.

    This class holds persistent state for command execution, and provides the interface for executing
    commands and command lines.
    """

    _session: Optional[Session]
    _selected_core: Optional[CoreTarget]
    _selected_ap_address: Optional[APAddressBase]
    _peripherals: Dict[str, SVDPeripheral]
    _python_namespace: Dict[str, Any]

    def __init__(self, no_init: bool = False, output_stream: Optional[IO[str]] = None):
        """@brief Constructor.
        @param self This object.
        @param no_init Whether the board and target will be initialized when attach_session() is called.
            Defaults to False.
        @param output_stream Stream object to which command output and errors will be written. If not provided,
            output will be written to sys.stdout.
        @param elf_path Optional path to an ELF file.
        """
        self._no_init = no_init
        self._output = output_stream or sys.stdout
        self._python_namespace = {}
        self._command_set = CommandSet()

        # State attributes.
        self._session = None
        self._selected_core = None
        self._selected_ap_address = None
        self._peripherals = {}
        self._loaded_peripherals = False

        # Add in the standard commands.
        self._command_set.add_command_group('standard')

    def write(self, message='', **kwargs):
        """@brief Write a fixed message to the output stream.

        The message is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator. No
        formatting is applied to the message. If formatting is required, use the writei() or writef()
        methods instead.

        @param self This object.
        @param message The text to write to the output. If not a string object, it is run through str().
        """
        if self._output is None:
            return
        end = kwargs.pop('end', "\n")
        if not isinstance(message, str):
            message = str(message)
        self._output.write(message + end)

    def writei(self, fmt, *args, **kwargs):
        """@brief Write an interpolated string to the output stream.

        The formatted string is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator.

        @param self This object.
        @param fmt Format string using printf-style "%" formatters.
        """
        assert isinstance(fmt, str)
        message = fmt % args
        self.write(message, **kwargs)

    def writef(self, fmt, *args, **kwargs):
        """@brief Write a formatted string to the output stream.

        The formatted string is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator.

        @param self This object.
        @param fmt Format string using the format() mini-language.
        """
        assert isinstance(fmt, str)
        message = fmt.format(*args, **kwargs)
        self.write(message, **kwargs)

    def attach_session(self, session):
        """@brief Associate a session with the command context.

        Various data for the context are initialized. This includes selecting the initially selected core and MEM-AP,
        and getting an ELF file that was set on the target.

        @param self This object.
        @param session A @ref pyocd.core.session.Session "Session" instance.
        @retval True Session attached and context state inited successfully.
        @retval False An error occurred when opening the session or initing the context state.
        """
        assert self._session is None
        assert session.is_open or self._no_init
        self._session = session
        assert self.target

        # Select the first core's MEM-AP by default.
        if not self._no_init:
            self.set_context_defaults()

        # Allow the target to add its own commands.
        self.target.add_target_command_groups(self.command_set)

        # Add user-defined commands once we know we have a session created.
        self.command_set.add_command_group('user')

        return True

    def set_context_defaults(self) -> None:
        """@brief Sets context attributes to their default values.

        Sets the selected core and selected MEM-AP to the default values.
        """
        assert self.target

        try:
            # Selected core defaults to the target's default selected core.
            if (self.selected_core is None) and (self.target.selected_core):
                self.selected_core = self.target.selected_core

            # Get the AP for the selected core.
            if self.selected_core is not None:
                self.selected_ap_address = self.selected_core.ap.address
        except IndexError:
            pass

        # Fall back to the first MEM-AP.
        if self.selected_ap_address is None:
            for ap_num in sorted(self.target.aps.keys()):
                if isinstance(self.target.aps[ap_num], MEM_AP):
                    self.selected_ap_address = ap_num
                    break

    @property
    def session(self) -> Session:
        assert self._session
        return self._session

    @property
    def board(self) -> Board:
        assert self._session and self._session.board
        return self._session.board

    @property
    def target(self) -> SoCTarget:
        assert self._session and self._session.target
        return self._session.target

    @property
    def probe(self) -> DebugProbe:
        assert self._session and self._session.probe
        return self._session.probe

    @property
    def elf(self):
        return self.target and self.target.elf

    @property
    def command_set(self):
        """@brief CommandSet with commands available in this context."""
        return self._command_set

    @property
    def peripherals(self):
        """@brief Dict of SVD peripherals."""
        assert self.target
        if self.target.svd_device and not self._loaded_peripherals:
            for p in self.target.svd_device.peripherals:
                self._peripherals[p.name.lower()] = p
            self._loaded_peripherals = True
        return self._peripherals

    @property
    def output_stream(self) -> IO[str]:
        return self._output

    @output_stream.setter
    def output_stream(self, stream: IO[str]) -> None:
        self._output = stream

    @property
    def selected_core(self) -> Optional[CoreTarget]:
        """@brief The Target instance for the selected core."""
        return self._selected_core

    @selected_core.setter
    def selected_core(self, value: CoreTarget) -> None:
        self._selected_core = value

    @property
    def selected_ap_address(self) -> Optional[APAddressBase]:
        return self._selected_ap_address

    @selected_ap_address.setter
    def selected_ap_address(self, value: APAddressBase) -> None:
        self._selected_ap_address = value

    @property
    def selected_ap(self) -> Optional[AccessPort]:
        if self.selected_ap_address is None:
            return None
        else:
            from ..coresight.coresight_target import CoreSightTarget
            assert self.target
            if isinstance(self.target, CoreSightTarget):
                return cast(CoreSightTarget, self.target).aps[self.selected_ap_address]
            else:
                raise exceptions.CommandError("target is not CoreSight based")

    def process_command_line(self, line: str) -> None:
        """@brief Run a command line consisting of one or more semicolon-separated commands.

        @param self
        @param line Complete command line string.
        """
        for args in self._split_commands(line):
            assert args
            invoc = self.parse_command(args)
            invoc.handler(invoc)

    def process_command_file(self, cmd_file: IO[str]) -> None:
        """@brief Run commands contained in a file.

        @param self
        @param cmd_file File object containing commands to run. Must be opened in text mode. When this method returns,
            the file will be closed. This is true even if an exception is raised during command execution.
        """
        try:
            for line in cmd_file:
                line = line.strip()

                # Skip empty or comment lines.
                if (len(line) == 0) or (line[0] == '#'):
                    continue

                self.process_command_line(line)
        finally:
            cmd_file.close()

    def _split_commands(self, line: str) -> Iterator[List[str]]:
        """@brief Generator yielding commands separated by semicolons.

        Python and system commands are handled specially. For these we yield a list of 2 elements: the command,
        either "$" or "!", followed by the unmodified remainder of the command line. For these commands,
        splitting on semicolons is not supported.
        """
        parts = split_command_line(line.strip())

        # Check for Python or system command. For these we yield a list of 2 elements: the command
        # followed by the rest of the command line as it was originally.
        if parts and (parts[0] in '$!'):
            # Remove the Python/system command prefix from the command line. Can't use str.removeprefix()
            # since it was added in 3.9.
            line_remainder = line.strip()
            assert line_remainder.find(parts[0]) == 0
            line_remainder = line_remainder[len(parts[0]):].strip()
            yield [parts[0], line_remainder]
            return

        result: List[str] = []

        for p in parts:
            if p == ';':
                if result:
                    yield result
                    result = []
            else:
                result.append(p)
        if result:
            yield result

    def parse_command(self, cmdline: List[str]) -> CommandInvocation:
        """@brief Create a CommandInvocation from a single command."""
        # Check for Python or system command lines.
        first_char = cmdline[0]
        if first_char in '$!':
            # cmdline parameters that are for Python and system commands must be a 2-element list,
            # as generated by _split_commands().
            assert len(cmdline) == 2

            # Return the invocation instance with the handler set appropriately.
            if first_char == '$':
                return CommandInvocation(cmdline[1], [], self.handle_python)
            elif first_char == '!':
                return CommandInvocation(cmdline[1], [], self.handle_system)

        # Split command into words.
        args = split_command_line(cmdline)
        cmd = args[0].lower()
        args = args[1:]

        # Look up shortened unambiguous match for the command name.
        matched_command = self._command_set.command_matcher.find_one(cmd)

        # Check for valid command.
        if matched_command is None:
            all_matches = self._command_set.command_matcher.find_all(cmd)
            if len(all_matches) > 1:
                raise exceptions.CommandError("command '%s' is ambiguous; matches are %s" % (cmd,
                        ", ".join("'%s'" % c for c in all_matches)))
            else:
                raise exceptions.CommandError("unrecognized command '%s'" % cmd)

        return CommandInvocation(matched_command, args, self.execute_command)

    def execute_command(self, invocation: CommandInvocation) -> None:
        """@brief Execute a single command."""
        # Must have an attached session to run commands, except for certain commands.
        assert (self.session is not None) or (invocation.cmd in ('list', 'help', 'exit'))

        # Run command.
        cmd_class = self._command_set.commands[invocation.cmd]
        cmd_object = cmd_class(self)
        cmd_object.check_arg_count(invocation.args)
        cmd_object.parse(invocation.args)

        if self.session:
            # Reroute print() in user-defined functions so it will come out our output stream.
            with self.session.user_script_print_proxy.push_target(self.write):
                cmd_object.execute()
        else:
            cmd_object.execute()

    def _build_python_namespace(self) -> None:
        """@brief Construct the dictionary used as the namespace for python commands."""
        assert self.session
        assert self.target
        ns = self.session.user_script_proxy.namespace
        ns.update({
                'elf': self.elf,
                'map': self.target.memory_map,
            })
        self._python_namespace = ns

    def handle_python(self, invocation: CommandInvocation) -> None:
        """@brief Evaluate a python expression."""
        assert self.session
        try:
            # Lazily build the python environment.
            if not self._python_namespace:
                self._build_python_namespace()

            # Reroute print() in user-defined functions so it will come out our output stream. Not that
            # we expect much use of print() from expressions...
            with self.session.user_script_print_proxy.push_target(self.write):
                result = eval(invocation.cmd, self._python_namespace)
                if result is not None:
                    if isinstance(result, int):
                        self.writei("0x%08x (%d)", result, result)
                    else:
                        w, h = get_terminal_size()
                        self.write(pprint.pformat(result, indent=2, width=w, depth=10))
        except Exception as e:
            # Log the traceback before raising the exception.
            if self.session and self.session.log_tracebacks:
                LOG.error("Exception while executing expression: %s", e, exc_info=True)
            raise exceptions.CommandError("exception while executing expression: %s" % e)

    def handle_system(self, invocation: CommandInvocation) -> None:
        """@brief Evaluate a system call command."""
        try:
            output = subprocess.check_output(invocation.cmd, stderr=subprocess.STDOUT, shell=True)
            self.write(six.ensure_str(output), end='')
        except subprocess.CalledProcessError as err:
            raise exceptions.CommandError(str(err)) from err
