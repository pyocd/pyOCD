# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

import logging
import os
import sys
import six
import pprint
from collections import namedtuple
import subprocess
from shutil import get_terminal_size

from ..core import exceptions
from ..coresight.ap import MEM_AP
from ..utility.cmdline import (
    split_command_line,
    UniquePrefixMatcher,
    )

LOG = logging.getLogger(__name__)

class CommandSet(object):
    """! @brief Holds a set of command classes."""
    
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
        """! @brief Add commands belonging to a group to the command set.
        @param self The command set.
        @param group_name String with the name of the group to add.
        """
        from .base import ALL_COMMANDS
        self.add_commands(ALL_COMMANDS.get(group_name, set()))
    
    def add_commands(self, commands):
        """! @brief Add some commands to the command set.
        @param self The command set.
        @param commands List of command classes.
        """
        from .base import (CommandBase, ValueBase)
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

CommandInvocation = namedtuple('CommandInvocation', ['cmd', 'args', 'handler'])
"""! @brief Groups the command name with an iterable of args and a handler function.

The handler is a callable that will evaluate the command. It accepts a single argument of the
CommandInvocation instance.
"""

class CommandExecutionContext(object):
    """! @brief Manages command execution.
    
    This class holds persistent state for command execution, and provides the interface for executing
    commands and command lines.
    """
    
    def __init__(self, no_init=False, output_stream=None):
        """! @brief Constructor.
        @param self This object.
        @param no_init Whether the board and target will be initialized when attach_session() is called.
            Defaults to False.
        @param output_stream Stream object to which command output and errors will be written. If not provided,
            output will be written to sys.stdout.
        @param elf_path Optional path to an ELF file.
        """
        self._no_init = no_init
        self._output = output_stream or sys.stdout
        self._python_namespace = None
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
        """! @brief Write a fixed message to the output stream.
        
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
        """! @brief Write an interpolated string to the output stream.
        
        The formatted string is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator.
        
        @param self This object.
        @param fmt Format string using printf-style "%" formatters.
        """
        assert isinstance(fmt, str)
        message = fmt % args
        self.write(message, **kwargs)
    
    def writef(self, fmt, *args, **kwargs):
        """! @brief Write a formatted string to the output stream.
        
        The formatted string is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator.
        
        @param self This object.
        @param fmt Format string using the format() mini-language.
        """
        assert isinstance(fmt, str)
        message = fmt.format(*args, **kwargs)
        self.write(message, **kwargs)

    def attach_session(self, session):
        """! @brief Associate a session with the command context.
        
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

        # Select the first core's MEM-AP by default.
        if not self._no_init:
            try:
                # Selected core defaults to the target's default selected core.
                if self.selected_core is None:
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
        
        return True
    
    @property
    def session(self):
        return self._session
    
    @property
    def board(self):
        return self._session and self._session.board
    
    @property
    def target(self):
        return self._session and self._session.target
    
    @property
    def probe(self):
        return self._session and self._session.probe
    
    @property
    def elf(self):
        return self.target and self.target.elf
    
    @property
    def command_set(self):
        """! @brief CommandSet with commands available in this context."""
        return self._command_set
    
    @property
    def peripherals(self):
        """! @brief Dict of SVD peripherals."""
        if self.target.svd_device and not self._loaded_peripherals:
            for p in self.target.svd_device.peripherals:
                self._peripherals[p.name.lower()] = p
            self._loaded_peripherals = True
        return self._peripherals
    
    @property
    def output_stream(self):
        return self._output
    
    @output_stream.setter
    def output_stream(self, stream):
        self._output = stream
    
    @property
    def selected_core(self):
        """! @brief The Target instance for the selected core."""
        return self._selected_core
    
    @selected_core.setter
    def selected_core(self, value):
        self._selected_core = value
    
    @property
    def selected_ap_address(self):
        return self._selected_ap_address

    @selected_ap_address.setter
    def selected_ap_address(self, value):
        self._selected_ap_address = value
    
    @property
    def selected_ap(self):
        if self.selected_ap_address is None:
            return None
        else:
            return self.target.aps[self.selected_ap_address]

    def process_command_line(self, line):
        """! @brief Run a command line consisting of one or more semicolon-separated commands."""
        for invoc in self.parse_command_line(line):
            invoc.handler(invoc)

    def parse_command_line(self, line):
        """! @brief Generator yielding CommandInvocations for commands separated by semicolons."""
        for cmd in self._split_commands(line):
            invoc = self.parse_command(cmd)
            if invoc is not None:
                yield invoc

    def _split_commands(self, line):
        """! @brief Generator yielding commands separated by semicolons."""
        result = ''
        i = 0
        while i < len(line):
            c = line[i]
            # Don't split on escaped semicolons.
            if (c == '\\') and (i < len(line) - 1) and (line[i + 1] == ';'):
                i += 1
                result += ';'
            elif c == ';':
                yield result
                result = ''
            else:
                result += c
            i += 1
        if result:
            yield result

    def parse_command(self, cmdline):
        """! @brief Create a CommandInvocation from a single command."""
        cmdline = cmdline.strip()
        
        # Check for Python or shell command lines.
        first_char = cmdline[0]
        if first_char in '$!':
            cmdline = cmdline[1:]
            if first_char == '$':
                return CommandInvocation(cmdline, None, self.handle_python)
            elif first_char == '!':
                return CommandInvocation(cmdline, None, self.handle_system)

        # Split command into words.
        args = split_command_line(cmdline)
        cmd = args[0].lower()
        args = args[1:]

        # Look up shorted unambiguous match for the command name.
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

    def execute_command(self, invocation):
        """! @brief Execute a single command."""
        # Must have an attached session to run commands, except for certain commands.
        assert (self.session is not None) or (invocation.cmd in ('list', 'help', 'exit'))

        # Run command.
        cmd_class = self._command_set.commands[invocation.cmd]
        cmd_object = cmd_class(self)
        cmd_object.check_arg_count(invocation.args)
        cmd_object.parse(invocation.args)
        cmd_object.execute()

    def _build_python_namespace(self):
        """! @brief Construct the dictionary used as the namespace for python commands."""
        import pyocd
        self._python_namespace = {
                'session': self.session,
                'board': self.board,
                'target': self.target,
                'probe': self.probe,
                'dp': self.target.dp,
                'aps': self.target.dp.aps,
                'elf': self.elf,
                'map': self.target.memory_map,
                'pyocd': pyocd,
            }

    def handle_python(self, invocation):
        """! @brief Evaluate a python expression."""
        try:
            # Lazily build the python environment.
            if self._python_namespace is None:
                self._build_python_namespace()
            
            result = eval(invocation.cmd, globals(), self._python_namespace)
            if result is not None:
                if isinstance(result, str):
                    self.writei("0x%08x (%d)", result, result)
                else:
                    w, h = get_terminal_size()
                    self.write(pprint.pformat(result, indent=2, width=w, depth=10))
        except Exception as e:
            # Log the traceback before raising the exception.
            if self.session.log_tracebacks:
                LOG.error("Exception while executing expression: %s", e, exc_info=True)
            raise exceptions.CommandError("exception while executing expression: %s" % e)
    
    def handle_system(self, invocation):
        """! @brief Evaluate a system call command."""
        try:
            output = subprocess.check_output(invocation.cmd, stderr=subprocess.STDOUT, shell=True)
            self.write(six.ensure_str(output), end='')
        except subprocess.CalledProcessError as err:
            raise exceptions.CommandError(str(err)) from err
