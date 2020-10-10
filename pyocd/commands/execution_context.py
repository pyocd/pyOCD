# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

from ..core import exceptions
from ..utility.compatibility import get_terminal_size
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
        if not isinstance(message, six.string_types):
            message = str(message)
        self._output.write(message + end)
    
    def writei(self, fmt, *args, **kwargs):
        """! @brief Write an interpolated string to the output stream.
        
        The formatted string is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator.
        
        @param self This object.
        @param fmt Format string using printf-style "%" formatters.
        """
        assert isinstance(fmt, six.string_types)
        message = fmt % args
        self.write(message, **kwargs)
    
    def writef(self, fmt, *args, **kwargs):
        """! @brief Write a formatted string to the output stream.
        
        The formatted string is written to the output stream passed to the constructor, terminated with
        a newline by default. The `end` keyword argument can be passed to change the terminator.
        
        @param self This object.
        @param fmt Format string using the format() mini-language.
        """
        assert isinstance(fmt, six.string_types)
        message = fmt.format(*args, **kwargs)
        self.write(message, **kwargs)

    def attach_session(self, session):
        """! @brief Associate a session with the command context.
        
        Various data for the context are initialized. This includes  selecting the initially selected MEM-AP,
        and getting an ELF file that was set on the target.
        
        @param self This object.
        @param session A @ref pyocd.core.session.Session "Session" instance.
        @retval True Session attached and context state inited successfully.
        @retval False An error occurred when opening the session or initing the context state.
        """
        assert self._session is None
        assert session.is_open
        self._session = session

        # Select the first core's MEM-AP by default.
        if not self._no_init:
            try:
                if self.target.selected_core is not None:
                    self.selected_ap_address = self.target.selected_core.ap.address
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
    def selected_ap_address(self):
        return self._selected_ap_address

    @selected_ap_address.setter
    def selected_ap_address(self, value):
        self._selected_ap_address = value
    
    @property
    def selected_ap(self):
        return self.target.aps[self.selected_ap_address]

    def process_command_line(self, line):
        """! @brief Run a command line consisting of one or more semicolon-separated commands."""
        for cmd in line.split(';'):
            self.process_command(cmd.strip())

    def process_command(self, cmd):
        """! @brief Execute a single command."""
        # Check for Python or shell command lines.
        firstChar = (cmd.strip())[0]
        if firstChar in '$!':
            cmd = cmd[1:].strip()
            if firstChar == '$':
                self.handle_python(cmd)
            elif firstChar == '!':
                os.system(cmd)
            return

        args = split_command_line(cmd)
        cmd = args[0].lower()
        args = args[1:]

        # Must have an attached session to run commands, except for certain commands.
        assert (self.session is not None) or (cmd in ('list', 'help'))

        # Handle register name as command.
        if (self.target is not None) and (cmd in self.target.core_registers.by_name):
            self.handle_reg([cmd])
            return

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
            return

        # Run command.
        cmd_class = self._command_set.commands[matched_command]
        cmd_object = cmd_class(self)
        cmd_object.check_arg_count(args)
        cmd_object.parse(args)
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

    def handle_python(self, cmd):
        """! @brief Evaluate a python expression."""
        try:
            # Lazily build the python environment.
            if self._python_namespace is None:
                self._build_python_namespace()
            
            result = eval(cmd, globals(), self._python_namespace)
            if result is not None:
                if isinstance(result, six.integer_types):
                    self.writei("0x%08x (%d)", result, result)
                else:
                    w, h = get_terminal_size()
                    self.write(pprint.pformat(result, indent=2, width=w, depth=10))
        except Exception as e:
            # Log the traceback before raising the exception.
            if self.session.log_tracebacks:
                LOG.error("Exception while executing expression: %s", e, exc_info=True)
            raise exceptions.CommandError("exception while executing expression: %s" % e)
