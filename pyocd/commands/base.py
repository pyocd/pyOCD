# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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
import textwrap

from ..core import exceptions
from ..utility import conversion
from ..utility.mask import round_up_div

LOG = logging.getLogger(__name__)

## @brief Dict of command group names to a set of command classes.
ALL_COMMANDS = {}

class CommandMeta(type):
    """! @brief Metaclass for commands.
    
    Examines the `INFO` attribute of the command class and builds the @ref pyocd.commands.commands.ALL_COMMANDS
    "ALL_COMMANDS" table.
    """

    def __new__(mcs, name, bases, dict):
        # Create the new type.
        new_type = type.__new__(mcs, name, bases, dict)
        
        # The Command base class won't have an INFO.
        if 'INFO' in dict:
            info = dict['INFO']
            
            # Validate the INFO dict.
            assert (('names' in info)
                    and ('group' in info)
                    and ('category' in info)
                    and ('help' in info)
                    and ((('nargs' in info) and ('usage' in info)) # Required for commands.
                        or ('access' in info))) # Required for values.
            
            # Add this command to our table of commands by group.
            ALL_COMMANDS.setdefault(info['group'], set()).add(new_type)
        return new_type

class CommandBase(metaclass=CommandMeta):
    """! @brief Base class for a command.
    
    Each command class must have an `INFO` attribute with the following keys:
    - `names`: List of names for the info. The first element is the primary name.
    - `group`: Optional name for the command group. The group is meant to be a context group, not type of
        command. Most commands belong to the 'standard' group.
    - `category`: Functional category for the command.
    - `nargs`: The number of arguments the command accepts. Either the string "*", meaning any number of
        arguments, a single integer, or a sequence of integers.
    - `usage`: String with a description of the command's argument usage.
    - `help`: String for the short help. Typically should be no more than one sentence.
    - `extra_help`: Optional key for a string with more detailed help.
    """

    def __init__(self, context):
        """! @brief Constructor."""
        self._context = context
    
    @property
    def context(self):
        """! @brief The command execution context."""
        return self._context

    def check_arg_count(self, args):
        """! @brief Verify the number of command arguments."""
        nargs = self.INFO['nargs']
        if nargs == '*':
            pass
        elif nargs is None:
            if len(args) != 0:
                raise exceptions.CommandError("command does not accept arguments")
        elif isinstance(nargs, list):
            if (len(args) not in nargs):
                raise exceptions.CommandError("incorrect number of arguments")
        elif len(args) < nargs:
            raise exceptions.CommandError("too few arguments")
        elif len(args) > nargs:
            raise exceptions.CommandError("too many arguments")

    def parse(self, args):
        """! @brief Extract command arguments."""
        pass

    def execute(self):
        """! @brief Perform the command."""
        raise NotImplementedError()

    def _format_core_register(self, info, value):
        hex_width = round_up_div(info.bitsize, 4) + 2 # add 2 for the "0x" prefix
        if info.is_float_register:
            value_str = "{f:g} ({i:#0{w}x})".format(f=conversion.u32_to_float32(value), i=value, w=hex_width)
        elif info.gdb_type in ('data_ptr', 'code_ptr'):
            value_str = "{h:#0{w}x}".format(h=value, w=hex_width)
        else:
            value_str = "{h:#0{w}x} ({d:d})".format(h=value, w=hex_width, d=value)
        return value_str

    def _convert_value(self, arg):
        """! @brief Convert an argument to a 32-bit integer.
        
        Handles the usual decimal, binary, and hex numbers with the appropriate prefix.
        Also recognizes register names and address dereferencing. Dereferencing using the
        ARM assembler syntax. To dereference, put the value in brackets, i.e. '[r0]' or
        '[0x1040]'. You can also use put an offset in the brackets after a comma, such as
        '[r3,8]'. The offset can be positive or negative, and any supported base.
        """
        try:
            deref = (arg[0] == '[')
            if deref:
                if not self.context.selected_core:
                    raise exceptions.CommandError("cannot dereference when memory is not accessible")
                arg = arg[1:-1]
                offset = 0
                if ',' in arg:
                    arg, offset = arg.split(',')
                    arg = arg.strip()
                    offset = int(offset.strip(), base=0)

            value = None
            if (self.context.selected_core) and (arg.lower() in self.context.selected_core.core_registers.by_name):
                value = self.context.selected_core.read_core_register(arg.lower())
                self.context.writei("%s = 0x%08x", arg.lower(), value)
            else:
                subargs = arg.lower().split('.')
                if subargs[0] in self.context.peripherals and len(subargs) > 1:
                    p = self.context.peripherals[subargs[0]]
                    r = [x for x in p.registers if x.name.lower() == subargs[1]]
                    if len(r):
                        value = p.base_address + r[0].address_offset
                    else:
                        raise exceptions.CommandError("invalid register '%s' for %s" % (subargs[1], p.name))
                elif self.context.elf is not None:
                    sym = self.context.elf.symbol_decoder.get_symbol_for_name(arg)
                    if sym is not None:
                        value = sym.address

            if value is None:
                arg = arg.lower().replace('_', '')
                value = int(arg, base=0)

            if deref:
                value = conversion.byte_list_to_u32le_list(
                        self.context.selected_core.read_memory_block8(value + offset, 4))[0]
                self.context.writei("[%s,%d] = 0x%08x", arg, offset, value)

            return value
        except ValueError as err:
            raise exceptions.CommandError("invalid argument '{}'".format(arg)) from None

    @classmethod
    def format_help(cls, context, max_width=72):
        """! @brief Return a string with the help text for this command."""
        text = "Usage: {cmd} {usage}\n".format(cmd=cls.INFO['names'][0], usage=cls.INFO['usage'])
        if len(cls.INFO['names']) > 1:
            text += "Aliases: {0}\n".format(", ".join(cls.INFO['names'][1:]))
        text += "\n" + textwrap.fill(cls.INFO['help'], width=max_width) + "\n"
        if 'extra_help' in cls.INFO:
            text += "\n" + textwrap.fill(cls.INFO['extra_help'], width=max_width) + "\n"
        return text

class ValueBase(CommandBase):
    """! @brief Base class for value commands.
    
    Value commands are special commands representing a value that can be read and/or written. They are used
    through the `show` and `set` commands. A value command has an associated access mode of read-only,
    write-only, or read-write. The access mode sets which of the `show` and `set` commands may be used with
    the value.
    
    Each value class must have an `INFO` attribute with the following keys:
    - `names`: List of names for the value. The first element is the primary name.
    - `group`: Optional name for the command group. The group is meant to be a context group, not type of
        command. Most values belong to the 'standard' group.
    - `category`: Functional category for the value.
    - `access`: A string of either "r" or "rw" indicating whether the value is read-only, write-only, or
        read-write.
    - `help`: String for the short help. Typically should be no more than one sentence.
    - `extra_help`: Optional key for a string with more detailed help.
    """
    
    def display(self, args):
        """! @brief Output the value of the info."""
        raise NotImplementedError()
    
    def modify(self, args):
        """! @brief Change the info to a new value."""
        raise NotImplementedError()

    @classmethod
    def format_help(cls, context, max_width=72):
        """! @brief Return a string with the help text for this command."""
        first_name = cls.INFO['names'][0]
        text = "Usage: "
        did_print_on_usage_line = False
        if 'r' in cls.INFO['access']:
            usage = cls.INFO.get('show_usage', "")
            text += "show {cmd} {usage}\n".format(cmd=first_name, usage=usage)
            did_print_on_usage_line = True
        if 'w' in cls.INFO['access']:
            indent = "       " if did_print_on_usage_line else ""
            usage = cls.INFO.get('set_usage', "VALUE")
            text += "{indent}set {cmd} {usage}\n".format(indent=indent, cmd=first_name, usage=usage)
        if len(cls.INFO['names']) > 1:
            text += "Aliases: {0}\n".format(", ".join(cls.INFO['names'][1:]))
        text += "\n" + textwrap.fill(cls.INFO['help'], width=max_width) + "\n"
        if 'extra_help' in cls.INFO:
            text += "\n" + textwrap.fill(cls.INFO['extra_help'], width=max_width) + "\n"
        return text

