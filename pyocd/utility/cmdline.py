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

import logging
from typing import (Any, Callable, Dict, Iterable, List, Optional, Tuple, Union, cast)

from ..core.target import Target
from ..core.options import OPTIONS_INFO
from ..utility.compatibility import to_str_safe

LOG = logging.getLogger(__name__)

def split_command(cmd: str) -> List[str]:
    """@brief Split command by whitespace, supporting quoted strings."""
    result: List[str] = []
    state = 0
    word = ''
    open_quote = ''
    pos = 0
    while pos < len(cmd):
        c = cmd[pos]
        pos += 1
        if state == 0:
            if c.isspace():
                if word:
                    result.append(word)
                    word = ''
            elif c in ('"', "'"):
                if word:
                    result.append(word)
                word = ''
                open_quote = c
                state = 1
            elif c in ';!@#$%^&*()+=[]{}|<>,?':
                if word:
                    result.append(word)
                word = c
                state = 2
            elif c == '\\':
                if pos < len(cmd):
                    c = cmd[pos]
                    pos += 1
                    word += c
            else:
                word += c
        elif state == 1:
            if c == open_quote:
                result.append(word)
                word = ''
                state = 0
            # Only honour escapes in double quotes.
            elif open_quote == '"' and c == '\\':
                if pos < len(cmd):
                    c = cmd[pos]
                    pos += 1
                    word += c
            else:
                word += c
        elif state == 2:
            if word:
                result.append(word)
            # Back up to reprocess this char in state 0.
            word = ''
            pos -= 1
            state = 0
    if word:
        result.append(word)
    return result

def split_command_line(cmd_line: Union[str, List[str]]) -> List[str]:
    """@brief Split command line by whitespace, supporting quoted strings."""
    result: List[str] = []
    if isinstance(cmd_line, str):
        args = [cmd_line]
    else:
        args = cmd_line
    for cmd in args:
        result += split_command(cmd)
    return result

## Map of vector char characters to masks.
VECTOR_CATCH_CHAR_MAP = {
        'e': Target.VectorCatch.SECURE_FAULT,
        'h': Target.VectorCatch.HARD_FAULT,
        'b': Target.VectorCatch.BUS_FAULT,
        'm': Target.VectorCatch.MEM_FAULT,
        'i': Target.VectorCatch.INTERRUPT_ERR,
        's': Target.VectorCatch.STATE_ERR,
        'c': Target.VectorCatch.CHECK_ERR,
        'p': Target.VectorCatch.COPROCESSOR_ERR,
        'r': Target.VectorCatch.CORE_RESET,
        'a': Target.VectorCatch.ALL,
        'n': Target.VectorCatch.NONE,
    }

def convert_vector_catch(vcvalue: Union[str, bytes]) -> int:
    """@brief Convert a vector catch string to a mask.

    @exception ValueError Raised if an invalid vector catch character is encountered.
    """
    # Make case insensitive.
    value: str = to_str_safe(vcvalue).lower()

    # Handle special vector catch options.
    if value == 'all':
        return Target.VectorCatch.ALL
    elif value == 'none':
        return Target.VectorCatch.NONE

    # Convert options string to mask.
    try:
        return sum([VECTOR_CATCH_CHAR_MAP[c] for c in value])
    except KeyError as e:
        # Reraise an error with a more helpful message.
        raise ValueError("invalid vector catch option '{}'".format(e.args[0]))

def _convert_string_list_option(value: Optional[str]) -> List[str]:
    """@brief Convert a comma-separated list of strings.

    A None value results in an empty list.

    No special support for quoted values is provided, so a comma in between quotes is treated
    the same as a comma elsewhere.
    """
    if value is None:
        return []
    return [
        i.strip()
        for i in value.split(',')
    ]

## Map with special converter routines for session options that need them.
_OPTION_CONVERTERS: Dict[str, Callable[[Optional[str]], Any]] = {
    'pack.debug_sequences.disabled_sequences': _convert_string_list_option,
}

def convert_one_session_option(name: str, value: Optional[str]) -> Tuple[str, Any]:
    """@brief Convert one session option's value from a string.

    Handles "no-" prefixed option names by inverting their boolean value. If a non-boolean option has
    a "no-" prefix, then a warning is logged and None returned for the value.

    @return Bi-tuple of option name, converted value. The option name may be modified from the one passed
        in for cases like a "no-" prefix.
    """
    # Check for and strip "no-" prefix before we validate the option name.
    if name.startswith('no-'):
        name = name[3:]
        had_no_prefix = True
    else:
        had_no_prefix = False

    # Look up this option.
    try:
        info = OPTIONS_INFO[name]
    except KeyError:
        # Return the value unmodified for unknown options.
        LOG.warning("unknown session option '%s'", name)
        return name, value

    # Check if "no-" prefix is allowed. Only bool options can use it.
    if had_no_prefix and (info.type is not bool):
        LOG.warning("'no-' prefix used on non-boolean session option '%s'", name)
        return name, None

    # Check for a special converter function.
    if name in _OPTION_CONVERTERS:
        return name, _OPTION_CONVERTERS[name](value)

    # Default result; unset option value.
    result = None

    # Extract the option's type. If its type is a tuple of types, then take the first type.
    if isinstance(info.type, tuple):
        option_type = cast(tuple, info.type)[0]
    else:
        option_type = info.type

    # Handle bool options without a value specially.
    if value is None:
        if issubclass(option_type, bool):
            result = not had_no_prefix
        else:
            LOG.warning("non-boolean option '%s' requires a value", name)
    # Convert string value to option type.
    elif issubclass(option_type, bool):
        if value.lower() in ("true", "1", "yes", "on", "false", "0", "no", "off"):
            result = value.lower() in ("true", "1", "yes", "on")

            # If a bool option with "no-" prefix has a value, the value is inverted.
            if had_no_prefix:
                result = not result
        else:
            LOG.warning("invalid value for option '%s'", name)
    elif issubclass(option_type, int):
        try:
            result = int(value, base=0)
        except ValueError:
            LOG.warning("invalid value for option '%s'", name)
    elif issubclass(option_type, float):
        try:
            result = float(value)
        except ValueError:
            LOG.warning("invalid value for option '%s'", name)
    else:
        result = value

    return name, result

def convert_session_options(option_list: Iterable[str]) -> Dict[str, Any]:
    """@brief Convert a list of session option settings to a dictionary."""
    options = {}
    if option_list is not None:
        for o in option_list:
            if '=' in o:
                name, value = o.split('=', 1)
                name = name.strip().lower()
                value = value.strip()
            else:
                name = o.strip().lower()
                value = None

            name, value = convert_one_session_option(name, value)
            if value is not None:
                options[name] = value
    return options

## Map to convert from reset type names to enums.
RESET_TYPE_MAP: Dict[str, Optional[Target.ResetType]] = {
        'default': None,
        'hw': Target.ResetType.HW,
        'sw': Target.ResetType.SW,
        'hardware': Target.ResetType.HW,
        'software': Target.ResetType.SW,
        'sw_system': Target.ResetType.SW_SYSTEM,
        'sw_core': Target.ResetType.SW_CORE,
        'sw_sysresetreq': Target.ResetType.SW_SYSRESETREQ,
        'sw_vectreset': Target.ResetType.SW_VECTRESET,
        'sw_emulated': Target.ResetType.SW_EMULATED,
        'system': Target.ResetType.SW_SYSTEM,
        'core': Target.ResetType.SW_CORE,
        'sysresetreq': Target.ResetType.SW_SYSRESETREQ,
        'vectreset': Target.ResetType.SW_VECTRESET,
        'emulated': Target.ResetType.SW_EMULATED,
    }

def convert_reset_type(value: str) -> Optional[Target.ResetType]:
    """@brief Convert a reset_type session option value to the Target.ResetType enum.
    @param value The value of the reset_type session option.
    @exception ValueError Raised if an unknown reset_type value is passed.
    """
    value = value.lower()
    if value not in RESET_TYPE_MAP:
        raise ValueError("unexpected value for reset_type option ('%s')" % value)
    return RESET_TYPE_MAP[value]

def convert_frequency(value: str) -> int:
    """@brief Applies scale suffix to frequency value string.
    @param value String with a float and possible 'k' or 'm' suffix (case-insensitive). "Hz" may
        also follow. No space is allowed between the float and suffix. Leading and trailing
        whitespace is allowed.
    @return Integer scaled according to optional metric suffix.
    """
    value = value.strip().lower()
    if value.endswith("hz"):
        value = value[:-2]
    suffix = value[-1]
    if suffix in ('k', 'm'):
        fvalue = float(value[:-1])
        if suffix == 'k':
            fvalue *= 1000
        elif suffix == 'm':
            fvalue *= 1000000
        return int(fvalue)
    else:
        return int(float(value))


def int_base_0(x: str) -> int:
    """@brief Converts a string to an int with support for base prefixes."""
    return int(x, base=0)


def flatten_args(args: Iterable[Iterable[Any]]) -> List[Any]:
    """@brief Converts a list of lists to a single list."""
    return [item for sublist in args for item in sublist]

