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
import shlex
import six
from typing import (Any, Dict, Iterable, List, Sequence, Union, Optional, Tuple)

from ..core.target import Target
from ..core.options import OPTIONS_INFO
from ..utility.compatibility import to_str_safe

LOG = logging.getLogger(__name__)

def split_command_line(cmd_line: Union[str, List[str]]) -> List[str]:
    """! @brief Split command line by whitespace, supporting quoted strings."""
    result = []
    if isinstance(cmd_line, six.string_types):
        args = [cmd_line]
    else:
        args = cmd_line
    for cmd in args:
        result += shlex.split(cmd)
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

def convert_vector_catch(value: str) -> int:
    """! @brief Convert a vector catch string to a mask.
    
    @exception ValueError Raised if an invalid vector catch character is encountered.
    """
    # Make case insensitive.
    value = to_str_safe(value).lower()

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

def convert_session_options(option_list: Iterable[str]) -> Dict[str, Any]:
    """! @brief Convert a list of session option settings to a dictionary."""
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
            
            # Check for and strip "no-" prefix before we validate the option name.
            if (value is None) and (name.startswith('no-')):
                name = name[3:]
                had_no_prefix = True
            else:
                had_no_prefix = False
            
            # Look for this option.
            try:
                info = OPTIONS_INFO[name]
            except KeyError:
                LOG.warning("ignoring unknown session option '%s'", name)
                continue

            # Handle bool options without a value specially.
            if value is None:
                if info.type is bool:
                    value = not had_no_prefix
                else:
                    LOG.warning("non-boolean option '%s' requires a value", name)
                    continue
            # Convert string value to option type.
            elif info.type is bool:
                value = value in ("true", "1", "yes", "on")
            elif info.type is int:
                try:
                    value = int(value, base=0)
                except ValueError:
                    LOG.warning("invalid value for option '%s'", name)
                    continue
            
            options[name] = value
    return options

## Map to convert from reset type names to enums.
RESET_TYPE_MAP = {
        'default': None,
        'hw': Target.ResetType.HW,
        'sw': Target.ResetType.SW,
        'hardware': Target.ResetType.HW,
        'software': Target.ResetType.SW,
        'sw_sysresetreq': Target.ResetType.SW_SYSRESETREQ,
        'sw_vectreset': Target.ResetType.SW_VECTRESET,
        'sw_emulated': Target.ResetType.SW_EMULATED,
        'sysresetreq': Target.ResetType.SW_SYSRESETREQ,
        'vectreset': Target.ResetType.SW_VECTRESET,
        'emulated': Target.ResetType.SW_EMULATED,
    }

def convert_reset_type(value: str) -> Target.ResetType:
    """! @brief Convert a reset_type session option value to the Target.ResetType enum.
    @param value The value of the reset_type session option.
    @exception ValueError Raised if an unknown reset_type value is passed.
    """
    value = value.lower()
    if value not in RESET_TYPE_MAP:
        raise ValueError("unexpected value for reset_type option ('%s')" % value)
    return RESET_TYPE_MAP[value]

def convert_frequency(value: str) -> int:
    """! @brief Applies scale suffix to frequency value string.
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

class UniquePrefixMatcher():
    """! @brief Manages detection of shortest unique prefix match of a set of strings."""
    
    def __init__(self, items: Optional[Sequence[str]] = None):
        """! @brief Constructor.
        @param self This object.
        @param items Optional sequence of strings.
        """
        self._items = set(items) if (items is not None) else set()
    
    def add_items(self, items: Sequence[str]) -> None:
        """! @brief Add some items to be matched.
        @param self This object.
        @param items Sequence of strings.
        """
        self._items.update(items)
    
    def find_all(self, prefix: str) -> Tuple[str, ...]:
        """! @brief Return all items matching the given prefix.
        @param self This object.
        @param prefix String that is compared as a prefix against the items passed to the constructor.
            Must not be the empty string.
        @return List of all items where `prefix` is a valid prefix.
        @exception ValueError Raised for an empty `prefix`.
        """
        if len(prefix) == 0:
            raise ValueError("empty prefix")
        # First look for an exact match.
        if prefix in self._items:
            return (prefix,)
        return tuple(i for i in self._items if i.startswith(prefix))
    
    def find_one(self, prefix: str) -> Optional[str]:
        """! @brief Return the item matching the given prefix, or None.
        @param self This object.
        @param prefix String that is compared as a prefix against the items passed to the constructor.
        @return The full value of the matching item where `prefix` is a valid prefix.
        @exception ValueError Raised for an empty `prefix`.
        """
        all_matches = self.find_all(prefix)
        if len(all_matches) == 1:
            return all_matches[0]
        return None
