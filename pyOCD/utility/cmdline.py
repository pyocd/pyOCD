"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from ..core.target import Target
from ..utility.py3_helpers import to_str_safe

## @brief Split command line by whitespace, supporting quoted strings.
#
# Accepts
def split_command_line(cmd_line):
    result = []
    if type(cmd_line) is str:
        args = [cmd_line]
    else:
        args = cmd_line
    for cmd in args:
        state = 0
        word = ''
        open_quote = ''
        for c in cmd:
            if state == 0:
                if c in (' ', '\t', '\r', '\n'):
                    if word:
                        result.append(word)
                        word = ''
                elif c in ('"', "'"):
                    open_quote = c
                    state = 1
                else:
                    word += c
            elif state == 1:
                if c == open_quote:
                    result.append(word)
                    word = ''
                    state = 0
                else:
                    word += c
        if word:
            result.append(word)
    return result

## Map of vector char characters to masks.
VECTOR_CATCH_CHAR_MAP = {
        'h': Target.CATCH_HARD_FAULT,
        'b': Target.CATCH_BUS_FAULT,
        'm': Target.CATCH_MEM_FAULT,
        'i': Target.CATCH_INTERRUPT_ERR,
        's': Target.CATCH_STATE_ERR,
        'c': Target.CATCH_CHECK_ERR,
        'p': Target.CATCH_COPROCESSOR_ERR,
        'r': Target.CATCH_CORE_RESET,
        'a': Target.CATCH_ALL,
        'n': Target.CATCH_NONE,
    }

## @brief Convert a vector catch string to a mask.
#
# @exception ValueError Raised if an invalid vector catch character is encountered.
def convert_vector_catch(value):
    # Make case insensitive.
    value = to_str_safe(value).lower()

    # Handle special vector catch options.
    if value == 'all':
        return Target.CATCH_ALL
    elif value == 'none':
        return Target.CATCH_NONE

    # Convert options string to mask.
    try:
        return sum([VECTOR_CATCH_CHAR_MAP[c] for c in value])
    except KeyError as e:
        # Reraise an error with a more helpful message.
        raise ValueError("invalid vector catch option '{}'".format(e.args[0]))

