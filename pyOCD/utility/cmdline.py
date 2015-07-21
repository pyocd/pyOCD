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

