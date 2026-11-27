# pyOCD debugger
# Copyright (c) 2026 Emre Gündoğar
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

from pyocd.commands.execution_context import CommandExecutionContext


class TestCommandLineSplitting:
    """Each command line must be split into words exactly once."""

    def _parse(self, line):
        ctx = CommandExecutionContext(no_init=True)
        commands = list(ctx._split_commands(line))
        assert len(commands) == 1
        return commands[0], ctx.parse_command(commands[0])

    def test_quoted_arg_with_operator_chars(self):
        words, invoc = self._parse("help '/a/mfw-nr+_nrf91x1_1.0.1.zip'")
        assert words == ['help', '/a/mfw-nr+_nrf91x1_1.0.1.zip']
        assert list(invoc.args) == ['/a/mfw-nr+_nrf91x1_1.0.1.zip']

    def test_escaped_operator_char(self):
        _, invoc = self._parse(r"help /a/mfw-nr\+_nrf91x1_1.0.1.zip")
        assert list(invoc.args) == ['/a/mfw-nr+_nrf91x1_1.0.1.zip']

    def test_unquoted_operator_chars_still_split(self):
        _, invoc = self._parse("help a+b")
        assert list(invoc.args) == ['a', '+', 'b']
