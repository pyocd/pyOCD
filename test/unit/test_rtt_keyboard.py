# pyOCD debugger
# Copyright (c) 2026 Solarboaters
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

import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.utility import kbhit
from pyocd.subcommands import rtt_cmd


@pytest.fixture
def windows_keyboard(monkeypatch):
    # Replace only the Windows console boundary; retain KBHit and the RTT loop.
    console = Mock()
    monkeypatch.setattr(kbhit, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(kbhit, 'msvcrt', console, raising=False)
    return kbhit.KBHit(), console


@pytest.mark.parametrize('prefix, scan', [('\xe0', 'H'), ('\x00', ';')])
def test_extended_key_is_consumed_without_sending_scan_code(windows_keyboard, prefix, scan):
    keyboard, console = windows_keyboard
    console.getch.side_effect = [prefix.encode('latin1'), scan.encode(), b'a']
    console.getwch.side_effect = [prefix, scan, 'a']
    assert keyboard.getch() == ''
    assert keyboard.getch() == 'a'


@pytest.mark.parametrize('character', ['a', '\r', '\x1b', 'é', '中'])
def test_windows_character_input(windows_keyboard, character):
    keyboard, console = windows_keyboard
    console.getch.return_value = character.encode('gb18030')[:1]
    console.getwch.return_value = character
    assert keyboard.getch() == character


def test_rtt_viewer_ignores_extended_key_and_keeps_text(monkeypatch, windows_keyboard):
    keyboard, console = windows_keyboard
    console.getch.side_effect = [b'\xe0', b'H', b'a', b'\x1b']
    console.getwch.side_effect = ['\xe0', 'H', 'a', '\x1b']
    console.kbhit.return_value = True
    output = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
    monkeypatch.setattr(rtt_cmd, 'sys', SimpleNamespace(stdout=output))
    monkeypatch.setattr(rtt_cmd, 'sleep', lambda seconds: None)
    up = Mock()
    up.read.return_value = b''
    down = Mock()
    down.write.side_effect = len
    command = rtt_cmd.RTTSubcommand.__new__(rtt_cmd.RTTSubcommand)
    command.viewer_loop(up, down, keyboard)
    assert b''.join(call.args[0] for call in down.write.call_args_list) == b'a'
