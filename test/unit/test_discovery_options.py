# -*- coding: utf8 -*-
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

from unittest.mock import Mock

import pytest

from pyocd.__main__ import PyOCDTool
from pyocd.core.session import Session
from pyocd.probe.aggregator import DebugProbeAggregator
from pyocd.probe.pydapaccess import dap_access_cmsis_dap as dap


@pytest.mark.parametrize('command', [['reset'], ['load', 'firmware.bin']])
@pytest.mark.parametrize('configured, override, expected', [
    (False, 'true', 'v1'), (True, 'false', 'v2'), (True, None, 'v1'), (False, None, 'v2')])
def test_cli_options_apply_before_interface_selection(monkeypatch, tmp_path, command, configured, override, expected):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Session, '_current_session', None)
    monkeypatch.setattr(Session, '_options_session', None)
    (tmp_path / 'pyocd.yaml').write_text(f'cmsis_dap.prefer_v1: {str(configured).lower()}\n')
    v1 = Mock(name='v1')
    v2 = Mock(name='v2')
    v1.get_serial_number.return_value = v2.get_serial_number.return_value = '1234'
    backend1, backend2 = Mock(), Mock()
    backend1.get_all_connected_interfaces.side_effect = lambda: [v1]
    backend2.get_all_connected_interfaces.side_effect = lambda: [v2]
    monkeypatch.setattr(dap, 'INTERFACE', {'v1': backend1, 'v2': backend2})
    monkeypatch.setattr(dap, 'USB_BACKEND', 'v1')
    monkeypatch.setattr(dap, 'USB_BACKEND_V2', 'v2')
    observed = []

    def discover(unique_id=None):
        observed.extend(dap._get_interfaces())
        return []  # Stop before creating/opening any physical probe.

    monkeypatch.setattr(DebugProbeAggregator, 'get_all_connected_probes', discover)
    args = command + ['-W']
    if override is not None:
        args += ['-O', 'cmsis_dap.prefer_v1=' + override]
    monkeypatch.setattr(PyOCDTool, '_setup_logging', lambda self: None)
    try:
        status = PyOCDTool().run(args)
    except SystemExit as exc:
        status = exc.code
    assert status == 1
    assert observed == [v1 if expected == 'v1' else v2]
