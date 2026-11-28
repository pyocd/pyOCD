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

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.core.helpers import ConnectHelper
from pyocd.probe import aggregator
from pyocd.probe.jlink_probe import JLinkProbe


@pytest.fixture
def jlink_only(monkeypatch):
    sdk = Mock()
    sdk.connected_emulators.return_value = [
        SimpleNamespace(SerialNumber=820102635, acProduct=b'J-Link'),
        SimpleNamespace(SerialNumber=682561275, acProduct=b'J-Link'),
    ]
    monkeypatch.setattr(JLinkProbe, '_get_jlink', staticmethod(lambda: sdk))
    monkeypatch.setattr(aggregator, 'PROBE_CLASSES', {'jlink': JLinkProbe})
    return sdk


@pytest.mark.parametrize('query,expected', [
    ('000820102635', ['820102635']),
    ('000682561275', ['682561275']),
    ('jlink:000820102635', ['820102635']),
    ('820102635', ['820102635']),
    ('682561275', ['682561275']),
    ('561', ['682561275']),
    ('000999999999', []),
    ('not-a-serial', []),
    ('', ['820102635', '682561275']),
])
def test_jlink_serial_selection(jlink_only, query, expected):
    probes = ConnectHelper.get_all_connected_probes(blocking=False, unique_id=query)
    assert sorted(p.unique_id for p in probes) == sorted(expected)
    assert all(isinstance(p, JLinkProbe) for p in probes)


def test_listing_preserves_sdk_serial_format(jlink_only):
    probes = ConnectHelper.get_all_connected_probes(blocking=False)
    assert sorted(p.unique_id for p in probes) == ['682561275', '820102635']
