# pyOCD debugger
# Copyright (c) 2026 Solarboaters
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.core.options_manager import OptionsManager
from pyocd.probe.debug_probe import DebugProbe
from pyocd.probe.jlink_probe import JLinkProbe, JLinkInterfaces


@pytest.mark.parametrize('protocol', [DebugProbe.Protocol.JTAG, DebugProbe.Protocol.SWD])
@pytest.mark.parametrize('frequency', [100_000, 1_000_000, 1_500_000])
def test_named_device_uses_configured_connection_frequency(monkeypatch, protocol, frequency):
    link = Mock()
    link.connected_emulators.return_value = [SimpleNamespace(SerialNumber=1234, acProduct=b'J-Link')]
    link.version = '9.22'
    link.supported_tifs.return_value = (1 << JLinkInterfaces.JTAG) | (1 << JLinkInterfaces.SWD)
    monkeypatch.setattr(JLinkProbe, '_get_jlink', classmethod(lambda cls: link))
    probe = JLinkProbe('1234')
    options = OptionsManager()
    options.add_front({'frequency': frequency, 'jlink.device': 'Cortex-M4'})
    probe.session = SimpleNamespace(options=options)
    probe.open()
    probe.set_clock(frequency)

    # A low-speed-only target cannot connect if pylink resets the speed to 'auto'.
    def connect(device, speed='auto'):
        assert speed == frequency // 1000
        assert device == 'Cortex-M4'

    link.connect.side_effect = connect
    probe.connect(protocol)
    link.set_speed.assert_called_once_with(frequency // 1000)
    link.coresight_configure.assert_called_once_with()
    assert probe.wire_protocol == protocol


def test_unnamed_device_does_not_use_pylink_connect(monkeypatch):
    link = Mock()
    link.connected_emulators.return_value = [SimpleNamespace(SerialNumber=1234, acProduct=b'J-Link')]
    link.version = '9.22'
    link.supported_tifs.return_value = 1 << JLinkInterfaces.SWD
    monkeypatch.setattr(JLinkProbe, '_get_jlink', classmethod(lambda cls: link))
    probe = JLinkProbe('1234')
    probe.session = SimpleNamespace(options=OptionsManager())
    probe.open()
    probe.connect()
    link.connect.assert_not_called()
    link.coresight_configure.assert_called_once_with()
