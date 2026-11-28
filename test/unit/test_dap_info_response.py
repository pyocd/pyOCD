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

from pyocd.core.helpers import ConnectHelper
from pyocd.core.session import Session
from pyocd.probe.cmsis_dap_probe import CMSISDAPProbe
from pyocd.probe.pydapaccess.cmsis_dap_core import CMSISDAPProtocol
from pyocd.probe.pydapaccess.dap_access_api import DAPAccessIntf
from pyocd.probe.pydapaccess.dap_access_cmsis_dap import DAPAccessCMSISDAP


ID = DAPAccessIntf.ID


@pytest.mark.parametrize('response', [b'', b'\x00', b'\x00\x01', b'\x00\x02\x01', b'\x00\x04\x01\x02\x03'])
def test_truncated_info_is_a_device_error(response):
    interface = Mock()
    interface.read.return_value = response
    with pytest.raises(DAPAccessIntf.DeviceError):
        CMSISDAPProtocol(interface).dap_info(ID.MAX_PACKET_COUNT)
    interface.write.assert_called_once_with([0, ID.MAX_PACKET_COUNT.value])


@pytest.mark.parametrize('info,response,expected', [
    (ID.MAX_PACKET_COUNT, b'\x00\x01\x01', 1),
    (ID.MAX_PACKET_SIZE, b'\x00\x02\x00\x08', 2048),
    (ID.SWO_BUFFER_SIZE, b'\x00\x04\x78\x56\x34\x12', 0x12345678),
    (ID.MAX_PACKET_COUNT, b'\x00\x01\x01.0' + bytes(59), 1),
    (ID.VENDOR, b'\x00\x04ARM\x00', 'ARM'),
    (ID.VENDOR, b'\x00\x00', None),
])
def test_valid_info(info, response, expected):
    interface = Mock()
    interface.read.return_value = response
    assert CMSISDAPProtocol(interface).dap_info(info) == expected


@pytest.mark.parametrize('info,response', [
    (ID.VENDOR, b'\x00\x04AR'),
    (ID.MAX_PACKET_COUNT, b'\x01\x01\x01'),
    (ID.MAX_PACKET_COUNT, b'\x00\x03\x01\x02\x03'),
])
def test_invalid_info_is_still_rejected(info, response):
    interface = Mock()
    interface.read.return_value = response
    with pytest.raises(DAPAccessIntf.DeviceError):
        CMSISDAPProtocol(interface).dap_info(info)


def test_empty_usb_response_does_not_abort_probe_listing(capsys, monkeypatch):
    # Replace only the USB transport; exercise the reported open/identify/list stack.
    interface = Mock()
    interface.get_serial_number.return_value = 'empty-reply-probe'
    interface.vendor_name = 'Example'
    interface.product_name = 'CMSIS-DAP'
    interface.vid = 0x1234
    interface.pid = 0x5678
    interface.read.return_value = b''
    probe = CMSISDAPProbe(DAPAccessCMSISDAP(None, interface=interface))
    other = Mock(description='Working probe', unique_id='working-probe', associated_board_info=None)
    session = Session(None, options={'cmsis_dap.limit_packets': False}, no_config=True)
    monkeypatch.setattr(Session, 'get_current', staticmethod(lambda: session))
    ConnectHelper._print_probe_list([probe, other])
    output = capsys.readouterr().out
    assert 'empty-reply-probe' in output
    assert 'working-probe' in output
    interface.write.assert_called_once_with([0, ID.MAX_PACKET_COUNT.value])
