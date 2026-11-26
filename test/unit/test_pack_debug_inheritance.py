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

"""Common debug attributes apply to processor-specific connections."""
import io

import pytest

from pyocd.coresight.ap import APv1Address
from pyocd.target.pack.cmsis_pack import CmsisPackDescription


def parse_device(debugs, family_debugs='', other_devices=''):
    xml = f'''<package><name>Test</name><devices>
      <family Dfamily="Test" Dvendor="Generic:0">
        <processor Pname="CORE0" Dcore="Cortex-M3"/>
        <processor Pname="CORE1" Dcore="Cortex-M3"/>
        {family_debugs}
        <device Dname="SNC733xx">{debugs}</device>
        {other_devices}
      </family></devices></package>'''
    return CmsisPackDescription(None, io.BytesIO(xml.encode())).devices


@pytest.mark.parametrize('common_first, at_family', [(True, True), (True, False), (False, False)])
def test_common_svd_is_inherited_by_each_processor(common_first, at_family):
    common = '<debug svd="SVD/SN_M3B.svd"/>'
    specific = ('<debug Pname="CORE0" __ap="0" defaultResetSequence="ResetProcessor"/>'
                '<debug Pname="CORE1" __ap="1" defaultResetSequence="ResetProcessor"/>')
    debugs = specific if at_family else (common + specific if common_first else specific + common)
    device = parse_device(debugs, common if at_family else '')[0]
    for i in range(2):
        proc = device.processors_map[f'CORE{i}']
        assert proc.svd_path == 'SVD/SN_M3B.svd'
        assert proc.ap_address == APv1Address(i)
        assert proc.default_reset_sequence == 'ResetProcessor'


def test_specific_svd_overrides_common_without_affecting_other_processor():
    device = parse_device('<debug Pname="CORE0" __ap="0" svd="core0.svd"/>'
                          '<debug Pname="CORE1" __ap="1"/>',
                          '<debug svd="common.svd"/>')[0]
    assert device.processors_map['CORE0'].svd_path == 'core0.svd'
    assert device.processors_map['CORE1'].svd_path == 'common.svd'


def test_child_common_attributes_override_parent_without_losing_processor_addresses():
    device = parse_device('<debug svd="device.svd"/>',
                          '<debug Pname="CORE0" __ap="0" svd="family.svd"/>'
                          '<debug Pname="CORE1" __ap="1" svd="family.svd"/>')[0]
    for i in range(2):
        proc = device.processors_map[f'CORE{i}']
        assert proc.svd_path == 'device.svd'
        assert proc.ap_address == APv1Address(i)


def test_named_only_debugs_keep_independent_settings():
    device = parse_device('<debug Pname="CORE0" __ap="0" svd="core0.svd"/>'
                          '<debug Pname="CORE1" __ap="1" svd="core1.svd"/>')[0]
    for i in range(2):
        proc = device.processors_map[f'CORE{i}']
        assert proc.svd_path == f'core{i}.svd'
        assert proc.ap_address == APv1Address(i)


def test_common_only_debug_keeps_svd():
    device = parse_device('<debug svd="common.svd"/>')[0]
    assert device.processors_map['CORE0'].svd_path == 'common.svd'


def test_no_debug_elements_leave_connection_defaults_unchanged():
    device = parse_device('')[0]
    assert device._info.debugs == []


def test_sibling_devices_do_not_inherit_each_others_overrides():
    first, second = parse_device(
        '<debug Pname="CORE0" svd="first.svd"/>',
        '<debug svd="family.svd"/>',
        '<device Dname="SECOND"><debug Pname="CORE0" __ap="2"/></device>')
    assert first.processors_map['CORE0'].svd_path == 'first.svd'
    assert second.processors_map['CORE0'].svd_path == 'family.svd'
    assert second.processors_map['CORE0'].ap_address == APv1Address(2)
