# -*- coding: utf-8 -*-
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

import pytest

from pyocd.core.memory_map import MemoryRange
from pyocd.target.pack.cmsis_pack import CmsisPackDescription


def algorithm(name, default, start='0x08000000'):
    return (f'<algorithm name="{name}" start="{start}" size="0x00200000" '
            f'default="{default}"/>')


def device(algorithms, inherited=''):
    xml = ('<package><name>Test</name><vendor>Test</vendor><devices>'
           '<family Dfamily="Test" Dvendor="Test:1">'
           '<processor Dcore="Cortex-M4"/>' + inherited +
           '<device Dname="Chip">' + algorithms + '</device></family></devices></package>')
    return CmsisPackDescription(None, io.BytesIO(xml.encode())).devices[0]


def selected(dev, start=0x08000000):
    return dev._find_matching_algo(MemoryRange(start=start, length=0x1000)).attrib['name']


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('true_value', ['1', 'true'])
def test_stm32_default_dual_bank_algorithm(reverse, true_value):
    # Same-address alternatives in issue #1628.
    records = [algorithm('STM32L4Rx_2048_Dual.FLM', true_value),
               algorithm('STM32L4Rx_2048_Single.FLM', '0')]
    if reverse:
        records.reverse()
    assert selected(device(''.join(records))) == 'STM32L4Rx_2048_Dual.FLM'


def test_imxrt_default_secure_algorithm_is_not_discarded():
    # Secure-range alternatives in issue #1704, alongside a separate range.
    dev = device(algorithm('normal.FLM', '1') +
                 algorithm('MIMXRT6XX_EVK_FLEXSPI_S.FLM', '1', '0x18000000') +
                 algorithm('MIMXRT6XX_FLEXSPI_B_SFDP_QSPI_S.FLM', '0', '0x18000000'))
    assert selected(dev, 0x18000000) == 'MIMXRT6XX_EVK_FLEXSPI_S.FLM'
    assert selected(dev) == 'normal.FLM'


def test_lower_level_still_overrides_parent_default():
    dev = device(algorithm('child.FLM', '0'), algorithm('parent.FLM', '1'))
    assert selected(dev) == 'child.FLM'


@pytest.mark.parametrize('default', ['0', '1'])
def test_equal_priority_retains_last_definition(default):
    dev = device(algorithm('first.FLM', default) + algorithm('last.FLM', default))
    assert selected(dev) == 'last.FLM'
