# pyOCD debugger
# Copyright (c) 2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import pytest
import six
from unittest import mock

from .test_rom_table import (MockCoreSightComponent, MockCoreSight, MockCSSOC600Components)

from pyocd.coresight.ap import AccessPort
from pyocd.coresight.sdc600 import SDC600
from pyocd.coresight.rom_table import CoreSightComponentID

MockAP = mock.Mock(spec=AccessPort)

@pytest.fixture(scope='function')
def sdc():
    cs = MockCoreSight([MockCSSOC600Components.SDC600])
    # Add SDC-600 register values.
    cs.write_memory_block32(0xd00, [
        0x00000000, # VIDR     = 0xD00
        0,          #            0xD04
        0x00000411, # FIDTXR   = 0xD08
        0x00000401, # FIDRXR   = 0xD0C
        0x00000000, # ICSR     = 0xD10
        0,          #            0xD14
        0,          #            0xD18
        0,          #            0xD1C
        0x00000000, # DR       = 0xD20
        0,          #            0xD24
        0,          #            0xD28
        0x80011001, # SR       = 0xD2C
        0x00000000, # DBR      = 0xD30
        0,          #            0xD34
        0,          #            0xD38
        0x80011001, # SR_ALIAS = 0xD3C
        ])
    cmpid = CoreSightComponentID(None, cs, MockCSSOC600Components.SDC600_BASE)
    sdc600 = SDC600(cs, cmpid, 0x1000)
    sdc600.init()
    return sdc600

# Flag bytes
FLAGS = [i for i in range(0xa0, 0xc0)]

class TestSDC600:
    # Verify non-flag bytes are not escaped.
    def test_stuff_nonflag(self, sdc):
        print(FLAGS)
        for i in range(256):
            # Skip flag bytes.
            if i in FLAGS:
                continue
            assert sdc._stuff([i]) == [i]

    # Verify non-flag bytes are not de-escaped.
    def test_destuff_nonflag(self, sdc):
        for i in range(256):
            # Skip flag bytes.
            if i in FLAGS:
                continue
            assert sdc._destuff([i]) == [i]
    
    # Test stuffing a single byte.
    def test_stuff_flag(self, sdc):
        for i in FLAGS:
            assert sdc._stuff([i]) == [SDC600.Flag.ESC, i ^ 0x80]
            assert sdc._stuff([i]) == [SDC600.Flag.ESC, i & ~0x80]

    # Test destuffing a single escaped byte.
    def test_destuff_flag(self, sdc):
        for i in FLAGS:
            assert sdc._destuff([SDC600.Flag.ESC, i ^ 0x80]) == [i]
            assert sdc._destuff([SDC600.Flag.ESC, i & ~0x80]) == [i]


