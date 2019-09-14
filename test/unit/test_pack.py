# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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
import cmsis_pack_manager

from pyocd.target.pack import (cmsis_pack, flash_algo, pack_target)
from pyocd.target import TARGET
from pyocd.core import memory_map

K64F = "MK64FN1M0VDC12"

@pytest.fixture(scope='module')
def pack_ref():
    return cmsis_pack_manager.CmsisPackRef(
                "NXP",
                "MK64F12_DFP",
                "11.0.1",
            )

@pytest.fixture(scope='module', autouse=True)
def cache(tmpdir_factory, pack_ref):
    tmp_path = str(tmpdir_factory.mktemp("cpm"))
    c = cmsis_pack_manager.Cache(False, False, json_path=tmp_path, data_path=tmp_path)
    c.download_pack_list([pack_ref])
    return c

@pytest.fixture(scope='module')
def k64dev(cache):
    devs = pack_target.ManagedPacks.get_installed_targets()
    return [d for d in devs if d.part_number == K64F].pop()

@pytest.fixture(autouse=True)
def fixed_installed_packs(monkeypatch, pack_ref):
    def my_get_installed_packs(cache=None):
        return [pack_ref]
    monkeypatch.setattr(pack_target.ManagedPacks,  'get_installed_packs', my_get_installed_packs)

class TestPack(object):
    def test_get_installed(self, pack_ref):
        p = pack_target.ManagedPacks.get_installed_packs()
        assert p == [pack_ref]
    
    def test_get_targets(self, k64dev):
        assert k64dev.part_number == K64F
    
    def test_pop_managed_k64(self):
        pack_target.ManagedPacks.populate_target(K64F)
        assert K64F.lower() in TARGET
    
    def test_k64_mem_map(self, k64dev):
        map = k64dev.memory_map
        raml = map.get_region_for_address(0x1fff0000)
        ramu = map.get_region_for_address(0x20000000)
        flash = map.get_default_region_of_type(memory_map.MemoryType.FLASH)
        assert raml.start == 0x1fff0000 and raml.length == 0x10000
        assert ramu.start == 0x20000000 and ramu.length == 0x30000
        assert flash.start == 0 and flash.length == 0x100000
        assert flash.sector_size == 0x1000
        

        
