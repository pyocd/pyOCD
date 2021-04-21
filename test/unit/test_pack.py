# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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
import cmsis_pack_manager
import os
import zipfile
from xml.etree import ElementTree
from pathlib import Path

from pyocd.target.pack import (cmsis_pack, flash_algo, pack_target)
from pyocd.target import TARGET
from pyocd.core import (memory_map, target)

K64F = "MK64FN1M0VDC12"
NRF5340 = "nRF5340_xxAA"
STM32L4R5 = "STM32L4R5AGIx"

TEST_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "packs"
K64F_PACK_PATH = TEST_DATA_DIR / "NXP.MK64F12_DFP.11.0.0.pack"
K64F_1M0_FLM = "arm/MK_P1M0.FLM"
NRF_PDSC_PATH = TEST_DATA_DIR / "NordicSemiconductor.nRF_DeviceFamilyPack.8.38.0.pdsc"
STM32L4_PDSC_PATH = TEST_DATA_DIR / "Keil.STM32L4xx_DFP.2.5.0.pdsc"

@pytest.fixture(scope='module')
def pack_ref():
    return cmsis_pack_manager.CmsisPackRef(
                "NXP",
                "MK64F12_DFP",
                "11.0.1",
            )

@pytest.fixture(scope='module')#, autouse=True)
def cache(tmpdir_factory, pack_ref):
    tmp_path = str(tmpdir_factory.mktemp("cpm"))
    c = cmsis_pack_manager.Cache(False, False, json_path=tmp_path, data_path=tmp_path)
    c.download_pack_list([pack_ref])
    return c

@pytest.fixture(scope='module')
def k64dev(cache):
    devs = pack_target.ManagedPacks.get_installed_targets()
    return [d for d in devs if d.part_number == K64F].pop()

@pytest.fixture()#autouse=True)
def fixed_installed_packs(monkeypatch, pack_ref):
    def my_get_installed_packs(cache=None):
        return [pack_ref]
    monkeypatch.setattr(pack_target.ManagedPacks,  'get_installed_packs', my_get_installed_packs)

@pytest.fixture(scope='function')
def k64pack():
    return cmsis_pack.CmsisPack(K64F_PACK_PATH)

@pytest.fixture(scope='function')
def k64f1m0(k64pack):
    return [d for d in k64pack.devices if d.part_number == "MK64FN1M0VLL12"].pop()

@pytest.fixture(scope='function')
def k64algo(k64pack):
    flm = k64pack.get_file(K64F_1M0_FLM)
    return flash_algo.PackFlashAlgo(flm)

# Replacement for CmsisPackDevice._load_flash_algo() that loads the FLM from the test data dir
# instead of the (unset) CmsisPack object.
def load_test_flm(filename):
    p = TEST_DATA_DIR / Path(filename).name
    return flash_algo.PackFlashAlgo(p.open('rb'))

@pytest.fixture(scope='function')
def nrfpdsc():
    return cmsis_pack.CmsisPackDescription(None, NRF_PDSC_PATH)

# Fixture to provide nRF5340 CmsisPackDevice modified to load FLM from test data dir.
@pytest.fixture(scope='function')
def nrf5340(monkeypatch, nrfpdsc):
    dev = [d for d in nrfpdsc.devices if d.part_number == NRF5340].pop()
    monkeypatch.setattr(dev, '_load_flash_algo', load_test_flm)
    return dev

@pytest.fixture(scope='function')
def stm32l4pdsc():
    return cmsis_pack.CmsisPackDescription(None, STM32L4_PDSC_PATH)

# Fixture to provide STM32L4R5 CmsisPackDevice modified to load FLM from test data dir.
@pytest.fixture(scope='function')
def stm32l4r5(monkeypatch, stm32l4pdsc):
    dev = [d for d in stm32l4pdsc.devices if d.part_number == STM32L4R5].pop()
    monkeypatch.setattr(dev, '_load_flash_algo', load_test_flm)
    return dev

# Tests for managed packs. Currently disabled as they fail on most systems.
class Disabled_TestPack(object):
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
        
class TestPack(object):
    def test_devices(self, k64pack):
        devs = k64pack.devices
        pns = [x.part_number for x in devs]
        assert "MK64FN1M0xxx12" in pns
        assert "MK64FX512xxx12" in pns
    
    # Make sure CmsisPack can open a zip file too.
    def test_zipfile(self):
        z = zipfile.ZipFile(K64F_PACK_PATH, 'r')
        p = cmsis_pack.CmsisPack(z)
        pns = [x.part_number for x in p.devices]
        assert "MK64FN1M0xxx12" in pns

    def test_parse_device_info(self, k64f1m0):
        assert k64f1m0.vendor == "NXP"
        assert k64f1m0.families == ["MK64F12"]
        assert k64f1m0.default_reset_type == target.Target.ResetType.SW
    
    def test_get_svd(self, k64f1m0):
        svd = k64f1m0.svd
        x = ElementTree.parse(svd)
        assert x.getroot().tag == 'device'
    
    def test_mem_map(self, k64f1m0):
        map = k64f1m0.memory_map
        bm = map.get_boot_memory()
        assert bm.start == 0 and bm.length == 1 * 1024 * 1024
        ram = map.get_default_region_of_type(memory_map.MemoryType.RAM)
        assert ram.start == 0x20000000 and ram.length == 0x30000
    
    # Verify the flash region was converted correctly.
    def test_flash(self, k64f1m0):
        map = k64f1m0.memory_map
        flash = map.get_boot_memory()
        assert isinstance(flash, memory_map.FlashRegion)
        assert flash.start == 0 and flash.length == 1 * 1024 * 1024
        assert flash.sector_size == 4096
    
class TestFLM(object):
    def test_algo(self, k64algo):
        i = k64algo.flash_info
#         print(i)
        assert i.type == 1
        assert i.start == 0
        assert i.size == 1 * 1024 * 1024
        assert i.page_size == 512
        assert i.sector_info_list == [(0, 4 * 1024)]
    
    def test_algo_dict(self, k64algo, k64f1m0):
        map = k64f1m0.memory_map
        ram = map.get_default_region_of_type(memory_map.MemoryType.RAM)
        d = k64algo.get_pyocd_flash_algo(4096, ram)
#         print(len(d['instructions']) * 4)
#         del d['instructions']
#         print(d)
        STACK_SIZE = 0x200
        assert d['load_address'] == ram.start + STACK_SIZE
        assert d['pc_init'] == ram.start + STACK_SIZE + 0x21
        assert d['pc_unInit'] == ram.start + STACK_SIZE + 0x71
        assert d['pc_eraseAll'] == ram.start + STACK_SIZE + 0x95
        assert d['pc_erase_sector'] == ram.start + STACK_SIZE + 0xcb
        assert d['pc_program_page'] == ram.start + STACK_SIZE + 0xdf
        
def has_overlapping_regions(memmap):
    return any((len(memmap.get_intersecting_regions(r.start, r.end)) > 1) for r in memmap.regions)

class TestNRF():
    def test_regions(self, nrf5340):
        memmap = nrf5340.memory_map
        assert not has_overlapping_regions(memmap)
        
class TestSTM32L4():
    def test_regions(self, stm32l4r5):
        memmap = stm32l4r5.memory_map
        assert not has_overlapping_regions(memmap)
