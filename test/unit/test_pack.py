# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
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
import cmsis_pack_manager
import zipfile
from xml.etree import ElementTree
from pathlib import Path
from unittest.mock import MagicMock

from pyocd.target.pack import (cmsis_pack, flash_algo, pack_target)
from pyocd.target.pack.flm_region_builder import FlmFlashRegionBuilder
from pyocd.target import TARGET
from pyocd.core import memory_map
from pyocd.utility.mask import align_down
from pyocd.coresight.ap import APv1Address

K64F = "MK64FN1M0VDC12"
NRF5340 = "nRF5340_xxAA"
STM32L4R5 = "STM32L4R5AGIx"
LPC55S36 = "LPC55S36JBD100"

TEST_DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "packs"
K64F_PACK_PATH = TEST_DATA_DIR / "NXP.MK64F12_DFP.11.0.0.pack"
K64F_1M0_FLM = "arm/MK_P1M0.FLM"
STM32F4_2M0_FLM = TEST_DATA_DIR / "STM32F4xx_2048.FLM"
NRF5340_APP_FLM = TEST_DATA_DIR / "nrf53xx_application.flm"
NRF_PDSC_PATH = TEST_DATA_DIR / "NordicSemiconductor.nRF_DeviceFamilyPack.8.38.0.pdsc"
STM32L4_PDSC_PATH = TEST_DATA_DIR / "Keil.STM32L4xx_DFP.2.5.0.pdsc"
TEST1_PDSC_PATH = TEST_DATA_DIR / "Test1.pdsc"
TEST2_PDSC_PATH = TEST_DATA_DIR / "Test2_algo_overlaps_alias.pdsc"
LPC55S36_PDSC_PATH = TEST_DATA_DIR / "NXP.LPC55S36_DFP.13.0.0.pdsc"

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

@pytest.fixture(scope='function')
def nrf5340appflm():
    return flash_algo.PackFlashAlgo(open(NRF5340_APP_FLM, 'rb'))

@pytest.fixture(scope='function')
def stm32f42mflm():
    return flash_algo.PackFlashAlgo(open(STM32F4_2M0_FLM, 'rb'))

# Replacement for CmsisPackDevice._load_flash_algo() that loads the FLM from the test data dir
# instead of the (unset) CmsisPack object.
def load_test_flm(filename):
    p = TEST_DATA_DIR / Path(filename).name
    return p.open('rb')

@pytest.fixture(scope='function')
def nrfpdsc():
    return cmsis_pack.CmsisPackDescription(None, open(NRF_PDSC_PATH, 'rb')) # type:ignore

@pytest.fixture(scope='function')
def test2pdsc():
    return cmsis_pack.CmsisPackDescription(None, open(TEST2_PDSC_PATH, 'rb')) # type:ignore

@pytest.fixture(scope='function')
def test2dev(test2pdsc):
    dev = test2pdsc.devices[0]
    dev._get_pack_file_cb = load_test_flm
    return dev

@pytest.fixture(scope='function')
def test1pdsc():
    return cmsis_pack.CmsisPackDescription(None, TEST1_PDSC_PATH)

@pytest.fixture(scope='function')
def test1dev(test1pdsc):
    return test1pdsc.devices[0]

# Fixture to provide nRF5340 CmsisPackDevice modified to load FLM from test data dir.
@pytest.fixture(scope='function')
def nrf5340(nrfpdsc):
    dev = [d for d in nrfpdsc.devices if d.part_number == NRF5340].pop()
    dev._get_pack_file_cb = load_test_flm
    return dev

@pytest.fixture(scope='function')
def stm32l4pdsc():
    return cmsis_pack.CmsisPackDescription(None, open(STM32L4_PDSC_PATH, 'rb')) # type:ignore

# Fixture to provide STM32L4R5 CmsisPackDevice modified to load FLM from test data dir.
@pytest.fixture(scope='function')
def stm32l4r5(stm32l4pdsc):
    dev = [d for d in stm32l4pdsc.devices if d.part_number == STM32L4R5].pop()
    dev._get_pack_file_cb = load_test_flm
    return dev

@pytest.fixture(scope='function')
def lpc55s36pdsc():
    return cmsis_pack.CmsisPackDescription(None, open(LPC55S36_PDSC_PATH, 'rb')) # type:ignore

# Fixture to provide STM32L4R5 CmsisPackDevice modified to load FLM from test data dir.
@pytest.fixture(scope='function')
def lpc55s36(lpc55s36pdsc):
    dev = [d for d in lpc55s36pdsc.devices if d.part_number == LPC55S36].pop()
    dev._get_pack_file_cb = load_test_flm
    return dev

# Tests for managed packs. Currently disabled as they fail on most systems.
class Disabled_TestPack:
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

class TestPack:
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
    # Note that the sector size will be 0 because CmsisPackDevice just prepares the flash region
    # for processing by FlmFlashRegionBuilder.
    def test_flash(self, k64f1m0):
        map = k64f1m0.memory_map
        flash = map.get_boot_memory()
        assert isinstance(flash, memory_map.FlashRegion)
        assert flash.start == 0 and flash.length == 1 * 1024 * 1024
        # assert flash.sector_size == 4096

class TestFLM:
    def test_algo(self, k64algo):
        i = k64algo.flash_info
#         print(i)
        assert i.type == 1
        assert i.start == 0
        assert i.size == 1 * 1024 * 1024
        assert i.page_size == 512
        assert i.sector_info_list == [(0, 4 * 1024)]

    def test_algo_dict_entry_points(self, k64algo):
        # Create the RAM region where we want the algo to be placed.
        ram = memory_map.RamRegion(0x20000000, length=0x10000)
        d = k64algo.get_pyocd_flash_algo(4096, ram)
        instr_len = len(d['instructions']) * 4
        load_addr = ram.end + 1 - instr_len
        assert d['load_address'] == load_addr
        assert d['pc_init'] == load_addr + 0x5
        assert d['pc_unInit'] == load_addr + 0x55
        assert d['pc_eraseAll'] == load_addr + 0x79
        assert d['pc_erase_sector'] == load_addr + 0xaf
        assert d['pc_program_page'] == load_addr + 0xc3

    def test_algo_dict_two_page_bufs(self, k64algo):
        # Create the RAM region where we want the algo to be placed.
        ram = memory_map.RamRegion(0x20000000, length=0x10000)
        d = k64algo.get_pyocd_flash_algo(k64algo.page_size, ram)
        instr_base = d['load_address']
        buf_top = align_down(instr_base, flash_algo.PackFlashAlgo._PAGE_BUFFER_ALIGN)
        buf1 = buf_top - k64algo.page_size
        buf2 = buf1 - k64algo.page_size
        assert d['page_buffers'] == [buf1, buf2]

    def test_algo_dict_one_page_buf(self, k64algo):
        # First get a full-sized algo allocation.
        ram = memory_map.RamRegion(0x20000000, length=0x10000)
        d = k64algo.get_pyocd_flash_algo(k64algo.page_size, ram)

        # Create a memory region with only enough memory for one page buf + stack.
        min_ram_size = len(d['instructions']) * 4 + k64algo.page_size + k64algo.page_size // 2
        min_ram = memory_map.RamRegion(0x20000000, length=min_ram_size)
        d = k64algo.get_pyocd_flash_algo(k64algo.page_size, min_ram)

        instr_base = d['load_address']
        assert instr_base == min_ram.end + 1 - len(d['instructions']) * 4
        buf_top = align_down(instr_base, flash_algo.PackFlashAlgo._PAGE_BUFFER_ALIGN)
        buf1 = buf_top - k64algo.page_size
        assert d['page_buffers'] == [buf1]

    # Flash Device:
    #   name=b'nRF53xxx_app'
    #   version=0x101
    #   type=1
    #   start=0x0
    #   size=0x200000
    #   page_size=0x1000
    #   value_empty=0xff
    #   prog_timeout_ms=1000
    #   erase_timeout_ms=3000
    #   sectors:
    #     start=0x0, size=0x1000
    def test_iter_sector_sizes_single(self, nrf5340appflm):
        sector_sizes = list(nrf5340appflm.iter_sector_size_ranges())
        assert sector_sizes == [
            (memory_map.MemoryRange(0x0000000, length=0x200000), 0x1000),
        ]

    # Flash Device:
    #   name=b'STM32F4xx 2MB Flash'
    #   version=0x101
    #   type=1
    #   start=0x8000000
    #   size=0x200000
    #   page_size=0x400
    #   value_empty=0xff
    #   prog_timeout_ms=100
    #   erase_timeout_ms=6000
    #   sectors:
    #     start=0x0, size=0x4000
    #     start=0x10000, size=0x10000
    #     start=0x20000, size=0x20000
    #     start=0x100000, size=0x4000
    #     start=0x110000, size=0x10000
    #     start=0x120000, size=0x20000
    def test_iter_sector_sizes_multiple(self, stm32f42mflm):
        sector_sizes = list(stm32f42mflm.iter_sector_size_ranges())
        assert sector_sizes == [
            (memory_map.MemoryRange(0x8000000, length=0x10000), 0x4000),
            (memory_map.MemoryRange(0x8010000, length=0x10000), 0x10000),
            (memory_map.MemoryRange(0x8020000, length=(0x100000 - 0x20000)), 0x20000),
            (memory_map.MemoryRange(0x8100000, length=0x10000), 0x4000),
            (memory_map.MemoryRange(0x8110000, length=0x10000), 0x10000),
            (memory_map.MemoryRange(0x8120000, length=(0x100000 - 0x20000)), 0x20000),
        ]

class TestFlmRegionBuilder:
    @pytest.fixture(scope='module')
    def builder(self):
        mock_target = MagicMock()
        mock_target.part_number = "TestPartNumber"
        ram = memory_map.RamRegion(0x20000000, length=0x10000, is_default=True)
        ram2 = memory_map.RamRegion(0x30010000, length=0x10000, is_default=False)
        memmap = memory_map.MemoryMap(ram, ram2)
        builder = FlmFlashRegionBuilder(mock_target, memmap)
        return builder

    def test_single_sector_size(self, builder: FlmFlashRegionBuilder, nrf5340appflm):
        flash = memory_map.FlashRegion(0, length=0x200000, flm=nrf5340appflm)
        assert builder.finalise_region(flash)
        assert not flash.has_subregions
        assert flash.sector_size == 0x1000

    def test_multiple_sector_size(self, builder: FlmFlashRegionBuilder, stm32f42mflm):
        flash = memory_map.FlashRegion(0x08000000, length=0x200000, flm=stm32f42mflm)
        assert builder.finalise_region(flash)
        assert flash.has_subregions
        submap = flash.submap
        assert submap.region_count == 6
        assert submap[0].sector_size == 0x4000
        assert submap[1].sector_size == 0x10000
        assert submap[2].sector_size == 0x20000
        assert submap[3].sector_size == 0x4000
        assert submap[4].sector_size == 0x10000
        assert submap[5].sector_size == 0x20000

    def test_ram_select_default(self, builder: FlmFlashRegionBuilder, nrf5340appflm):
        flash = memory_map.FlashRegion(0, length=0x200000, flm=nrf5340appflm)
        builder.finalise_region(flash)
        assert flash.algo
        instr_len = len(flash.algo['instructions']) * 4
        assert flash.algo['load_address'] == (0x20010000 - instr_len)
        assert not flash.has_subregions
        assert flash.algo

    def test_ram_select_explicit(self, builder: FlmFlashRegionBuilder, nrf5340appflm):
        flash = memory_map.FlashRegion(0, length=0x200000, flm=nrf5340appflm,
                                        _RAMstart=0x30010000, _RAMsize=0x4000)
        assert builder.finalise_region(flash)
        assert flash.algo
        instr_len = len(flash.algo['instructions']) * 4
        assert flash.algo['load_address'] == (0x30014000 - instr_len)
        assert not flash.has_subregions
        assert flash.algo

def has_overlapping_regions(memmap):
    return any((len(memmap.get_intersecting_regions(r.start, r.end)) > 1) for r in memmap.regions)

class TestNRF:
    def test_regions(self, nrf5340):
        memmap = nrf5340.memory_map
        assert not has_overlapping_regions(memmap)

class TestSTM32L4:
    def test_regions(self, stm32l4r5):
        memmap = stm32l4r5.memory_map
        assert not has_overlapping_regions(memmap)

class TestLPC55S36:
    def test_regions(self, lpc55s36):
        import pprint
        memmap = lpc55s36.memory_map
        print("memory map:")
        pprint.pprint(memmap.regions)
        assert not has_overlapping_regions(memmap)

class TestAlgoOverlappingAliasRegion:
    def test_regions(self, test2dev):
        import pprint
        memmap = test2dev.memory_map
        print("memory map:")
        pprint.pprint(memmap.regions)
        assert not has_overlapping_regions(memmap)
        # assert False

class TestAPID:
    def test1_dp(self, test1dev):
        assert test1dev.valid_dps == [0]

    def test1_procs(self, test1dev):
        procs = test1dev.processors_map
        m4 = procs['CM4']
        assert m4.name == 'CM4'
        assert m4.ap_address == APv1Address(0)
        assert m4.svd_path == "cm4.svd"
        m0p = procs['CM0p']
        assert m0p.name == 'CM0p'
        assert m0p.ap_address == APv1Address(2)
        assert m0p.svd_path == "cm0p.svd"

