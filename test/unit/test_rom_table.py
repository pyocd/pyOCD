# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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
import logging
from intervaltree import (Interval, IntervalTree)

from .conftest import mock

from pyocd.coresight.component import CoreSightCoreComponent
from pyocd.core import memory_map
from pyocd.coresight.rom_table import (
    CoreSightComponentID,
    ROMTable,
    )
from pyocd.core.memory_interface import MemoryInterface
from pyocd.debug.cache import MemoryCache
from pyocd.debug.context import DebugContext

class MockCoreForMemCache(CoreSightCoreComponent):
    """! @brief Just enough of a core to satisfy MemoryCache.
    
    Most importantly, it defines a memory map with a single RAM region covering almost the
    full 4 GB address space.
    """
    def __init__(self):
        self.run_token = 1
        self.memory_map = memory_map.MemoryMap(
            memory_map.RamRegion(name="ram", start=0, length=0xf0000000, cacheable=True)
            )

    def is_running(self):
        return False

MockDebugContext = mock.Mock(spec=DebugContext)

class RomMemory(MemoryCache, MemoryInterface):
    """! @brief Memory interface for reading constant values.
    
    Uses the memory cache as readily-available component to store data at fixed addresses. We
    just have to make sure the cache is never invalidated.
    """
    def __init__(self, ranges):
        """! @brief Constructor.
        
        @param self
        @param ranges Dict of start address -> list of word values.
        """
        super(RomMemory, self).__init__(MockDebugContext(), MockCoreForMemCache())
        
        # Fill in cache with data from ranges.
        for addr, data in ranges.items():
            self.write_memory_block32(addr, data)

    def _check_cache(self):
        # Ensure the cache is always valid.
        pass

class MockCoreSight(RomMemory):
    """! @brief RomMemory based on a list of MockCoreSightComponent objects."""
    def __init__(self, components):
        """! @brief Constructor.
        
        @param self
        @param components List of component dicts, where each component dict consists of start
            address -> list of word values.
        """
        ranges = {base: data for c in components for base, data in c.data.items()}
        super(MockCoreSight, self).__init__(ranges)
    
    @property
    def short_description(self):
        return "MockCoreSight"

class MockCoreSightComponent(object):
    """! @brief Generates a data dict from CoreSight component ID register values."""
    
    # Start offset within the 4 kB CoreSight component memory window of the ID registers
    # we care about, particularly those read by CoreSightComponentID.
    CMPID_REGS_OFFSET = 0xfbc
    
    def __init__(self, base, cidr, pidr, **kwargs):
        """! @brief Constructor.
        @param self
        @param base Base address of the component.
        @param cidr 32-bit combined CIDR register value.
        @param pidr 64-bit combined PIDR register value.
        @param kwargs Optional 'devarch', 'devtype', 'devid', and 'extra' keyword arguments. The
            first two are simple integers. 'devid' must be a list of 3 integers. 'extra' is a
            data dictionary (address -> list of 32-bit word values) for any extra fixed data that
            is contained in the component's 4 kB address space (such as a ROM table).
        """
        self._base = base
        self._pidr4_7 = (pidr >> 32)
        self._pidr0_3 = pidr & 0xffffffff
        self._cidr = cidr
        self._devarch = kwargs.get('devarch', 0)
        self._devid = kwargs.get('devid', [0, 0, 0])
        self._devtype = kwargs.get('devtype', 0)
        self._extra = kwargs.get('extra', {})
    
    @property
    def data(self):
        d = self._extra.copy()
        d.update({
            self._base + self.CMPID_REGS_OFFSET: [
                    self._devarch,                  # 0xfbc = DEVARCH
                    self._devid[2],                 # 0xfc0 = DEVID2
                    self._devid[1],                 # 0xfc4 = DEVID1
                    self._devid[0],                 # 0xfc8 = DEVID0
                    self._devtype,                  # 0xfcc = DEVTYPE
                    self._pidr4_7 & 0xff,           # 0xfd0 = PID4
                    (self._pidr4_7 >> 8) & 0xff,    # 0xfd4 = PID5
                    (self._pidr4_7 >> 16) & 0xff,   # 0xfd8 = PID6
                    (self._pidr4_7 >> 24) & 0xff,   # 0xfdc = PID7
                    self._pidr0_3 & 0xff,           # 0xfe0 = PID0
                    (self._pidr0_3 >> 8) & 0xff,    # 0xfe4 = PID1
                    (self._pidr0_3 >> 16) & 0xff,   # 0xfe8 = PID3
                    (self._pidr0_3 >> 24) & 0xff,   # 0xfec = PID3
                    self._cidr & 0xff,              # 0xff0 = CID0
                    (self._cidr >> 8) & 0xff,       # 0xff4 = CID1
                    (self._cidr >> 16) & 0xff,      # 0xff8 = CID2
                    (self._cidr >> 24) & 0xff,      # 0xffc = CID3
                ]
            })
        return d

class MockM4Components:
    """! @ brief Namespace for mock Cortex-M4 Class 0x1 ROM table and core complex components."""
    
    # ROM table #0 @ 0xe00ff000 (designer=244 part=00d)
    M4_ROM_TABLE_BASE = 0xe00ff000
    M4_ROM_TABLE = MockCoreSightComponent(M4_ROM_TABLE_BASE, cidr=0xb105100d, pidr=0x4000bb4c4,
        extra={
            # ROM table entries.
            0xe00ff000: [   0xfff0f003, # SCS
                            0xfff02003, # DWT
                            0xfff03003, # FPB
                            0xfff01003, # ITM
                            0xfff41003, # TPIU
                            0xfff42003, # ETM
                            0x00000000, 0x00000000, 0x00000000, 0x00000000, # (Terminator and extra)
                        ],
        })

    # [0]<e000e000:SCS-M4 class=14 designer=43b part=00c>
    SCS_BASE = 0xe000e000
    SCS = MockCoreSightComponent(SCS_BASE, cidr=0xb105e00d, pidr=0x4000bb00c)

    # [1]<e0001000:DWT class=14 designer=43b part=002>
    DWT_BASE = 0xe0001000
    DWT = MockCoreSightComponent(DWT_BASE, cidr=0xb105e00d, pidr=0x4003bb002)

    # [2]<e0002000:FPB class=14 designer=43b part=003>
    FPB_BASE = 0xe0002000
    FPB = MockCoreSightComponent(FPB_BASE, cidr=0xb105e00d, pidr=0x4002bb003)

    # [3]<e0000000:ITM class=14 designer=43b part=001>
    ITM_BASE = 0xe0000000
    ITM = MockCoreSightComponent(ITM_BASE, cidr=0xb105e00d, pidr=0x4003bb001)

    # [4]<e0040000:TPIU-M4 class=9 designer=43b part=9a1 devtype=11 archid=0000 devid=ca1:0:0>
    TPIU_BASE = 0xe0040000
    TPIU = MockCoreSightComponent(TPIU_BASE, cidr=0xb105900d, pidr=0x4000bb9a1, devtype=0x11, devid=[0xca1, 0, 0])

    # [5]<e0041000:ETM-M4 class=9 designer=43b part=925 devtype=13 archid=0000 devid=0:0:0>
    ETM_BASE = 0xe0041000
    ETM = MockCoreSightComponent(ETM_BASE, cidr=0xb105900d, pidr=0x4000bb925, devtype=0x13)
    
class MockCSSOC600Components:
    """! @ brief Namespace for mock Class 0x9 ROM table and CoreSight SoC-600 components."""
    
    C9_ROM_TABLE_BASE = 0x00000000
    C9_ROM_TABLE = MockCoreSightComponent(C9_ROM_TABLE_BASE, cidr=0xb105900d, pidr=0x4000bb7d5,
        devarch=0x47700af7, devid=[0x20, 0, 0],
        extra={
            # ROM table entries.
            0x00000000: [   0x00001003, # SDC-600
                            0x00002003, # SoC-600 AHB-AP
                            0x00000000, 0x00000000, 0x00000000, 0x00000000, # (Terminator and extra)
                            0x00000000, 0x00000000, 0x00000000, 0x00000000, # (extra)
                        ],
        })
    
    SDC600_BASE = 0x00001000
    SDC600 = MockCoreSightComponent(SDC600_BASE, cidr=0xb105900d, pidr=0x4000bb9ef, devarch=0x47700a57)
    
    C9_AHB_AP_BASE = 0x00002000
    C9_AHB_AP = MockCoreSightComponent(C9_AHB_AP_BASE, cidr=0xb105900d, pidr=0x4002bb9e3, devarch=0x47700a17)
    

# Complete set of components for a Cortex-M4 subsystem.
@pytest.fixture(scope='function')
def m4_rom():
    return MockCoreSight([
                MockM4Components.M4_ROM_TABLE,
                MockM4Components.SCS,
                MockM4Components.DWT,
                MockM4Components.FPB,
                MockM4Components.ITM,
                MockM4Components.TPIU,
                MockM4Components.ETM,
            ])

@pytest.fixture(scope='function')
def c9_top_rom():
    return MockCoreSight([
                MockCSSOC600Components.C9_ROM_TABLE,
                MockCSSOC600Components.SDC600,
                MockCSSOC600Components.C9_AHB_AP,
            ])

@pytest.fixture(scope='function')
def testrom():
    a = {
            0x1000: [1, 2, 3, 4],
            0x4000: [0xaa, 0xbeef],
            0x4400: [0xcccccccc],
        }
    return RomMemory(a)

@pytest.fixture(scope='function')
def testcoresight():
    return MockCoreSight([MockM4Components.M4_ROM_TABLE, MockM4Components.ETM])

class TestRomMemory:
    def test_r32(self, testrom):
        assert testrom.read32(0x1000) == 1
        assert testrom.read32(0x1004) == 2
        assert testrom.read32(0x4004) == 0xbeef
        assert testrom.read32(0x4400) == 0xcccccccc

    def test_r16(self, testrom):
        assert testrom.read16(0x1000) == 1
        assert testrom.read16(0x1002) == 0
        assert testrom.read16(0x4000) == 0xaa
        assert testrom.read16(0x4004) == 0xbeef
        assert testrom.read16(0x4402) == 0xcccc

    def test_r8(self, testrom):
        assert testrom.read8(0x1001) == 0
        assert testrom.read8(0x1003) == 0
        assert testrom.read8(0x1004) == 2
        assert testrom.read8(0x4001) == 0
        assert testrom.read8(0x4004) == 0xef
        assert testrom.read8(0x4005) == 0xbe
        assert testrom.read8(0x4401) == 0xcc

    def test_rb32(self, testrom):
        assert testrom.read_memory_block32(0x1000, 4) == [1, 2, 3, 4]
        assert testrom.read_memory_block32(0x4000, 2) == [0xaa, 0xbeef]

    def test_rb8(self, testrom):
        assert testrom.read_memory_block8(0x1008, 6) == [3, 0, 0, 0, 4, 0]
        assert testrom.read_memory_block8(0x4001, 6) == [0, 0, 0, 0xef, 0xbe, 00]
    
class TestMockCoreSight:
    def test_1(self, testcoresight):
        assert testcoresight.read32(0xe00ff000) == 0xfff0f003
        assert testcoresight.read32(0xe00ff000) == 0xfff0f003
        assert testcoresight.read_memory_block32(0xe00ffff0, 4) == [0xd, 0x10, 0x5, 0xb1]

class TestCoreSightComponentID:
    # Test parsing a non-CoreSight component in isolation.
    def test_scs(self):
        cmp = CoreSightComponentID(None, MockCoreSight([MockM4Components.SCS]),
                MockM4Components.SCS_BASE)
        cmp.read_id_registers()
        assert cmp.component_class == 14
        assert cmp.designer == 0x43b
        assert cmp.part == 0xc
        assert cmp.devarch == 0
        assert cmp.devid == [0, 0, 0]
    
    # Test parsing a CoreSight (class 9) component in isolation.
    def test_etm(self):
        cmp = CoreSightComponentID(None, MockCoreSight([MockM4Components.ETM]),
                MockM4Components.ETM_BASE)
        cmp.read_id_registers()
        assert cmp.component_class == 9
        assert cmp.designer == 0x43b
        assert cmp.part == 0x925
        assert cmp.devtype == 0x13
        assert cmp.archid == 0
        assert cmp.devarch == 0
        assert cmp.devid == [0, 0, 0]
    
    # Test parsing a CoreSight (class 9) component with a DEVID.
    def test_tpiu(self):
        cmp = CoreSightComponentID(None, MockCoreSight([MockM4Components.TPIU]),
                MockM4Components.TPIU_BASE)
        cmp.read_id_registers()
        assert cmp.component_class == 9
        assert cmp.designer == 0x43b
        assert cmp.part == 0x9a1
        assert cmp.devtype == 0x11
        assert cmp.archid == 0
        assert cmp.devarch == 0
        assert cmp.devid == [0xca1, 0, 0]
    
    # Test parsing a Class 0x9 ROM table.
    def test_c9_rom(self):
        cmp = CoreSightComponentID(None, MockCoreSight([MockCSSOC600Components.C9_ROM_TABLE]),
                MockCSSOC600Components.C9_ROM_TABLE_BASE)
        cmp.read_id_registers()
        assert cmp.component_class == 9
        assert cmp.is_rom_table

class TestRomTable:
    # Test a Class 0x1 ROM table.
    def test_m4_rom(self, m4_rom):
        # Read ROM table component ID.
        cmpid = CoreSightComponentID(None, m4_rom, MockM4Components.M4_ROM_TABLE_BASE)
        cmpid.read_id_registers()
        
        # Create the ROM table.
        rom_table = ROMTable.create(m4_rom, cmpid)
        rom_table.init()
        
        # Verify all components were parsed.
        assert len(rom_table.components) == 6
        
        # Check SCS-M4.
        scs = rom_table.components[0]
        assert scs.component_class == 14
        assert scs.designer == 0x43b
        assert scs.part == 0xc
        
        # Check TPIU.
        tpiu = rom_table.components[4]
        assert tpiu.component_class == 9
        assert tpiu.part == 0x9a1
        assert tpiu.devid == [0xca1, 0, 0]
        
    # Test a Class 0x9 ROM table and CS-600 components.
    def test_c9_rom(self, c9_top_rom):
        # Read ROM table component ID.
        cmpid = CoreSightComponentID(None, c9_top_rom, MockCSSOC600Components.C9_ROM_TABLE_BASE)
        cmpid.read_id_registers()
        
        # Create the ROM table.
        rom_table = ROMTable.create(c9_top_rom, cmpid)
        rom_table.init()

        # Validate ROM table properties.
        assert rom_table._width == 32
        assert not rom_table.has_com_port
        assert rom_table.has_prr
        assert not rom_table.is_sysmem

        # Validate components.
        assert len(rom_table.components) == 2
        
        # Validate SDC-600.
        sdc = rom_table.components[0]
        assert sdc.component_class == 9
        assert sdc.designer == 0x43b
        assert sdc.part == 0x9ef
        assert sdc.archid == 0xa57
        
        # Validate AHB-AP.
        ahb = rom_table.components[1]
        assert ahb.component_class == 9
        assert ahb.designer == 0x43b
        assert ahb.part == 0x9e3
        assert ahb.archid == 0xa17

