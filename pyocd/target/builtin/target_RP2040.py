# pyOCD debugger
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

import logging

from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (RomRegion, FlashRegion, RamRegion, MemoryMap)
from ...probe.swj import SWJSequenceSender
from ...probe.debug_probe import DebugProbe
from ...utility import mask

LOG = logging.getLogger(__name__)

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe00abe00,
    0xb085b5f0, 0x447e4e1e, 0x28017830, 0xf000d101, 0x2001f839, 0x70309004, 0x46384f15, 0xf00030f7,
    0x4604f8a3, 0x1c804813, 0xf89ef000, 0x46384605, 0xf89af000, 0x48109003, 0xf896f000, 0x480f9002,
    0xf892f000, 0x480b9001, 0xf88ef000, 0x47a04607, 0x607447a8, 0x980360b5, 0x980260f0, 0x98016130,
    0x61b76170, 0x70309804, 0xb0052000, 0x46c0bdf0, 0x00004552, 0x00005843, 0x00005052, 0x00004346,
    0x0000027a, 0x4c07b510, 0x7820447c, 0xd1062801, 0x47806960, 0x478069a0, 0x70202000, 0x2001bd10,
    0x46c0bd10, 0x000001f8, 0x44784805, 0x28007800, 0x2001d101, 0x48014770, 0x46c04770, 0x000070d0,
    0x000001d6, 0x4601b570, 0x447a4a0e, 0x28017810, 0x2301d10e, 0x2400071d, 0x46261b48, 0x42a94166,
    0x68d5d308, 0x041a0319, 0x47a823d8, 0xbd704620, 0xbd702001, 0x44784804, 0x4a042121, 0xf000447a,
    0x46c0f855, 0x000001b6, 0x00000126, 0x00000164, 0xb081b5f0, 0x4d10460b, 0x7829447d, 0xd10f2901,
    0x070e2101, 0x1b812400, 0x41674627, 0xd30b42b0, 0x4608692d, 0x461a4611, 0x462047a8, 0xbdf0b001,
    0x46202401, 0xbdf0b001, 0x44784804, 0x4a042121, 0xf000447a, 0x46c0f82b, 0x00000168, 0x000000d2,
    0x00000120, 0xd4d4de00, 0x2114b280, 0x1e898809, 0x2a00884a, 0x1d09d004, 0xd1f94282, 0x47708808,
    0x44784803, 0x4a03210e, 0xf000447a, 0x46c0f80f, 0x00000076, 0x000000c8, 0xd4d44770, 0x49024801,
    0x46c04770, 0x4d94efcf, 0x7847d224, 0xaf00b580, 0x2300b088, 0x4c079305, 0x93039404, 0x23019302,
    0xab069301, 0x91079300, 0x46689006, 0xf0004611, 0xdefef803, 0x00000244, 0xaf00b580, 0x9103b084,
    0x48049002, 0x48049001, 0x46689000, 0xffbaf7ff, 0x46c0defe, 0x00000244, 0x00000244, 0x636e7546,
    0x746f6e20, 0x756f6620, 0x7273646e, 0x616d2f63, 0x722e6e69, 0xd4d4d473, 0xd4d4d4d4, 0xd4d4d4d4,
    0x65747461, 0x2074706d, 0x73206f74, 0x72746275, 0x20746361, 0x68746977, 0x65766f20, 0x6f6c6672,
    0xd4d4d477, 0x00000199, 0x00000000, 0x00000001, 0x0000019d, 0x0000020a, 0x0000000b, 0x00000014,
    0x00000011, 0x0000020a, 0x0000000b, 0x00000053, 0x00000028, 0x0000020a, 0x0000000b, 0x00000058,
    0x0000002a, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000089,
    'pc_program_page': 0x20000115,
    'pc_erase_sector': 0x200000c9,
    # 'pc_eraseAll': 0x200000ad, # not implemented yet

    'static_base' : 0x20000000 + 0x00000004 + 0x00000254,
    'begin_stack' : 0x20000500,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x0,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001100],   # Enable double buffering
    'min_program_length' : 256,

    # Relative region addresses and sizes
    'ro_start': 0x0,
    'ro_size': 0x254,
    'rw_start': 0x254,
    'rw_size': 0x30,
    'zi_start': 0x284,
    'zi_size': 0x1c,
}

def _parity32(value):
    parity = sum((value >> i) for i in range(32))
    return parity & 1

class RP2040Base(CoreSightTarget):
    """! @brief Raspberry Pi RP2040.
    
    This device is very strange in that it as three DPs. The first two DPs each have a single AHB-AP
    for the two Cortex-M0+ cores. The third DP is a "Rescue DP" that has no APs, but the CDBGPWRUPREQ
    signal is repurposed as a rescue signal.
    """
    
    class Targetsel:
        """! @brief DP TARGETEL values for each DP."""
        CORE_0 = 0x01002927
        CORE_1 = 0x11002927
        RESCUE_DP = 0xf1002927

    VENDOR = "Raspberry Pi"
    
    MEMORY_MAP = MemoryMap(
        RomRegion(  start=0,            length=0x4000,      name="bootrom",             ),
        FlashRegion(start=0x10000000,   length=0x1000000,   name="xip",                 
            sector_size=4096,
            page_size=256,
            algo=FLASH_ALGO,
            is_boot_memory=True),
        RomRegion(  start=0x11000000,   length=0x1000000,   name="xip_noalloc",           alias="xip"),
        RomRegion(  start=0x12000000,   length=0x1000000,   name="xip_nocache",           alias="xip"),
        RomRegion(  start=0x13000000,   length=0x1000000,   name="xip_noalloc_nocache",   alias="xip"),
        RamRegion(  start=0x20000000,   length=0x40000,     name="sram0_3",               ),
        RamRegion(  start=0x20040000,   length=0x2000,      name="sram4_5",               ),
        RamRegion(  start=0x21000000,   length=0x40000,     name="sram0_3_alias",         alias="sram0_3"),
        RamRegion(  start=0x51000000,   length=0x1000,      name="usbram",                ),
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

        ## The TARGETSEL value to be used.
        self._core_targetsel = None

        # Disable the SWJ sequence. This performs a line reset, which causes all DPs to be selected. After
        # any line reset on a multi-drop SWD setup there must be a target selection sequence.
        session.options['dap_swj_enable'] = False

    def create_init_sequence(self):
        seq = super().create_init_sequence()
        
        seq.insert_before('load_svd', ('check_probe', self._check_probe)) \
            .insert_before('dp_init', ('select_core0', self._select_core))

        return seq
    
    def _check_probe(self):
        # Have to import here to avoid a circular import
        from ...probe.debug_probe import DebugProbe
        if DebugProbe.Capability.SWD_SEQUENCE not in self.session.probe.capabilities:
            raise exceptions.TargetSupportError("RP2040 requires a debug probe with SWD sequence capability")

    def _select_core(self):
        self.select_dp(self._core_targetsel)

    def select_dp(self, targetsel):
        """! @brief Select the DP with the matching TARGETSEL."""
        probe = self.session.probe
        
        # Have to connect the probe first, or SWCLK will not be enabled.
        probe.connect(DebugProbe.Protocol.SWD)

        # First perform the dormant to SWD sequence. An SW-DPv2 implementing multi-drop SWD will cold
        # reset into dormant mode.
        swj = SWJSequenceSender(self.session.probe, True)
        swj.dormant_to_swd()

        # SWD line reset to activate all DPs.
        swj.line_reset()
        swj.idle_cycles(2)
        
        # Send multi-drop SWD target selection sequence to select the requested DP.
        probe.swd_sequence([
            # DP TARGETSEL write
            # output 8 cycles:
            #   - Start = 1
            #   - APnDP = 0
            #   - RnW = 0
            #   - A[2:3] = 2'b11
            #   - Parity = 0
            #   - Stop = 0
            #   - Park = 1
            # -> LSB first, that's 0b10011001 or 0x99
            (8, 0x99),
            
            # 5 cycles with SWDIO as input
            (5,),
            
            # DP TARGETSEL value
            # output 32 + 1 cycles
            (33, targetsel | mask.parity32_high(targetsel)),

            # 2 idle cycles
            (2, 0x00),
            ])

        DP_IDR = 0x00
        dpidr = probe.read_dp(DP_IDR)
        LOG.debug("DP IDR after writing TARGETSEL: 0x%08x", dpidr)
        
        probe.write_dp(0x8, 0x2) # DPBANKSEL=2 to select TARGETID
        targetid = probe.read_dp(0x4)
        LOG.debug("DP TARGETID: 0x%08x", targetid)
        
        probe.write_dp(0x8, 0x3) # DPBANKSEL=3 to select DLPIDR
        dlpidr = probe.read_dp(0x4)
        LOG.debug("DP DLPIDR: 0x%08x", dlpidr)
        
        probe.write_dp(0x8, 0x0) # restore DPBANKSEL=0

class RP2040Core0(RP2040Base):
    """! @brief RP2040 target for core 0."""

    def __init__(self, session):
        super().__init__(session)
        self._core_targetsel = self.Targetsel.CORE_0

class RP2040Core1(RP2040Base):
    """! @brief RP2040 target for core 1."""
    
    def __init__(self, session):
        super().__init__(session)
        self._core_targetsel = self.Targetsel.CORE_1

