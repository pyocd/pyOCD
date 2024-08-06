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
from ...core.target import Target
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
    0xe7fdbe00,
    0xaf03b5f0, 0x4614b087, 0x447d4d5a, 0x28007828, 0x485ed007, 0x68004478, 0x485d4780, 0x68004478,
    0x26014780, 0x1e60702e, 0xd3002803, 0x4848e08d, 0xf90ef000, 0x2800460c, 0x4846d15f, 0xf0001c80,
    0x2800f907, 0x460cd001, 0x9406e057, 0x78102210, 0x284d4c41, 0x2311d151, 0x28757818, 0x2012d14d,
    0x78009002, 0xd00a2802, 0xd1462801, 0x92049303, 0x20149105, 0x21188800, 0x4938880a, 0x9303e008,
    0x91059204, 0xf8d4f000, 0x88022016, 0x21044833, 0x4c334790, 0x46222800, 0x4602d000, 0x99052800,
    0x9b039804, 0x7800d029, 0x284d4c2e, 0x7818d125, 0xd1222875, 0x78009802, 0x91052802, 0xd0079201,
    0xd11a2801, 0x88002014, 0x880a2118, 0xe0054926, 0xf8aef000, 0x88022016, 0x21044823, 0x4c234790,
    0x46222800, 0x4602d000, 0xd0062800, 0x48209204, 0xf8aef000, 0x2800460c, 0x4620d002, 0xbdf0b007,
    0xf0004814, 0x2800f8a5, 0x9103d19d, 0x28009806, 0x9806d019, 0x98054780, 0x48174780, 0x99014478,
    0x48166001, 0x99064478, 0x48156001, 0x99044478, 0x48146001, 0x60044478, 0x44784813, 0x60019903,
    0x2400702e, 0x9c05e7d9, 0xf000e7d7, 0x46c0f8ab, 0x00004649, 0x00005843, 0x10004552, 0x00004552,
    0x20004552, 0x10005052, 0x00005052, 0x20005052, 0x00004346, 0x0000029e, 0x00000194, 0x00000188,
    0x00000188, 0x00000184, 0x00000182, 0x000002a4, 0x000002a0, 0xaf02b5d0, 0x447c4c08, 0x28017820,
    0x4807d10a, 0x68004478, 0x48064780, 0x68004478, 0x20004780, 0xbdd07020, 0xbdd02001, 0x0000010e,
    0x00000114, 0x00000110, 0xaf02b5d0, 0x44794909, 0x29017809, 0x210fd10c, 0x18400709, 0x44794906,
    0x2201680c, 0x04120311, 0x47a023d8, 0xbdd02000, 0xbdd02001, 0x000000da, 0x000000d2, 0xaf02b5d0,
    0x4909460b, 0x78094479, 0xd10a2901, 0x0709210f, 0x49061840, 0x680c4479, 0x461a4611, 0x200047a0,
    0x2001bdd0, 0x46c0bdd0, 0x000000a4, 0x000000a0, 0xf45f4806, 0x60014140, 0xf710ee30, 0xec40d404,
    0xec400780, 0xbf400781, 0x00004770, 0xe000ed88, 0xaf02b5d0, 0x2010b284, 0x284d7800, 0x2011d10f,
    0x28757800, 0x2012d10b, 0x28027800, 0x2801d00b, 0x2014d105, 0x21188800, 0x4621880a, 0x2001e009,
    0x18610701, 0xf7ffbdd0, 0x2016ffd3, 0x21048802, 0x47904620, 0x42404601, 0x29004148, 0x2101d1f2,
    0xe7ee0749, 0xaf00b580, 0xdefede00, 0xd4d4d400, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000199,
    'pc_program_page': 0x20000201,
    'pc_erase_sector': 0x200001cd,
    'pc_eraseAll': 0x120000003,

    'static_base' : 0x20000000 + 0x00000004 + 0x000002c4,
    'begin_stack' : 0x200012d0,
    'end_stack' : 0x200002d0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x0,
    'analyzer_supported' : False,
    'page_buffers' : [0x20001400, 0x20001500],   # Enable double buffering
    'min_program_length' : 256,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x2c4,
    'rw_start': 0x2c8,
    'rw_size': 0x0,
    'zi_start': 0x2c8,
    'zi_size': 0x0,
}

def _parity32(value):
    parity = sum((value >> i) for i in range(32))
    return parity & 1

class RP2Base(CoreSightTarget):
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


class RP2350(RP2Base):
    """@brief Raspberry Pi RP2350
    """

    def __init__(self, session):
        super().__init__(session)

    def create_init_sequence(self):
        seq = super().create_init_sequence()

        # Secure mode is only needed for the flash algo.
        seq.insert_before('post_connect_hook', ('set_set_secure_mode', self._set_secure_mode))

        return seq

    def _set_secure_mode(self):
        # The RP2350 flash functions in ROM require the core to be in secure mode
        state = self.session.board.target.get_security_state()
        if state == Target.SecurityState.SECURE:
            LOG.debug("target in secure mode")
            return

        LOG.debug("target not in secure mode, attempting to switch to secure mode")
        target = self.session.board.target

        DCB_DSCSR = 0xE000EE08
        DSCSR_CDSKEY = 1 << 17
        DSCSR_CDS = 1 << 16
        dscsr = target.read32(DCB_DSCSR)
        target.write32(DCB_DSCSR, (dscsr & ~DSCSR_CDSKEY) | DSCSR_CDS)

        state = self.session.board.target.get_security_state()
        if state != Target.SecurityState.SECURE:
            LOG.debug("target failed to enter secure mode")
            raise exceptions.TargetError("Unable to set target to secure mode")

        # Attempt to enable secure access to SRAM
        ACCESSCTRL_LOCK =  0x40060000
        ACCESSCTRL_LOCK_DEBUG_BITS = 0x00000008

        ACCESSCTRL_CFGRESET = 0x40060008
        ACCESSCTRL_WRITE_PASSWORD = 0xacce0000
        lock = target.read32(ACCESSCTRL_LOCK)
        if lock & ACCESSCTRL_LOCK_DEBUG_BITS:
            # Warn instead of rasing an error in case the permissions are setup
            # correctly.
            LOG.warn("ACCESSCTRL is locked.  Unable to reset.")
        else:
            target.write32(ACCESSCTRL_CFGRESET, ACCESSCTRL_WRITE_PASSWORD | 1)


class RP2040Base(RP2Base):
    """@brief Raspberry Pi RP2040.

    This device is very strange in that it as three DPs. The first two DPs each have a single AHB-AP
    for the two Cortex-M0+ cores. The third DP is a "Rescue DP" that has no APs, but the CDBGPWRUPREQ
    signal is repurposed as a rescue signal.
    """

    class Targetsel:
        """@brief DP TARGETEL values for each DP."""
        CORE_0 = 0x01002927
        CORE_1 = 0x11002927
        RESCUE_DP = 0xf1002927

    def __init__(self, session):
        super().__init__(session)

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
        """@brief Select the DP with the matching TARGETSEL."""
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
    """@brief RP2040 target for core 0."""

    def __init__(self, session):
        super().__init__(session)
        self._core_targetsel = self.Targetsel.CORE_0

class RP2040Core1(RP2040Base):
    """@brief RP2040 target for core 1."""

    def __init__(self, session):
        super().__init__(session)
        self._core_targetsel = self.Targetsel.CORE_1
