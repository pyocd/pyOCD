# pyOCD debugger
# Copyright (c) 2026 NXP
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RomRegion, RamRegion, MemoryMap)
from ...coresight.ap import AccessPort, APv1Address
from ...coresight.cortex_m import CortexM
from pyocd.flash.flash import Flash
from pyocd.flash.builder import FlashBuilder
from pyocd.core.options import add_option_set, OptionInfo
from pyocd.core.exceptions import TransferError, FlashEraseFailure, FlashProgramFailure
from pyocd.core.target import Target
import time

LOG = logging.getLogger(__name__)

add_option_set({
    OptionInfo("vtor", str, None, "CM7 app vector table address for the core restart"),
    OptionInfo("imx95.stop_dma", bool, True, "Stop the CM7's eDMA channels before a CM7 core restart"),
})

# SRC register holding the CM7 initial vector table (boot VTOR).
SRC_M7_INIT_VTOR = 0x544F0108

# GPC CM7 CM_MISC register and its SLEEP_HOLD_EN bit, cleared on connect.
GPC_CM7_CM_MISC = 0x4447080C
GPC_CM_MISC_SLEEP_HOLD_EN = 1 << 1

# CM7 SCS registers that CortexM does not define, accessed via the CM7 MEM-AP.
MPU_CTRL = 0xE000ED94
CM7_CFSR = 0xE000ED28
CM7_HFSR = 0xE000ED2C
# FPCCR reset value: automatic and lazy FP state saving on exception entry (ASPEN, LSPEN).
CM7_FPCCR_RESET = 0xC0000000

# eDMA channel page registers (CH_CSR, CH_ES, CH_INT) and the CH_CSR bits used to stop a channel.
EDMA_CH_CSR_ERQ = 1 << 0
EDMA_CH_CSR_DONE = 1 << 30
EDMA_CH_CSR_ACTIVE = 1 << 31
EDMA_CH_INT = 0x8
# First channel page and page step of eDMA2 (0x42000000) and eDMA3 (0x44000000, SM name EDMA1).
EDMA2_CH0, EDMA2_CH_STEP = 0x42010000, 0x8000
EDMA3_CH0, EDMA3_CH_STEP = 0x44010000, 0x10000
EDMA_CH_INT_INT = 1 << 0
# Seconds to wait for stopped eDMA channels to finish their current minor loop.
EDMA_STOP_TIMEOUT = 0.1

# Seconds to try parking a CM7 that the SM keeps resetting, and the stack top for the parking loop.
M7_PARK_TIMEOUT = 1.0
# Seconds to wait on connect for a CM7 that the System Manager is still bringing out of reset.
M7_RESET_TIMEOUT = 2.0
M7_PARK_SP = 0x20040000

# WDOG2 (the System Manager's watchdog) counter register and its 32-bit refresh word.
WDOG2_CNT = 0x542E0004
WDOG_REFRESH_KEY = 0xB480A602

# FlexSPI XIP base, used as the app VTOR fallback when nothing better is known.
FLEXSPI_BASE = 0x28000000

# Parking loop code: LE halfwords 0xB672 (cpsid i), 0xE7FE (b .).
SAFE_LOOP_CODE = 0xE7FEB672

# One flash algorithm serves both cores: the same load address, FlexSPI registers and flash
# window, and ProgramPage sends a write enable per 256-byte page, so it takes multi-page calls.
FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00, 0xf644b081, 0xf2c40120, 0x68084146, 0x98009000, 0x1080f440, 0x98009000, 0xb0016008,
    0xbf004770, 0xf644b081, 0xf2c40120, 0x68084146, 0x98009000, 0x1080f420, 0x98009000, 0xb0016008,
    0xbf004770, 0xb090b580, 0x910c900d, 0x2000920b, 0xf3ef900a, 0xb6728010, 0x980b900f, 0xd1092803,
    0x2100e7ff, 0x215ef2c4, 0x1012f243, 0x70fff6cf, 0xe0086008, 0xf2c42100, 0xf243215e, 0xf6cf0032,
    0x600870ff, 0x2104e7ff, 0x215ef2c4, 0x30fff04f, 0x21086008, 0x215ef2c4, 0x10f7f244, 0x0000f2c2,
    0x210c6008, 0x215ef2c4, 0x60082038, 0xf2c42120, 0x2000215e, 0x000ff2c8, 0x21246008, 0x215ef2c4,
    0x21286008, 0x215ef2c4, 0x212c6008, 0x215ef2c4, 0x21306008, 0x215ef2c4, 0x21346008, 0x215ef2c4,
    0x21386008, 0x215ef2c4, 0x213c6008, 0x215ef2c4, 0xf2c82080, 0x60080000, 0xf2c42160, 0xf44f215e,
    0x60083000, 0xf2c42164, 0x2000215e, 0x21686008, 0x215ef2c4, 0x216c6008, 0x215ef2c4, 0x22706008,
    0x225ef2c4, 0xf2c02163, 0x60110102, 0xf2c42274, 0x2163225e, 0x22786011, 0x225ef2c4, 0x227c6011,
    0x225ef2c4, 0x22806011, 0x225ef2c4, 0x6110f44f, 0x21846011, 0x215ef2c4, 0x21886008, 0x215ef2c4,
    0x218c6008, 0x215ef2c4, 0x21946008, 0x215ef2c4, 0x600820c3, 0x2803980b, 0xe7ffd103, 0xfa0ef000,
    0x21c0e009, 0x215ef2c4, 0x60082079, 0xf2c421c4, 0x6008215e, 0x2100e7ff, 0x215ef2c4, 0x68089101,
    0x0002f020, 0xf0006008, 0x9901f81d, 0xf0406808, 0x60080001, 0x2000e7ff, 0x205ef2c4, 0x07c06800,
    0xe7ffb108, 0xf000e7f7, 0x900af845, 0xb118980a, 0x980ae7ff, 0xe002900e, 0x900e980a, 0x980ee7ff,
    0xbd80b010, 0x2118b081, 0x215ef2c4, 0x20f0f645, 0x20f0f6c5, 0x211c6008, 0x215ef2c4, 0x60082002,
    0x90002000, 0x9800e7ff, 0xd813283b, 0x9a00e7ff, 0x40e0f240, 0x0000f2c0, 0xf8504478, 0xf2400022,
    0xf2c42100, 0xf841215e, 0xe7ff0022, 0x30019800, 0xe7e89000, 0xf2c42118, 0xf645215e, 0xf6c520f0,
    0x600820f0, 0xf2c4211c, 0x2001215e, 0xb0016008, 0xbf004770, 0xb084b580, 0x93012300, 0x90002002,
    0x461a4619, 0xf84ef000, 0x98029002, 0xe7ffb118, 0x90039802, 0x2008e019, 0x466a2100, 0xf0002301,
    0x9002f841, 0xb1189802, 0x9802e7ff, 0xe00c9003, 0xf0002001, 0x9002f8f7, 0xb1189802, 0x9802e7ff,
    0xe0029003, 0x90039802, 0x9803e7ff, 0xbd80b004, 0xbf00bf00, 0x9000b081, 0xb0012000, 0xbf004770,
    0xbf00bf00, 0xb082b580, 0x93002300, 0x46192004, 0xf000461a, 0x9000f817, 0xb1189800, 0x9800e7ff,
    0xe0099001, 0x2300200b, 0x461a4619, 0xf80af000, 0x98009000, 0xe7ff9001, 0xb0029801, 0xbf00bd80,
    0xbf00bf00, 0x9007b088, 0x92059106, 0x3012f8ad, 0x90032000, 0xf2c42180, 0x6808215e, 0x4000f040,
    0x21146008, 0x215ef2c4, 0x703ff640, 0x98066008, 0xf2c421a0, 0x6008215e, 0xf8bd9907, 0xea400012,
    0x21a44001, 0x215ef2c4, 0x21bc6008, 0x215ef2c4, 0x60082001, 0xf2c421b0, 0x6008215e, 0xf8bde7ff,
    0xb3d00012, 0xf8bde7ff, 0x28070012, 0xe7ffd804, 0x0012f8bd, 0xe0029000, 0x90002008, 0x9800e7ff,
    0xf2409001, 0xf2c41080, 0x9002205e, 0x2014e7ff, 0x205ef2c4, 0x06406800, 0xd4012800, 0xe7f6e7ff,
    0xf1019905, 0x90050008, 0x68496808, 0xe9c29a02, 0x20140100, 0x205ef2c4, 0x60012140, 0xf8bd9a01,
    0x1a891012, 0x1012f8ad, 0xf0106800, 0xd0030f0a, 0x2001e7ff, 0xe0009003, 0xe7ffe7c1, 0xf2c420e0,
    0x6800205e, 0x28000780, 0xe7ffd401, 0x2014e7f6, 0x205ef2c4, 0xf0106800, 0xd0030f0a, 0x2001e7ff,
    0xe7ff9003, 0xb0089803, 0xbf004770, 0xb084b580, 0x98029002, 0x4058f100, 0x23009001, 0x20049300,
    0x461a4619, 0xff6ef7ff, 0x98009000, 0xe7ffb118, 0x90039800, 0x9901e023, 0x23002005, 0xf7ff461a,
    0x9000ff61, 0xb1189800, 0x9800e7ff, 0xe0169003, 0xf0002001, 0x9000f817, 0xf2c42100, 0x6808215e,
    0x0001f040, 0xe7ff6008, 0xf2c42000, 0x6800205e, 0xb10807c0, 0xe7f7e7ff, 0x90039800, 0x9803e7ff,
    0xbd80b004, 0xb086b580, 0x0013f88d, 0x0013f89d, 0x200107c1, 0xbf182900, 0x9000200a, 0x9800e7ff,
    0xaa022100, 0xf0002301, 0x9001f8a5, 0xb1189801, 0x9801e7ff, 0xe0169005, 0x0008f89d, 0xb12007c0,
    0x2001e7ff, 0x0012f88d, 0x2000e003, 0x0012f88d, 0xe7ffe7ff, 0x0012f89d, 0x280007c0, 0xe7ffd1df,
    0x90059801, 0x9805e7ff, 0xbd80b006, 0xe92db351, 0xf1004ff8, 0x468a4b58, 0x25004617, 0x4c134e12,
    0x20042300, 0x0905eb07, 0x0805eb0b, 0x4619461a, 0xb9a847b0, 0x7380f44f, 0x4641464a, 0x47b02007,
    0x4b0bb970, 0x47982001, 0xf0436823, 0x60230301, 0x07db6823, 0xf505d4fc, 0x45aa7580, 0x2000d8e0,
    0x8ff8e8bd, 0x47702000, 0x20000305, 0x425e0000, 0x20000485, 0xf2c42100, 0x6808215e, 0x0001f040,
    0xe7ff6008, 0xf2c42000, 0x6800205e, 0xb10807c0, 0xe7f7e7ff, 0x9901e7ff, 0x44089800, 0x99019000,
    0x44089804, 0x99019004, 0x44089803, 0xe7ca9003, 0x90079802, 0x9807e7ff, 0xbd80b008, 0x23c0b081,
    0x235ef2c4, 0x60182002, 0xf2c422c4, 0x6010225e, 0x60182000, 0x21796010, 0x60116019, 0xe7ff9000,
    0xf2489800, 0xf2c0619f, 0x42880101, 0xe7ffdc10, 0xf2c420e8, 0x6800205e, 0x1003f000, 0x1f03f1b0,
    0xe7ffd101, 0xe7ffe004, 0x30019800, 0xe7e79000, 0x4770b001, 0x9007b088, 0x92059106, 0x3012f8ad,
    0x90032000, 0xf2c42180, 0xf640215e, 0xf2c81000, 0x60080000, 0xf2c42114, 0xf640215e, 0x6008703f,
    0x21a09806, 0x215ef2c4, 0x99076008, 0x0012f8bd, 0x4001ea40, 0xf2c421a4, 0x6008215e, 0xf2c421b8,
    0x2001215e, 0x21b06008, 0x215ef2c4, 0xe7ff6008, 0x0012f8bd, 0xe7ffb3d0, 0x0012f8bd, 0xd8042807,
    0xf8bde7ff, 0x90000012, 0x2008e002, 0xe7ff9000, 0x90019800, 0x1000f240, 0x205ef2c4, 0xe7ff9002,
    0xf2c42014, 0x6800205e, 0x28000680, 0xe7ffd401, 0x9802e7f6, 0x0200e9d0, 0xf1019905, 0x93050308,
    0x6008604a, 0xf2c42014, 0x2120205e, 0x9a016001, 0x1012f8bd, 0xf8ad1a89, 0x68001012, 0x0f0af010,
    0xe7ffd003, 0x90032001, 0xe7c1e000, 0x20e0e7ff, 0x205ef2c4, 0x07806800, 0xd4012800, 0xe7f6e7ff,
    0xf2c42014, 0x6800205e, 0x0f0af010, 0xe7ffd003, 0x90032001, 0x9803e7ff, 0x4770b008, 0x871187ee,
    0xb3288b20, 0x0000a704, 0x00000000, 0x24040405, 0x00000000, 0x00000000, 0x00000000, 0x00000406,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x87f98706,
    0x00000000, 0x00000000, 0x00000000, 0x87de8721, 0x00008b20, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x87ed8712, 0xa3048b20, 0x00000000, 0x00000000, 0x04000472,
    0x04000400, 0x20010400, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x87fa8705,
    0xb3048b20, 0x0000a704, 0x00000000, 0x8b2007c4, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x000007b7, 0x00000000, 0x00000000, 0x00000000, 0xa7010770,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    ],

    # Relative function addresses
    'pc_init': 0x20000045,
    'pc_unInit': 0x200002b5,
    'pc_program_page': 0x200004ed,
    'pc_erase_sector': 0x2000040d,
    # No pc_eraseAll: the blob's chip erase is a plain-SPI command (0xC4) that never waits for the erase.

    'static_base' : 0x20000000 + 0x00000004 + 0x000007e8,
    'begin_stack' : 0x200019f0,
    'end_stack' : 0x200009f0,
    'begin_data' : 0x20000000 + 0x1000,
    # ProgramPage writes any multiple of 256 bytes, one write enable per 256-byte page.
    'page_size' : 0x4000,
    # pyocd's CRC32 analyzer; it encodes page address / page size in 16 bits, so pages
    # must be at least 16 KB for the 0x28000000 flash window.
    'analyzer_supported' : True,
    'analyzer_address' : 0x2000C000,
    'page_buffers' : [
        0x20004000,
        0x20008000
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x7e8,
    'rw_start': 0x7ec,
    'rw_size': 0x4,
    'zi_start': 0x7f0,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x28000000,
    'flash_size': 0x4000000,
    'sector_sizes': (
        (0x0, 0x1000),
    )
}



# XSPI1 pad mux, daisy select and pad control writes for the FlexSPI1 port A octal NOR.
XSPI1_PAD_WRITES = (
    # IOMUXC_PAD_XSPI1_SCLK__FLEXSPI1_A_SCLK
    (0x443C0194, 0x0), (0x443C04F4, 0x1), (0x443C0398, 0x7e),
    # IOMUXC_PAD_XSPI1_SS0_B__FLEXSPI1_A_SS0_B
    (0x443C0198, 0x0), (0x443C039C, 0x3fe),
    # IOMUXC_PAD_XSPI1_SS1_B__FLEXSPI1_A_SS1_B
    (0x443C019C, 0x0), (0x443C03A0, 0x3fe),
    # IOMUXC_PAD_XSPI1_DQS__FLEXSPI1_A_DQS
    (0x443C0190, 0x0), (0x443C04D0, 0x1), (0x443C0394, 0x7e),
    # IOMUXC_PAD_XSPI1_DATA0__FLEXSPI1_A_DATA_BIT0
    (0x443C0170, 0x0), (0x443C04D4, 0x1), (0x443C0374, 0x2),
    # IOMUXC_PAD_XSPI1_DATA1__FLEXSPI1_A_DATA_BIT1
    (0x443C0174, 0x0), (0x443C04D8, 0x1), (0x443C0378, 0x2),
    # IOMUXC_PAD_XSPI1_DATA2__FLEXSPI1_A_DATA_BIT2
    (0x443C0178, 0x0), (0x443C04DC, 0x1), (0x443C037C, 0x2),
    # IOMUXC_PAD_XSPI1_DATA3__FLEXSPI1_A_DATA_BIT3
    (0x443C017C, 0x0), (0x443C04E0, 0x1), (0x443C0380, 0x2),
    # IOMUXC_PAD_XSPI1_DATA4__FLEXSPI1_A_DATA_BIT4
    (0x443C0180, 0x0), (0x443C04E4, 0x1), (0x443C0384, 0x2),
    # IOMUXC_PAD_XSPI1_DATA5__FLEXSPI1_A_DATA_BIT5
    (0x443C0184, 0x0), (0x443C04E8, 0x1), (0x443C0388, 0x2),
    # IOMUXC_PAD_XSPI1_DATA6__FLEXSPI1_A_DATA_BIT6
    (0x443C0188, 0x0), (0x443C04EC, 0x1), (0x443C038C, 0x2),
    # IOMUXC_PAD_XSPI1_DATA7__FLEXSPI1_A_DATA_BIT7
    (0x443C018C, 0x0), (0x443C04F0, 0x1), (0x443C0390, 0x2),
)

class FlexSpiFlashBuilder(FlashBuilder):
    """Erases each sector while the host loads the sector's first page, then programs the sector.

    The algo's Init sets FlexSPI up the same way for ERASE and PROGRAM (only VERIFY differs), so the
    whole erase and program sequence runs under one PROGRAM init.
    """

    def _erase_sectors(self, progress_cb=None):
        # Deferred to program(), which erases each sector right before programming it.
        if not (self.flash.is_double_buffering_supported and self.enable_double_buffering):
            super()._erase_sectors(progress_cb)

    def _program_double_buffer(self, progress_cb=lambda _: None):
        flash = self.flash
        options = flash.target.session.options
        sectors = [s for s in self.sector_list if s.are_any_pages_not_same()]
        if not sectors:
            return
        flash.init(flash.Operation.PROGRAM)
        buf = 0
        for done, sector in enumerate(sectors, 1):
            first = sector.page_list[0]
            addrs = list(sector.addrs) if self.region.is_erasable else []
            step = -(-len(first.data) // max(len(addrs), 1))
            for n, addr in enumerate(addrs):
                flash._call_function(flash.flash_algo['pc_erase_sector'], addr)
                flash.target.write_memory_block8(flash.page_buffers[buf] + n * step,
                                                 first.data[n * step:(n + 1) * step])
                result = flash.wait_for_completion(timeout=options.get('flash.timeout.erase_sector'))
                if result != 0:
                    raise FlashEraseFailure('flash erase sector failure', address=addr, result_code=result)
            if not addrs:
                flash.load_page_buffer(buf, first.addr, first.data)
            for i, page in enumerate(sector.page_list):
                flash.start_program_page_with_buffer(buf, page.addr)
                if i + 1 < len(sector.page_list):
                    nxt = sector.page_list[i + 1]
                    flash.load_page_buffer(1 - buf, nxt.addr, nxt.data)
                result = flash.wait_for_completion(timeout=options.get('flash.timeout.program'))
                if result != 0:
                    raise FlashProgramFailure('flash program page failure', address=page.addr, result_code=result)
                buf = 1 - buf
            progress_cb(done / len(sectors))
        flash.uninit()


class FlexSpiFlash(Flash):
    _restore_read = False

    def get_flash_builder(self):
        return FlexSpiFlashBuilder(self)

    def uninit(self):
        # FlashBuilder uninits before cleanup, so remember that FlexSPI is left in a write setup.
        self._restore_read |= self._active_operation in (self.Operation.ERASE, self.Operation.PROGRAM)
        super().uninit()

    def cleanup(self):
        # Init for VERIFY puts FlexSPI back in its read setup and clears the AHB read buffers; without
        # it, reads and the app's XIP fetches can see stale data from the erase or program setup.
        try:
            if self._restore_read or self._active_operation in (self.Operation.ERASE, self.Operation.PROGRAM):
                self._restore_read = False
                self.init(self.Operation.VERIFY)
        finally:
            super().cleanup()

    def prepare_target(self):
        # Any path that programs the NOR (gdb load included) rewrites code under a core that may be
        # running the old image: restart it first so caches are off, NVIC, SysTick and eDMA are quiet
        # and VTOR, MSP and PC hold the app table before the algo is loaded.
        self.target.reset_and_halt()
        # Runs once per prepare, with the CM7 halted and before the algo is loaded.
        for addr, value in XSPI1_PAD_WRITES:
            self.target.ap3.write32(addr, value)

        # flexspi1_clk_root (CCM root 85) = SYS_PLL1_DFS1 / 4 = 200 MHz
        self.target.ap3.write32(0x44452A80, 0x203)

class FlexSpiFlashCm33(FlexSpiFlash):
    # The algo replaces System Manager code, so a CM33 flash ends with the SoC reset (SYSRESETREQ).

    def prepare_target(self):
        # A running CM7 fetches code from the same NOR through FlexSPI, and the algo then hangs now
        # and then until WDOG2 resets the SoC. Halt the CM7; the SoC reset after the flash restarts it.
        try:
            AccessPort.create(self.target.dp, APv1Address(2)).write32(
                    CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)
        except TransferError:
            self.target.dp.clear_sticky_err()
        super().prepare_target()
        # Disable the CM33 code and system caches, which sit between the algo and the flash.
        self.target.ap3.write32(0x44400000, 0x0)
        self.target.ap3.write32(0x44400800, 0x0)
        # MPU off, so the System Manager's regions do not cover the algo, its buffers or FlexSPI.
        self.target.ap3.write32(MPU_CTRL, 0x0)

    def _call_function(self, pc, *args, **kwargs):
        # WDOG2 stops only while the CM33 is halted, so it counts while the algo runs; one call
        # must finish within its 2 s timeout.
        # ponytail: a chip erase runs longer than that in one call; refresh from the wait loop if needed.
        self.target.ap3.write32(WDOG2_CNT, WDOG_REFRESH_KEY)
        super()._call_function(pc, *args, **kwargs)

class CM7Core(CortexM):
    # The CM7 next to a running System Manager: core-only restart into the application, parking
    # of a core the System Manager keeps resetting, and its own eDMA channels quiesced first.
    def _get_actual_reset_type(self, reset_type):
        # SYSRESETREQ asks the System Manager to reset the M7 logical machine. Every other type,
        # DEFAULT from the CLI and gdbserver included, is the core-only restart: a probe or SRC
        # reset would hit the SoC or the M7 behind the System Manager's back.
        reset_type = super()._get_actual_reset_type(reset_type)
        return reset_type if reset_type is Target.ResetType.SYSRESETREQ else Target.ResetType.EMULATED

    def _perform_emulated_reset(self):
        # Restart from the app vector table instead of the boot region, with the MPU off.
        vtor = self._app_vtor()
        demcr = self.read32(CortexM.DEMCR)
        self.write32(CortexM.DEMCR, demcr | CortexM.DEMCR_VC_CORERESET)
        try:
            super()._perform_emulated_reset()
        finally:
            self.write32(CortexM.DEMCR, demcr)
        if self.session.options.get("imx95.stop_dma"):
            self._stop_dma(self.session.target.m7_dma_channels())
        self.write32(MPU_CTRL, 0)
        # Fault status bits are write-one-to-clear; the stock reset writes 0 and leaves them set.
        self.write_memory_block32(CM7_CFSR, [0xFFFFFFFF, 0xFFFFFFFF])
        self.write32(CortexM.FPCCR, CM7_FPCCR_RESET)
        self.write32(CortexM.VTOR, vtor)
        self.write_core_registers_raw(['msp', 'pc'], [self.read32(vtor), self.read32(vtor + 4) & ~1])
        LOG.debug(f"CM7 restart from VTOR 0x{vtor:08X}")
        if (demcr & CortexM.DEMCR_VC_CORERESET) == 0:
            self.resume()

    def _stop_dma(self, channels):
        # The old image's eDMA channels keep running through a core restart and write into the next
        # image. Clear ERQ, wait for ACTIVE to drop, then clear DONE and INT (both write-one-to-clear).
        for page in channels:
            csr = self.read32(page)
            if csr & EDMA_CH_CSR_ERQ:
                self.write32(page, csr & ~(EDMA_CH_CSR_ERQ | EDMA_CH_CSR_DONE))
        deadline = time.monotonic() + EDMA_STOP_TIMEOUT
        for page in channels:
            while self.read32(page) & EDMA_CH_CSR_ACTIVE:
                if time.monotonic() > deadline:
                    LOG.warning(f"eDMA channel at 0x{page:08X} still active after the stop")
                    break
        for page in channels:
            csr = self.read32(page)
            if csr & EDMA_CH_CSR_DONE:
                self.write32(page, csr & ~EDMA_CH_CSR_ERQ)
            self.write32(page + EDMA_CH_INT, EDMA_CH_INT_INT)

    def _app_vtor(self):
        # Priority: -O vtor, else the live VTOR when it holds an app table, else the flash base.
        # A table whose reset handler directly follows it is a parking loop, not an app.
        opt = self.session.options.get("vtor")
        if opt:
            return int(opt, 0)
        try:
            if not self.read32(CortexM.DHCSR) & CortexM.S_LOCKUP:
                vtor = self.read32(CortexM.VTOR)
                if not (vtor & 0x7F) and self.memory_map.is_valid_address(vtor) \
                        and (self.read32(vtor + 4) & ~1) != vtor + 8:
                    return vtor
        except TransferError:
            pass
        return FLEXSPI_BASE


class MIMX95_CM7(CoreSightTarget):
    VENDOR = "NXP"

    # Note: itcm, dtcm share a single 512 KB block of RAM that can be configurably
    # divided between those regions (this is called FlexRAM). Thus, the memory map regions for
    # each of these RAMs allocate the maximum possible of 512 KB, but that is the maximum and
    # will not actually be available in all regions simultaneously.
    memoryMap = MemoryMap(
        RamRegion(name="itcm",              start=0x00000000, length=0x80000, is_boot_memory=True), # 512 KB
        RomRegion(name="romcp",             start=0x00100000, length=0x40000), # 256 KB
        RamRegion(name="dtcm",              start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )

    def __init__(self, session):
        super(MIMX95_CM7, self).__init__(session, self.memoryMap)
        self._dma_channels = None

    def power_up_m7mix(self):
        # CM33 MEM-AP, used only as a bus master for the SRC, IOMUXC and CCM. It is kept out of
        # dp.aps so that discovery does not set up the System Manager core's DWT, ITM and breakpoint
        # unit. The M7 slice reset line is the System Manager's; never write SLICE_SW_CTRL.
        self.ap3 = AccessPort.create(self.dp, APv1Address(3))
        self._discoverer._create_1_ap(2)
        self.ap2 = self.dp.aps[2]  # CM7 MEM‑AP
        self.connect_dhcsr = self._read_connect_dhcsr()
        if self._wait_m7_out_of_reset():
            self._park_m7_reset_loop()

        misc = self.ap2.read32(GPC_CM7_CM_MISC)
        self.ap2.write32(GPC_CM7_CM_MISC, misc & ~GPC_CM_MISC_SLEEP_HOLD_EN)

    def _read_connect_dhcsr(self):
        # Reading DHCSR clears S_RESET_ST, so the first read is kept and logged for scripts.
        try:
            dhcsr = self.ap2.read32(CortexM.DHCSR)
        except TransferError:
            self.dp.clear_sticky_err()
            LOG.info("CM7 DHCSR at connect: read faulted")
            return None
        reset = " (reset since the last read)" if dhcsr & CortexM.S_RESET_ST else ""
        LOG.info(f"CM7 DHCSR at connect 0x{dhcsr:08X}{reset}")
        return dhcsr

    def _wait_m7_out_of_reset(self):
        # After a system reset the System Manager releases the M7 later than the debug port comes
        # up, and the ROM table and SCB reads of discovery fault until then. Wait until a DHCSR read
        # answers without S_RESET_ST (no reset since the previous read), or shows a lockup.
        # Returns True on a lockup. In a lockup-reset loop only some reads catch S_LOCKUP.
        deadline = time.monotonic() + M7_RESET_TIMEOUT
        while time.monotonic() < deadline:
            try:
                dhcsr = self.ap2.read32(CortexM.DHCSR)
                if dhcsr & CortexM.S_LOCKUP:
                    return True
                if not dhcsr & CortexM.S_RESET_ST:
                    return False
            except TransferError:
                self.dp.clear_sticky_err()
            time.sleep(0.01)
        LOG.warning("CM7 did not come out of reset on connect")
        return False

    def _park_m7_reset_loop(self):
        # On a CM7 lockup the SM resets the M7 and boots it from the boot vector (INITVTOR). If that
        # image is broken, the M7 locks up again within a millisecond, forever, and its debug
        # registers fault while it is in reset. Replace the broken boot vector with a parking loop.
        boot = self.ap3.read32(SRC_M7_INIT_VTOR)
        stub = [M7_PARK_SP, (boot + 8) | 1, SAFE_LOOP_CODE]
        deadline = time.monotonic() + M7_PARK_TIMEOUT
        # Each M7 reset also resets the AP2 CSW (address increment off) behind pyOCD's cached copy.
        while time.monotonic() < deadline:
            self.ap2._invalidate_cache()
            try:
                self.ap2.write_memory_block32(boot, stub)
                if self.ap2.read_memory_block32(boot, len(stub)) == stub:
                    LOG.warning(f"CM7 boot image at 0x{boot:08X} locks up; replaced its vectors with a "
                                f"parking loop (a power cycle restores the boot image)")
                    time.sleep(0.1)
                    self.ap2._invalidate_cache()
                    return
            except TransferError:
                self.dp.clear_sticky_err()
        LOG.warning("CM7 keeps locking up and its boot vector could not be replaced")

    def create_init_sequence(self):
        seq = super(MIMX95_CM7, self).create_init_sequence()
        seq.insert_before('discovery', ('power_up_m7mix', self.power_up_m7mix))
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('find_aps', self.find_aps),
            )
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def m7_dma_channels(self):
        # CH_CSR addresses of the eDMA channels the CM7 may access. The System Manager's TRDC
        # config decides that, so each channel page is read once through the CM7 MEM-AP: pages of
        # other domains fault. eDMA2 channel pairs share one TRDC block, so one read covers two.
        if self._dma_channels is None:
            groups = [[EDMA2_CH0 + (n + i) * EDMA2_CH_STEP for i in (0, 1)] for n in range(0, 64, 2)]
            groups += [[EDMA3_CH0 + n * EDMA3_CH_STEP] for n in range(32)]
            self._dma_channels = []
            for group in groups:
                try:
                    self.ap2.read32(group[0])
                    self._dma_channels += group
                except TransferError:
                    self.dp.clear_sticky_err()
            LOG.debug(f"CM7 owns {len(self._dma_channels)} eDMA channels")
        return self._dma_channels

    def find_aps(self):
        if self.dp.valid_aps is None:
            self.dp.valid_aps = [2]

    def create_cores(self):
        core0 = CM7Core(self.session, self.aps[2], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.EMULATED

        self.aps[2].core = core0

        core0.init()

        self.add_core(core0)

class MIMX95_CM7_MX25UM(MIMX95_CM7):
    memoryMap = MemoryMap(
        RamRegion(name="itcm",              start=0x00000000, length=0x80000), # 512 KB
        RomRegion(name="romcp",             start=0x00100000, length=0x40000), # 256 KB
        RamRegion(name="dtcm",              start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        FlashRegion(name="flexspi",         start=0x28000000, length=0x7FFFFFF, blocksize=0x1000,
            is_boot_memory=True, algo=FLASH_ALGO, page_size=0x4000, flash_class=FlexSpiFlash),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )

class MIMX95_CM33(CoreSightTarget):

    VENDOR = "NXP"

    memoryMap = MemoryMap(
        RamRegion(name="codetcm",           start=0x1ffc0000, length=0x40000, is_boot_memory=True), # 256 KB
        RomRegion(name="romcp",             start=0x00000000, length=0x40000), # 256 KB
        RamRegion(name="systemtcm",         start=0x20000000, length=0x40000), # 256 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )

    def __init__(self, link):
        super(MIMX95_CM33, self).__init__(link, self.memoryMap)

    def create_init_sequence(self):
        seq = super(MIMX95_CM33, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('find_aps', self.find_aps)
            )
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def disconnect(self, resume: bool = True):
        # The CM33 runs the System Manager, which must not stay halted or under debug control.
        super().disconnect(True)

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        # A CM33 reset is a SoC reset, and an emulated reset points VTOR at the flash, so an
        # exception taken while the algo runs locks the core up. Halt only.
        self.halt()

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return
        self.dp.read_ap(0xFC)
        self.dp.valid_aps = [3]
        AccessPort.create(self.dp, APv1Address(0))

    def create_cores(self):
        core0 = CortexM(self.session, self.aps[3], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.DEFAULT

        self.aps[3].core = core0

        core0.init()

        self.add_core(core0)

        self.ap3 = self.aps[3]

class MIMX95_CM33_MX25UM(MIMX95_CM33):

    VENDOR = "NXP"

    memoryMap = MemoryMap(
        RamRegion(name="codetcm",           start=0x1ffc0000, length=0x40000), # 256 KB
        RomRegion(name="romcp",             start=0x00000000, length=0x40000), # 256 KB
        RamRegion(name="systemtcm",         start=0x20000000, length=0x40000), # 256 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        FlashRegion(name="flexspi",         start=0x28000000, length=0x7FFFFFF, blocksize=0x1000,
            is_boot_memory=True, algo=FLASH_ALGO, page_size=0x4000, flash_class=FlexSpiFlashCm33),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )
