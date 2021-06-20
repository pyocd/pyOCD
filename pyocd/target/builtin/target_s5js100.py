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

import logging
from time import sleep
from ...flash.flash import Flash
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...core.target import Target
from ...coresight.cortex_m import CortexM
from ...core import exceptions
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)

flash_algo = {
    'load_address': 0x00100000,

    # Flash algorithm as a hex string
    'instructions': [
        0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
        0x280a49fa, 0x698ad10a, 0x7f80f012, 0x698ad1fb, 0x0f7ff412, 0x220dd1fb, 0x2020f881, 0xf012698a,
        0xd1fb7f80, 0xf412698a, 0xd1fb0f7f, 0x0020f881, 0xb1284770, 0x70116802, 0x1c496801, 0x47706001,
        0x48eab2ca, 0xd10a2a0a, 0xf0116981, 0xd1fb7f80, 0xf4116981, 0xd1fb0f7f, 0xf880210d, 0x69811020,
        0x7f80f011, 0x6981d1fb, 0x0f7ff411, 0xf880d1fb, 0x47702020, 0x41f0e92d, 0x460e1e14, 0xf04f4680,
        0xf04f0500, 0xdd100720, 0x21007832, 0xb1224630, 0x2f01f810, 0x2a001c49, 0x42a1d1fa, 0x2400bfac,
        0xf0131a64, 0xbf180f02, 0xf0132730, 0xd1090f01, 0xdd072c00, 0x46404639, 0xffbbf7ff, 0x1c6d1e64,
        0xdcf72c00, 0xb1407830, 0x4640b2c1, 0xffb1f7ff, 0x0f01f816, 0x28001c6d, 0x2c00d1f6, 0x4639dd07,
        0xf7ff4640, 0x1e64ffa6, 0x2c001c6d, 0x4628dcf7, 0x81f0e8bd, 0x45f0e92d, 0x469cb083, 0xe9dd4680,
        0x2000730b, 0x46059e0a, 0xb1294682, 0x0f00f1bc, 0x2a0ad016, 0xe013d00e, 0xf88d2030, 0xf88d0000,
        0x463ba001, 0x46694632, 0xf7ff4640, 0xb003ffa3, 0x85f0e8bd, 0x0c00f1b1, 0x2001bfbc, 0x0100f1cc,
        0x040bf10d, 0xa00bf88d, 0xfbb1b189, 0xfb02fcf2, 0xf1bc1c1c, 0xbfa40f0a, 0xf1ac449c, 0xf10c0c3a,
        0xfbb10c30, 0xf804f1f2, 0x2900cd01, 0xb178d1ed, 0xbf182e00, 0x0f02f017, 0xf04fd007, 0x4640012d,
        0xff57f7ff, 0x1e761c6d, 0x202de002, 0x0d01f804, 0x4632463b, 0x46404621, 0xff6cf7ff, 0x4428b003,
        0x85f0e8bd, 0xe92db40f, 0xb0844df0, 0x9c0c2700, 0xad0d463e, 0x28007820, 0xf04fd075, 0xf04f0b41,
        0x46ba0861, 0x2825b2c0, 0x2200d17b, 0x0f01f814, 0x28004613, 0x2825d07f, 0x282dd073, 0x2301bf04,
        0x78201c64, 0xd1052830, 0x0f01f814, 0x0302f043, 0xd0f92830, 0x3830b2c0, 0xd80a2809, 0x0082eb02,
        0xf8140040, 0x38301b01, 0x7820180a, 0x28093830, 0x7820d9f4, 0xd00a2873, 0xd0112864, 0xd01c2878,
        0xd0272858, 0xd0322875, 0xd03f2863, 0xf855e04e, 0x29001b04, 0xa16ebf08, 0xf7ff4638, 0xe024ff1b,
        0x2300e9cd, 0x8008f8cd, 0x1b04f855, 0x220a2301, 0xf7ff4638, 0x4406ff4f, 0xe9cde038, 0xf8cd2300,
        0xf8558008, 0x23001b04, 0x46382210, 0xff42f7ff, 0xe02b4406, 0x2300e9cd, 0xb008f8cd, 0x1b04f855,
        0x22102300, 0xf7ff4638, 0x4406ff35, 0xe9cde01e, 0xf8cd2300, 0xf8558008, 0x23001b04, 0x4638220a,
        0xff28f7ff, 0xe01be7f1, 0xe014e00b, 0x0b04f815, 0x000cf88d, 0xa00df88d, 0x4638a903, 0xfedaf7ff,
        0xb2c1e7e3, 0xf7ff4638, 0x1c76feb4, 0x0f01f814, 0xf47f2800, 0x2f00af77, 0x6838bf1c, 0xa000f880,
        0xb0044630, 0x0df0e8bd, 0xfb14f85d, 0xea236803, 0x43110101, 0x47706001, 0x42812100, 0x1c49bfb8,
        0x4770dbfb, 0xf44f493c, 0xf84140c6, 0x60480f70, 0x60c86088, 0x61486108, 0x21014838, 0x21006741,
        0x49376781, 0x21646041, 0x1c402000, 0xdbfc4288, 0xf04f4770, 0x48334202, 0xf8c24934, 0x48320100,
        0x49336008, 0x60081200, 0x12001d09, 0x49316008, 0x1d096008, 0x3001f04f, 0x210a6008, 0x1c402000,
        0xdbfc4288, 0x2136482c, 0x21106241, 0x21706281, 0xf24062c1, 0x63013101, 0x60012155, 0x210a4827,
        0x0100f8c2, 0x1c402000, 0xdbfc4288, 0xf3bf4770, 0xf3bf8f6f, 0x49228f4f, 0x60082000, 0x8f6ff3bf,
        0x8f4ff3bf, 0x481f4920, 0x47706008, 0x8f6ff3bf, 0x8f4ff3bf, 0x21e0f04f, 0x61082000, 0x8f6ff3bf,
        0x8f4ff3bf, 0xf3bf4770, 0xf3bf8f6f, 0x20008f4f, 0xf1004601, 0x1d0022e0, 0x1100f8c2, 0xdbf82820,
        0x8f6ff3bf, 0x8f4ff3bf, 0x00004770, 0x83015000, 0x6c756e28, 0x0000296c, 0x82021000, 0x85020000,
        0x8660061a, 0xc1900d01, 0x01000001, 0x82000a04, 0x83000a00, 0x85000a00, 0x85024000, 0xc1900d11,
        0xe000ef50, 0x00040200, 0xe000ed14, 0x20e0f04f, 0xf8402100, 0x4ab31f10, 0x7100f04f, 0x17516011,
        0x1170f8c0, 0x1174f8c0, 0x1270f8c0, 0x1274f8c0, 0x4bad4770, 0xf0406818, 0x60180002, 0x680849ab,
        0x0001f040, 0x49aa6008, 0xf0406808, 0x60080001, 0xf8d149a8, 0xb1780118, 0xf8c12200, 0x200f2100,
        0x0104f8c1, 0x0108f8d1, 0xd1fb280f, 0x2104f8c1, 0x0108f8d1, 0xd1fb2800, 0x20002264, 0x42901c40,
        0xf8d1dbfc, 0xf0200110, 0xf8c10003, 0xf8d10110, 0xf0200118, 0xf8c10003, 0xf8d10118, 0xf0200114,
        0xf8c10003, 0x68180114, 0x0002f020, 0x47706018, 0x21004891, 0x68016201, 0x0104f021, 0x47706001,
        0x45f0e92d, 0xf04f488c, 0xf8c00c00, 0x6801c020, 0x0104f021, 0xf7ff6001, 0xf3bfff1c, 0xf3bf8f6f,
        0x48868f4f, 0xc000f8c0, 0x8f6ff3bf, 0x8f4ff3bf, 0x48834984, 0xf3bf6008, 0xf3bf8f6f, 0xf04f8f4f,
        0xf3bf20e0, 0xf3bf8f6f, 0xf8c08f4f, 0x4a75c010, 0x7100f04f, 0x17516011, 0x1180f8c0, 0x1184f8c0,
        0x1280f8c0, 0x1284f8c0, 0x8f6ff3bf, 0x8f4ff3bf, 0xf1002000, 0x1d0021e0, 0xc100f8c1, 0xdbf82820,
        0x8f6ff3bf, 0x8f4ff3bf, 0xff73f7ff, 0x81bcf8df, 0x486d2201, 0xf8c84b6e, 0xf2472038, 0xf8c03101,
        0xf8c3c0c4, 0xf8c31130, 0xe9c01134, 0x26032c02, 0xe9c02406, 0xe9c04c04, 0xf243c206, 0xf04f3785,
        0xe9c04502, 0xf8d56700, 0xf0155100, 0xf04f4f00, 0xbf190504, 0x6aa1f44f, 0xa20ae9c0, 0x0aa8f04f,
        0xa50ae9c0, 0x0a07f04f, 0xc038f8c0, 0x20c4f8c0, 0x2038f8c8, 0xc0c4f8c0, 0x1130f8c3, 0x1134f8c3,
        0x60476006, 0x2121f240, 0xf8c06081, 0x6104c00c, 0xc014f8c0, 0xc018f8c0, 0x216a61c2, 0x62c46281,
        0x63456305, 0xc03cf8c0, 0xa008f8c0, 0x20002164, 0x42881c40, 0xf44fdbfc, 0x671840c6, 0x67986758,
        0xf8c367d8, 0xf8c30080, 0x48420084, 0x60414942, 0x2c1de9c0, 0x20002164, 0x42881c40, 0x2000dbfc,
        0x85f0e8bd, 0xb510493b, 0x6048483c, 0xf7ffa03c, 0x2000fda9, 0xb510bd10, 0xf7ffa03b, 0x4b3dfda3,
        0xf44f4934, 0x20001480, 0x0cfff04f, 0x20dcf891, 0x0f01f012, 0xeb03d1fa, 0xf1a23200, 0x610a4280,
        0xc05ef881, 0x20dcf891, 0x0f01f012, 0x1c40d1fa, 0x3f14ebb0, 0xa030d3ea, 0xfd84f7ff, 0xbd102000,
        0x4c24b570, 0x68624605, 0xa02d4601, 0xfd7af7ff, 0x20dcf894, 0x0f01f012, 0xf1a5d1fa, 0x61204080,
        0xf88420ff, 0xf894005e, 0xf01000dc, 0xd1fa0001, 0xb570bd70, 0x44a0f100, 0x46154816, 0x6843460e,
        0x4621460a, 0xf7ffa028, 0x1cf0fd5d, 0x0003f030, 0xf855d005, 0xf8441b04, 0x1f001b04, 0x2000d1f9,
        0x0000bd70, 0xe000ed04, 0x82020460, 0x82020500, 0x82020520, 0x82020000, 0x83011000, 0xe000ef50,
        0x00040200, 0xe000ed14, 0x83015000, 0x85041000, 0x82021000, 0x85020000, 0x8660061a, 0x0660860a,
        0x6e696e55, 0x000a7469, 0x53415245, 0x48432045, 0x000a5049, 0x406f4000, 0x454e4f44, 0x0000000a,
        0x20337773, 0x53415245, 0x45532045, 0x524f5443, 0x7830202c, 0x202c7825, 0x73616c66, 0x78305b68,
        0x0a5d7825, 0x00000000, 0x676f7250, 0x206d6172, 0x3d726461, 0x78257830, 0x7a73202c, 0x2578303d,
        0x66202c78, 0x6873616c, 0x2578305b, 0x000a5d78, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x00100501,
    'pc_unInit': 0x00100665,
    'pc_program_page': 0x001006f3,
    'pc_erase_sector': 0x001006c1,
    'pc_eraseAll': 0x00100677,

    'static_base': 0x001007d0,
    'begin_stack': 0x00100a00,
    'begin_data': 0x00100000 + 0x1000,
    'page_size': 0x400,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    # 'page_buffers': [0x00101000, 0x00101400],  # Enable double buffering
    'min_program_length': 0x400

}


class Flash_s5js100(Flash):
    def __init__(self, target, flash_algo):
        super(Flash_s5js100, self).__init__(target, flash_algo)
        self._did_prepare_target = False
        # LOG.info("S5JS100.Flash_s5js100.__init__ c")

    def init(self, operation, address=None, clock=0, reset=True):
        # LOG.info("S5JS100.Flash_s5js100.init c")

        if self._active_operation != operation and self._active_operation is not None:
            self.uninit()

        super(Flash_s5js100, self).init(operation, address, clock, reset)

    def uninit(self):
        # LOG.info("S5JS100.Flash_s5js100.uninit c")
        if self._active_operation is None:
            return

        super(Flash_s5js100, self).uninit()


ERASE_ALL_WEIGHT = 140  # Time it takes to perform a chip erase
ERASE_SECTOR_WEIGHT = 1  # Time it takes to erase a page
# Time it takes to program a page (Not including data transfer time)
PROGRAM_PAGE_WEIGHT = 1


class S5JS100(CoreSightTarget):
    VENDOR = "Samsung"
    AP_NUM = 0
    ROM_ADDR = 0xE00FE000

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x406f4000, length=0x00100000,
                    page_size=0x400, blocksize=0x1000,
                    is_boot_memory=True,
                    erased_byte_value=0xFF,
                    algo=flash_algo,
                    erase_all_weight=ERASE_ALL_WEIGHT,
                    erase_sector_weight=ERASE_SECTOR_WEIGHT,
                    program_page_weight=PROGRAM_PAGE_WEIGHT,
                    flash_class=Flash_s5js100),
        RamRegion(start=0x00100000, length=0x80000)
    )

    def __init__(self, session):
        super(S5JS100, self).__init__(session, self.MEMORY_MAP)
        self.AP_NUM = 0

    def create_init_sequence(self):
        seq = super(S5JS100, self).create_init_sequence()
        seq.wrap_task(
            'discovery', lambda seq: seq.replace_task(
                'find_aps', self.find_aps).replace_task(
                'create_cores', self.create_s5js100_core).insert_before(
                'find_components', ('fixup_ap_base_addrs', self._fixup_ap_base_addrs), ))
        return seq

    def _fixup_ap_base_addrs(self):
        self.dp.aps[self.AP_NUM].rom_addr = self.ROM_ADDR

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return

        self.dp.valid_aps = (self.AP_NUM,)

    def create_s5js100_core(self):
        core = CortexM_S5JS100(
            self.session, self.aps[self.AP_NUM], self.memory_map, 0)
        core.default_reset_type = self.ResetType.SW
        self.aps[self.AP_NUM].core = core
        core.init()
        self.add_core(core)


class CortexM_S5JS100(CortexM):

    def reset(self, reset_type=None):
        # Always use software reset for S5JS100 since the hardware version
        self.session.notify(Target.Event.PRE_RESET, self)

        # LOG.info("s5js100 reset HW")
        self.S5JS100_reset_type = reset_type
        self.write_memory(0x82020018, 0x1 << 1)
        self.write_memory(0x83011000, 0x4 << 0)  # enable watchdog
        self.write_memory(0x8301100c, 0x1 << 0)
        self.write_memory(0x83011010, 0x1 << 0)
        self.write_memory(0x83011020, 0x1 << 0)
        self.write_memory(0x83011800, 0x1 << 0)  # clock gating disable
        # set 1s to be reset , 1 sec=32768
        self.write_memory(0x83011004, 32768 << 0)
        # force to load value to be reset
        self.write_memory(0x83011008, 0xFF << 0)

        xpsr = self.read_core_register('xpsr')
        if xpsr & self.XPSR_THUMB == 0:
            self.write_core_register('xpsr', xpsr | self.XPSR_THUMB)

        self.write_memory(0x120000, 0xe7fe)
        self.write_core_register('pc', 0x120000)

        self.flush()
        self.resume()
        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    dhcsr_reg = self.read32(CortexM.DHCSR)
                    LOG.debug("reg = %x", dhcsr_reg)
                    if (dhcsr_reg & CortexM.S_RESET_ST) != 0:
                        break
                    sleep(0.1)
                except exceptions.TransferError:
                    self.flush()
                    self._ap.dp.connect()
                    sleep(0.01)
            else:
                raise exceptions.TimeoutError("Timeout waiting for reset")
        self.session.notify(Target.Event.POST_RESET, self)

    def reset_and_halt(self, reset_type=None):
        # LOG.info("reset_and_halt")
        reset_catch_saved_demcr = self.read_memory(CortexM.DEMCR)
        if (reset_catch_saved_demcr & CortexM.DEMCR_VC_CORERESET) == 0:
            self.write_memory(
                CortexM.DEMCR,
                reset_catch_saved_demcr | CortexM.DEMCR_VC_CORERESET)
        self.reset(reset_type)
        sleep(0.1)
        self.halt()
        self.wait_halted()
        self.write_memory(CortexM.DEMCR, reset_catch_saved_demcr)

    def wait_halted(self):
        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    if not self.is_running():
                        break
                except exceptions.TransferError:
                    self.flush()
                    sleep(0.01)
            else:
                raise exceptions.TimeoutError("Timeout waiting for target halt")

    def get_state(self):
        # LOG.info("s5js100.get_state")
        try:
            dhcsr = self.read_memory(CortexM.DHCSR)
            # LOG.info("s5js100.get_state dhcsr 0x%x", dhcsr)
        except exceptions.TransferError:
            # LOG.info("s5js100.get_state read fail dhcsr..try more")
            self._ap.dp.connect()
            dhcsr = self.read_memory(CortexM.DHCSR)
            # LOG.info("fail s5js100.get_state dhcsr 0x%x", dhcsr)

        if dhcsr & CortexM.S_RESET_ST:
            # Reset is a special case because the bit is sticky and really means
            # "core was reset since last read of DHCSR". We have to re-read the
            # DHCSR, check if S_RESET_ST is still set and make sure no instructions
            # were executed by checking S_RETIRE_ST.
            newDhcsr = self.read_memory(CortexM.DHCSR)
            if (newDhcsr & CortexM.S_RESET_ST) and not (
                    newDhcsr & CortexM.S_RETIRE_ST):
                return Target.State.RESET
        if dhcsr & CortexM.S_LOCKUP:
            return Target.State.LOCKUP
        elif dhcsr & CortexM.S_SLEEP:
            return Target.State.SLEEPING
        elif dhcsr & CortexM.S_HALT:
            return Target.State.HALTED
        else:
            return Target.State.RUNNING

    def set_breakpoint(self, addr, type=Target.BreakpointType.HW):
        # s5js100 don't support Target.BreakpointType.SW
        return super(
            CortexM_S5JS100,
            self).set_breakpoint(
            addr,
            Target.BreakpointType.HW)
