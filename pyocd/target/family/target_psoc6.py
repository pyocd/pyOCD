# pyOCD debugger
# Copyright (c) 2013-2019 Arm Limited
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

from pyocd.coresight.generic_mem_ap import GenericMemAPTarget
from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (MemoryMap, RamRegion)
from ...core.target import Target
from ...coresight.cortex_m import CortexM
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)


class CortexM_PSoC6(CortexM):
    VTBASE_CM0 = None
    VTBASE_CM4 = None

    def reset(self, reset_type=None):
        if reset_type is not Target.ResetType.HW:
            self.session.notify(Target.Event.PRE_RESET, self)
        self._run_token += 1
        if reset_type is Target.ResetType.HW:
            self._ap.dp.reset()
            sleep(0.5)
            self._ap.dp.connect()
            self.fpb.enable()
        else:
            if reset_type is Target.ResetType.SW_VECTRESET:
                mask = CortexM.NVIC_AIRCR_VECTRESET
            else:
                mask = CortexM.NVIC_AIRCR_SYSRESETREQ

            try:
                self.write_memory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | mask)
                self.flush()
            except exceptions.TransferError:
                self.flush()

        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    dhcsr_reg = self.read32(CortexM.DHCSR)
                    if (dhcsr_reg & CortexM.S_RESET_ST) == 0:
                        break
                except exceptions.TransferError:
                    self.flush()
                    try:
                        self._ap.dp.connect()
                    except exceptions.TransferError:
                        self.flush()

                    sleep(0.01)

        if reset_type is not Target.ResetType.HW:
            self.session.notify(Target.Event.POST_RESET, self)

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

    def reset_and_halt(self, reset_type=None):
        self.halt()
        self.reset(reset_type)
        sleep(0.5)
        self.halt()
        self.wait_halted()

        if self.core_number == 0:
            vtbase = self.read_memory(self.VTBASE_CM0)
        elif self.core_number == 1:
            vtbase = self.read_memory(self.VTBASE_CM4)
        else:
            raise exceptions.TargetError("Invalid CORE ID")

        vtbase &= 0xFFFFFF00
        if vtbase < 0x10000000 or vtbase > 0x10200000:
            LOG.info("Vector Table address invalid (0x%08X), will not halt at main()", vtbase)
            return

        entry = self.read_memory(vtbase + 4)
        if entry < 0x10000000 or entry > 0x10200000:
            LOG.info("Entry Point address invalid (0x%08X), will not halt at main()", entry)
            return

        self.set_breakpoint(entry)
        self.bp_manager.flush()
        self.reset(self.ResetType.SW_SYSRESETREQ)
        sleep(0.2)
        self.wait_halted()
        self.remove_breakpoint(entry)
        self.bp_manager.flush()


class CortexM_PSoC6_BLE2(CortexM_PSoC6):
    VTBASE_CM0 = 0x402102B0
    VTBASE_CM4 = 0x402102C0


class CortexM_PSoC6_A2M(CortexM_PSoC6):
    VTBASE_CM0 = 0x40201120
    VTBASE_CM4 = 0x40200200


class PSoC6(CoreSightTarget):
    VENDOR = "Cypress"
    cortex_m_core_class = None

    def __init__(self, session, cortex_m_core_class, memory_map):
        self.cortex_m_core_class = cortex_m_core_class
        super(PSoC6, self).__init__(session, memory_map)

    def create_init_sequence(self):
        seq = super(PSoC6, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_psoc_cores)
            )
        return seq

    def create_psoc_cores(self):
        core0 = self.cortex_m_core_class(self.session, self.aps[1], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.SW_SYSRESETREQ
        core1 = self.cortex_m_core_class(self.session, self.aps[2], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.SW_SYSRESETREQ

        self.aps[1].core = core0
        self.aps[2].core = core1
        core0.init()
        core1.init()
        self.add_core(core0)
        self.add_core(core1)


class CortexM_PSoC64(CortexM):
    TEST_MODE_ADDR = None
    MAGIC_NUM_ADDR = None
    CM4_PWR_CTL_ADDR = None

    MAGIC_NUM_VALUE = 0x12344321
    TEST_MODE_VALUE = 0x80000000
    CM4_PWR_CTL_VALUE = 0x05FA0003

    def __init__(self, session, ap, memory_map, core_num, acquire_timeout):
        self._acquire_timeout = acquire_timeout
        self._skip_reset_and_halt = False
        super(CortexM_PSoC64, self).__init__(session, ap, memory_map, core_num)

    @property
    def acquire_timeout(self):
        return self._acquire_timeout

    @acquire_timeout.setter
    def acquire_timeout(self, value):
        self._acquire_timeout = value

    @property
    def skip_reset_and_halt(self):
        return self._skip_reset_and_halt

    @skip_reset_and_halt.setter
    def skip_reset_and_halt(self, value):
        self._skip_reset_and_halt = value

    def reset(self, reset_type=None):
        if reset_type is not Target.ResetType.HW:
            self.session.notify(Target.Event.PRE_RESET, self)

        self._run_token += 1

        if reset_type is Target.ResetType.HW:
            self._ap.dp.reset()
            self.reinit_dap()
            self.fpb.enable()

        else:
            if reset_type is Target.ResetType.SW_VECTRESET:
                mask = CortexM.NVIC_AIRCR_VECTRESET
            else:
                mask = CortexM.NVIC_AIRCR_SYSRESETREQ

            try:
                self.write_memory(CortexM.NVIC_AIRCR, CortexM.NVIC_AIRCR_VECTKEY | mask)
                self.flush()
            except exceptions.TransferError:
                self.flush()

        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    self._ap.dp.connect()
                    dhcsr_reg = self.read32(CortexM.DHCSR)
                    if (dhcsr_reg & CortexM.S_RESET_ST) == 0:
                        break
                    self.flush()
                except exceptions.TransferError:
                    pass

        if reset_type is not Target.ResetType.HW:
            self.session.notify(Target.Event.POST_RESET, self)

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
                raise Exception("Timeout waiting for target halt")

    def reinit_dap(self):
        with Timeout(2.0) as t_o:
            while t_o.check():
                try:
                    self._ap.dp.connect()
                    self.flush()
                    break
                except exceptions.TransferError:
                    self.flush()

            else:
                LOG.error("Failed to initialize DAP")

    def acquire(self):
        with Timeout(self.acquire_timeout) as t_o:
            while t_o.check():
                try:
                    self._ap.dp.connect()
                    # self.write32(self.IPC2_DATA_ADDR, 0)
                    self.write32(self.TEST_MODE_ADDR, self.TEST_MODE_VALUE)
                    self.flush()
                    break
                except exceptions.TransferError:
                    pass

            else:
                LOG.warning("Failed to enter test mode")

    def check_flashboot_ver(self):
        fb_ver_hi = self.read32(0x16002004)
        fb_ver_lo = self.read32(0x16002018)
        b0 = fb_ver_hi >> 28
        b1 = (fb_ver_hi >> 24) & 0xF
        b2 = (fb_ver_hi >> 16) & 0xFF
        b3 = fb_ver_hi & 0x0000FFFF
        if b3 != 0x8001 or b0 != 2:
            LOG.error("Flash Boot is corrupted or non Flash Boot image programmed")
            return

        patch = fb_ver_lo >> 24
        if b1 == 4 and b2 == 0 and patch == 0:
            LOG.warning("Pre-production version of device is detected which is incompatible with this software")
            LOG.warning("Please contact Cypress for new production parts")

        return

    def reset_and_halt(self, reset_type=None):
        if self.skip_reset_and_halt:
            return

        LOG.info("Acquiring target...")

        self.reset(self.ResetType.SW_SYSRESETREQ)
        try:
            self.flush()
        except exceptions.TransferError:
            pass

        self.acquire()

        with Timeout(self.acquire_timeout) as t_o:
            while t_o.check():
                try:
                    if self.read32(self.MAGIC_NUM_ADDR) == self.MAGIC_NUM_VALUE:
                        break
                except exceptions.TransferError:
                    pass

        if not t_o.check():
            LOG.warning("Failed to acquire the target (listen window not implemented?)")

        self.check_flashboot_ver()

        with Timeout(self.acquire_timeout) as t_o:
            while t_o.check():
                try:
                    self._ap.dp.connect()
                    self.halt()
                    self.wait_halted()
                    self.write_core_register('xpsr', CortexM.XPSR_THUMB)
                    break
                except exceptions.TransferError:
                    pass

    def resume(self):
        from .flash_psoc6 import Flash_PSoC64
        super(CortexM_PSoC64, self).resume()

        if not Flash_PSoC64.isFlashing:
            LOG.info("Clearing TEST_MODE bit...")
            self.write32(self.TEST_MODE_ADDR, 0)
            self.flush()


class CortexM_PSoC64_BLE2(CortexM_PSoC64):
    TEST_MODE_ADDR = 0x40260100
    MAGIC_NUM_ADDR = 0x08044804
    CM4_PWR_CTL_ADDR = 0x40210080


class CortexM_PSoC64_A2M(CortexM_PSoC64):
    TEST_MODE_ADDR = 0x40260100
    MAGIC_NUM_ADDR = 0x080FE004
    CM4_PWR_CTL_ADDR = 0x40201200


class CortexM_PSoC64_A512K(CortexM_PSoC64):
    TEST_MODE_ADDR = 0x40260100
    MAGIC_NUM_ADDR = 0x0803E004
    CM4_PWR_CTL_ADDR = 0x40201200


class SYS_AP_PSoC64(GenericMemAPTarget):
    def __init__(self, session, ap, memory_map, core_num, acquire_timeout):
        self._acquire_timeout = acquire_timeout
        self._skip_reset_and_halt = False
        super(SYS_AP_PSoC64, self).__init__(session, ap, memory_map, core_num)

    @property
    def acquire_timeout(self):
        return self._acquire_timeout

    @acquire_timeout.setter
    def acquire_timeout(self, value):
        self._acquire_timeout = value

    @property
    def skip_reset_and_halt(self):
        return self._skip_reset_and_halt

    @skip_reset_and_halt.setter
    def skip_reset_and_halt(self, value):
        self._skip_reset_and_halt = value

    def reset(self, reset_type=None):
        self.session.notify(Target.Event.PRE_RESET, self)
        try:
            self.ap.dp.reset()
        except exceptions.TransferError:
            pass

        with Timeout(self._acquire_timeout) as t_o:
            while t_o.check():
                try:
                    self._ap.dp.connect()
                    break
                except exceptions.TransferError:
                    pass

        self.session.notify(Target.Event.POST_RESET, self)


class PSoC64(CoreSightTarget):
    VENDOR = "Cypress"
    AP_NUM = None
    cortex_m_core_class = None

    def __init__(self, session, cortex_m_core_class, memory_map, ap_num):
        self.cortex_m_core_class = cortex_m_core_class
        self.AP_NUM = ap_num
        self.DEFAULT_ACQUIRE_TIMEOUT = 25.0
        super(PSoC64, self).__init__(session, memory_map)

    def create_init_sequence(self):
        seq = super(PSoC64, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq
                        .replace_task('find_aps', self.find_aps)
                        .replace_task('create_cores', self.create_psoc_core)
            )
        return seq

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return

        if self.AP_NUM:
            self.dp.valid_aps = (0, self.AP_NUM,)
        else:
            self.dp.valid_aps = (0,)

    def create_psoc_core(self):
        sysap = SYS_AP_PSoC64(self.session, self.aps[0], self.memory_map, 0, self.DEFAULT_ACQUIRE_TIMEOUT)
        sysap.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[0].core = sysap
        sysap.init()
        self.add_core(sysap)

        if self.AP_NUM:
            core = self.cortex_m_core_class(self.session, self.aps[self.AP_NUM], self.memory_map, 1,
                                     self.DEFAULT_ACQUIRE_TIMEOUT)
            core.default_reset_type = self.ResetType.SW_SYSRESETREQ
            self.aps[self.AP_NUM].core = core
            core.init()
            self.add_core(core)
            self.selected_core = 1


class cy8c64_sysap(PSoC64):
    MEMORY_MAP = MemoryMap(RamRegion(start=0, length=0x100000000))

    def __init__(self, session):
        super(cy8c64_sysap, self).__init__(session, None, self.MEMORY_MAP, 0)
