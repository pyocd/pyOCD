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

from ...core import exceptions
from ...core.coresight_target import CoreSightTarget
from ...core.target import Target
from ...coresight.cortex_m import CortexM
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)


class CortexM_PSoC6(CortexM):
    VTBASE_CM0 = None
    VTBASE_CM4 = None

    def reset(self, reset_type=None):
        self.session.notify(Target.Event.PRE_RESET, self)
        self._run_token += 1
        if reset_type is Target.ResetType.HW:
            self.session.probe.reset()
            sleep(0.5)
            self._ap.dp.init()
            self._ap.dp.power_up_debug()
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
                        self._ap.dp.init()
                        self._ap.dp.power_up_debug()
                    except exceptions.TransferError:
                        self.flush()

                    sleep(0.01)

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
    CoretxM_Core = None

    def __init__(self, link, CoretxM_Core, MemoryMap):
        self.CoretxM_Core = CoretxM_Core
        super(PSoC6, self).__init__(link, MemoryMap)

    def create_init_sequence(self):
        seq = super(PSoC6, self).create_init_sequence()
        seq.replace_task('create_cores', self.create_psoc_cores)
        return seq

    def create_psoc_cores(self):
        core0 = self.CoretxM_Core(self.session, self.aps[1], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.SW_SYSRESETREQ
        core1 = self.CoretxM_Core(self.session, self.aps[2], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.SW_SYSRESETREQ

        self.aps[1].core = core0
        self.aps[2].core = core1
        core0.init()
        core1.init()
        self.add_core(core0)
        self.add_core(core1)


class CortexM_PSoC64(CortexM):
    TEST_MODE_ADDR = None
    IPC2_DATA_ADDR = None
    CM4_PWR_CTL_ADDR = None

    IPC2_DATA_MAGIC = 0x12344321
    TEST_MODE_VALUE = 0x80000000
    CM4_PWR_CTL_VALUE = 0x05FA0003

    def __init__(self, session, ap, memoryMap, core_num, acquire_timeout):
        self._acquire_timeout = acquire_timeout
        super(CortexM_PSoC64, self).__init__(session, ap, memoryMap, core_num)

    @property
    def acquire_timeout(self):
        return self._acquire_timeout

    @acquire_timeout.setter
    def acquire_timeout(self, value):
        self._acquire_timeout = value

    def reset(self, reset_type=None):
        self.session.notify(Target.Event.PRE_RESET, self)

        self._run_token += 1

        if reset_type is Target.ResetType.HW:
            self.session.probe.reset()
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
                    self._ap.dp.init()
                    self._ap.dp.power_up_debug()
                    dhcsr_reg = self.read32(CortexM.DHCSR)
                    if (dhcsr_reg & CortexM.S_RESET_ST) == 0:
                        break
                    self.flush()
                except exceptions.TransferError:
                    sleep(0.01)

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
                    self._ap.dp.init()
                    self._ap.dp.power_up_debug()
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
                    self._ap.dp.init()
                    self._ap.dp.power_up_debug()
                    self.write32(self.IPC2_DATA_ADDR, 0)
                    self.write32(self.TEST_MODE_ADDR, self.TEST_MODE_VALUE)
                    self.flush()
                    break
                except exceptions.TransferError:
                    pass

            else:
                LOG.warning("Failed to enter test mode")

    def reset_and_halt(self, reset_type=None):
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
                    if self.read32(self.IPC2_DATA_ADDR) == self.IPC2_DATA_MAGIC:
                        break
                except exceptions.TransferError:
                    pass

        if not t_o.check():
            LOG.warning("Failed to acquire the target (listen window not implemented?)")

        try:
            if self.ap.ap_num == 2 and self.read32(self.CM4_PWR_CTL_ADDR) & 3 != 3:
                LOG.debug("CM4 is sleeping, trying to wake it up...")
                self.write32(self.CM4_PWR_CTL_ADDR, self.CM4_PWR_CTL_VALUE)
        except exceptions.TransferError:
            pass

        self.halt()
        self.wait_halted()
        self.write_core_register('xpsr', CortexM.XPSR_THUMB)

    def resume(self):
        from .flash_psoc6 import Flash_PSoC64
        super(CortexM_PSoC64, self).resume()

        if not Flash_PSoC64.isFlashing:
            LOG.info("Clearing TEST_MODE bit...")
            self.write32(self.TEST_MODE_ADDR, 0)
            self.flush()


class CortexM_PSoC64_BLE2(CortexM_PSoC64):
    TEST_MODE_ADDR = 0x40260100
    IPC2_DATA_ADDR = 0x4023004C
    CM4_PWR_CTL_ADDR = 0x40210080


class CortexM_PSoC64_A2M(CortexM_PSoC64):
    TEST_MODE_ADDR = 0x40260100
    IPC2_DATA_ADDR = 0x4022004C
    CM4_PWR_CTL_ADDR = 0x40201200


class PSoC64(CoreSightTarget):
    VENDOR = "Cypress"
    AP_NUM = None
    CoretxM_Core = None

    def __init__(self, link, CoretxM_Core, MemoryMap, ap_num):
        self.CoretxM_Core = CoretxM_Core
        self.DEFAULT_ACQUIRE_TIMEOUT = 25.0
        self.AP_NUM = ap_num
        super(PSoC64, self).__init__(link, MemoryMap)

    def create_init_sequence(self):
        seq = super(PSoC64, self).create_init_sequence()
        seq.replace_task('find_aps', self.find_aps)
        seq.replace_task('create_cores', self.create_psoc_core)
        return seq

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return

        self.dp.valid_aps = (self.AP_NUM,)

    def create_psoc_core(self):
        core = self.CoretxM_Core(self.session, self.aps[self.AP_NUM], self.memory_map, 0, self.DEFAULT_ACQUIRE_TIMEOUT)
        core.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[self.AP_NUM].core = core
        core.init()
        self.add_core(core)
