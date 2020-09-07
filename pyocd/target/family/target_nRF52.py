# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2019 Monadnock Systems Ltd.
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

from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...debug.svd.loader import SVDFile
from ...utility.timeout import Timeout
import logging
from time import sleep

AHB_AP_NUM = 0x0
CTRL_AP_NUM = 0x1

CTRL_AP_RESET = 0x000
CTRL_AP_ERASEALL = 0x004
CTRL_AP_ERASEALLSTATUS = 0x008
CTRL_AP_APPROTECTSTATUS = 0x00C
CTRL_AP_IDR = 0x0FC

CTRL_AP_ERASEALLSTATUS_READY = 0x0
CTRL_AP_ERASEALLSTATUS_BUSY = 0x1

CTRL_AP_APPROTECTSTATUS_ENABLED = 0x0
CTRL_AP_APPROTECTSTATUS_DISABLED = 0x1

CTRL_AP_RESET_NORESET = 0x0
CTRL_AP_RESET_RESET = 0x1

CTRL_AP_ERASEALL_NOOPERATION = 0x0
CTRL_AP_ERASEALL_ERASE = 0x1

CTRL_IDR_EXPECTED = 0x2880000
CTRL_IDR_VERSION_MASK = 0xf0000000
CTRL_IDR_VERSION_SHIFT = 28

MASS_ERASE_TIMEOUT = 15.0

LOG = logging.getLogger(__name__)


class NRF52(CoreSightTarget):

    VENDOR = "Nordic Semiconductor"

    def __init__(self, session, memory_map=None):
        super(NRF52, self).__init__(session, memory_map)
        self._svd_location = SVDFile.from_builtin("nrf52.svd")
        self.ctrl_ap = None

    def create_init_sequence(self):
        seq = super(NRF52, self).create_init_sequence()

        # Must check whether security is enabled, and potentially auto-unlock, before
        # any init tasks that require system bus access.
        seq.wrap_task('discovery',
            lambda seq: seq.insert_before('find_components',
                              ('check_ctrl_ap_idr', self.check_ctrl_ap_idr),
                              ('check_flash_security', self.check_flash_security),
                          )
            )

        return seq

    def check_ctrl_ap_idr(self):
        self.ctrl_ap = self.dp.aps[CTRL_AP_NUM]

        # Check CTRL-AP ID.
        if (self.ctrl_ap.idr & ~CTRL_IDR_VERSION_MASK) != CTRL_IDR_EXPECTED:
            LOG.error("%s: bad CTRL-AP IDR (is 0x%08x)", self.part_number, self.ctrl_ap.idr)

        ctrl_ap_version = (self.ctrl_ap.idr & CTRL_IDR_VERSION_MASK) >> CTRL_IDR_VERSION_SHIFT
        LOG.debug("CTRL-AP version %d", ctrl_ap_version)

    def check_flash_security(self):
        """! @brief Check security and unlock device.

        This init task determines whether the device is locked (APPROTECT enabled). If it is,
        and if auto unlock is enabled, then perform a mass erase to unlock the device.

        This init task runs *before* cores are created.
        """

        if self.is_locked():
            if self.session.options.get('auto_unlock'):
                LOG.warning("%s APPROTECT enabled: will try to unlock via mass erase", self.part_number)

                # Do the mass erase.
                if not self.mass_erase():
                    LOG.error("%s: mass erase failed", self.part_number)
                    raise exceptions.TargetError("unable to unlock device")
                # Cached badness from create_ap run during AP lockout prevents create_cores from
                # succeeding.
                self.dp.create_1_ap(AHB_AP_NUM)
            else:
                LOG.warning("%s APPROTECT enabled: not automatically unlocking", self.part_number)
        else:
            LOG.info("%s not in secure state", self.part_number)

    def is_locked(self):
        status = self.ctrl_ap.read_reg(CTRL_AP_APPROTECTSTATUS)
        return status == CTRL_AP_APPROTECTSTATUS_ENABLED

    def mass_erase(self):
        # See Nordic Whitepaper nWP-027 for magic numbers and order of operations from the vendor
        self.ctrl_ap.write_reg(CTRL_AP_ERASEALL, CTRL_AP_ERASEALL_ERASE)
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.ctrl_ap.read_reg(CTRL_AP_ERASEALLSTATUS)
                if status == CTRL_AP_ERASEALLSTATUS_READY:
                    break
                sleep(0.1)
            else:
                # Timed out
                LOG.error("Mass erase timeout waiting for ERASEALLSTATUS")
                return False
        self.ctrl_ap.write_reg(CTRL_AP_RESET, CTRL_AP_RESET_RESET)
        self.ctrl_ap.write_reg(CTRL_AP_RESET, CTRL_AP_RESET_NORESET)
        self.ctrl_ap.write_reg(CTRL_AP_ERASEALL, CTRL_AP_ERASEALL_NOOPERATION)
        return True
