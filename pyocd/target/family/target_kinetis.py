# pyOCD debugger
# Copyright (c) 2020 NXP
# Copyright (c) 2006-2018 Arm Limited
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

from ...coresight import ap
from ...coresight.cortex_m import CortexM
from ...core import exceptions
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...utility.timeout import Timeout

MDM_STATUS = 0x00000000
MDM_CTRL = 0x00000004
MDM_IDR = 0x000000fc

MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE = (1 << 0)
MDM_STATUS_FLASH_READY = (1 << 1)
MDM_STATUS_SYSTEM_SECURITY = (1 << 2)
MDM_STATUS_MASS_ERASE_ENABLE = (1 << 5)
MDM_STATUS_CORE_HALTED = (1 << 16)

MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS = (1 << 0)
MDM_CTRL_DEBUG_REQUEST = (1 << 2)
MDM_CTRL_SYSTEM_RESET_REQUEST = (1 << 3)
MDM_CTRL_CORE_HOLD_RESET = (1 << 4)

MDM_IDR_EXPECTED = 0x001c0000
MDM_IDR_VERSION_MASK = 0xf0
MDM_IDR_VERSION_SHIFT = 4

HALT_TIMEOUT = 2.0
MASS_ERASE_TIMEOUT = 10.0

ACCESS_TEST_ATTEMPTS = 10

LOG = logging.getLogger(__name__)

class Kinetis(CoreSightTarget):
    """! @brief Family class for NXP Kinetis devices.
    """

    VENDOR = "NXP"

    def __init__(self, session, memory_map=None):
        super(Kinetis, self).__init__(session, memory_map)
        self.mdm_ap = None
        self._force_halt_on_connect = False

    def create_init_sequence(self):
        seq = super(Kinetis, self).create_init_sequence()

        seq.wrap_task('discovery',  lambda seq: \
                                        seq.insert_before('find_components',
                                            ('check_mdm_ap_idr',        self.check_mdm_ap_idr),
                                            ('check_flash_security',    self.check_flash_security),
                                            ))

        return seq

    def check_mdm_ap_idr(self):
        if not self.dp.aps:
            LOG.debug('Not found valid aps, skip MDM-AP check.')
            return

        self.mdm_ap = self.dp.aps[1]

        # Check MDM-AP ID.
        if (self.mdm_ap.idr & ~MDM_IDR_VERSION_MASK) != MDM_IDR_EXPECTED:
            LOG.error("%s: bad MDM-AP IDR (is 0x%08x)", self.part_number, self.mdm_ap.idr)

        self.mdm_ap_version = (self.mdm_ap.idr & MDM_IDR_VERSION_MASK) >> MDM_IDR_VERSION_SHIFT
        LOG.debug("MDM-AP version %d", self.mdm_ap_version)

    def check_flash_security(self):
        """! @brief Check security and unlock device.

        This init task determines whether the device is locked (flash security enabled). If it is,
        and if auto unlock is enabled, then perform a mass erase to unlock the device.

        This whole sequence is greatly complicated by some behaviour of the device when flash is
        blank. If flash is blank and the device does not have a ROM, then it will repeatedly enter
        lockup and then reset.

        Immediately after reset asserts, the flash controller begins to initialise. The device is
        always locked, and flash security reads as enabled, until the flash controller has finished
        its init sequence. Thus, depending on exactly when the debugger reads the MDM-AP status
        register, a blank, unlocked device may be detected as locked.

        There is also the possibility that the device will be (correctly) detected as unlocked, but
        it resets again before the core can be halted, thus causing connect to fail.

        This init task runs *before* cores are created.
        """
        if not self.dp.aps:
            return

        # check for flash security
        isLocked = self.is_locked()

        # Test whether we can reliably access the memory and the core. This test can fail if flash
        # is blank and the device is auto-resetting.
        if isLocked:
            canAccess = False
        else:
            try:
                # Ensure to use AP#0 as a MEM_AP
                if isinstance(self.aps[0], ap.MEM_AP):
                    for attempt in range(ACCESS_TEST_ATTEMPTS):
                        self.aps[0].read32(CortexM.DHCSR)
            except exceptions.TransferError:
                LOG.debug("Access test failed with fault")
                canAccess = False
            else:
                canAccess = True

        # Verify locked status under reset. We only want to assert reset if the device looks locked
        # or accesses fail, otherwise we could not support attach mode debugging.
        if not canAccess:
            # Keep the target in reset until is had been erased and halted. It will be deasserted
            # later, in perform_halt_on_connect().
            #
            # Ideally we would use the MDM-AP to hold the device in reset, but SYSTEM_RESET_REQUEST
            # cannot be written in MDM_CTRL when the device is locked in MDM-AP version 0.
            self.dp.assert_reset(True)

            # Re-read locked status under reset.
            isLocked = self.is_locked()

            # If the device isn't really locked, we have no choice but to halt on connect.
            if not isLocked and self.session.options.get('connect_mode') == 'attach':
                LOG.warning("Forcing halt on connect in order to gain control of device")
                self._force_halt_on_connect = True

        # Only do a mass erase if the device is actually locked.
        if isLocked:
            if self.session.options.get('auto_unlock'):
                LOG.warning("%s in secure state: will try to unlock via mass erase", self.part_number)

                # Do the mass erase.
                if not self.mass_erase():
                    self.dp.assert_reset(False)
                    self.mdm_ap.write_reg(MDM_CTRL, 0)
                    LOG.error("%s: mass erase failed", self.part_number)
                    raise exceptions.TargetError("unable to unlock device")

                # Assert that halt on connect was forced above. Reset will stay asserted
                # until halt on connect is executed.
                # assert self._force_halt_on_connect

#                 isLocked = False
            else:
                LOG.warning("%s in secure state: not automatically unlocking", self.part_number)
        else:
            LOG.info("%s not in secure state", self.part_number)

    def perform_halt_on_connect(self):
        """! This init task runs *after* cores are created."""
        if self.session.options.get('connect_mode') == 'under-reset' or self._force_halt_on_connect:
            if not self.mdm_ap:
                return
            LOG.info("Configuring MDM-AP to halt when coming out of reset")
            # Prevent the target from resetting if it has invalid code
            with Timeout(HALT_TIMEOUT) as to:
                while to.check():
                    self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET)
                    if self.mdm_ap.read_reg(MDM_CTRL) & (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET) == (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET):
                        break
                else:
                    raise exceptions.TimeoutError("Timed out attempting to set DEBUG_REQUEST and CORE_HOLD_RESET in MDM-AP")

            # Enable debug
            self.aps[0].write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)

        else:
            super(Kinetis, self).perform_halt_on_connect()

    def post_connect(self):
        if self.session.options.get('connect_mode') == 'under-reset' or self._force_halt_on_connect:
            if not self.mdm_ap:
                return
            # We can now deassert reset.
            LOG.info("Deasserting reset post connect")
            self.dp.assert_reset(False)

            # Disable holding the core in reset, leave MDM halt on
            self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)

            # Wait until the target is halted
            with Timeout(HALT_TIMEOUT) as to:
                while to.check():
                    if self.mdm_ap.read_reg(MDM_STATUS) & MDM_STATUS_CORE_HALTED == MDM_STATUS_CORE_HALTED:
                        break
                    LOG.debug("Waiting for mdm halt")
                    sleep(0.01)
                else:
                    raise exceptions.TimeoutError("Timed out waiting for core to halt")

            # release MDM halt once it has taken effect in the DHCSR
            self.mdm_ap.write_reg(MDM_CTRL, 0)

            # sanity check that the target is still halted
            if self.get_state() == Target.State.RUNNING:
                raise exceptions.DebugError("Target failed to stay halted during init sequence")

    def is_locked(self):
        if not self.mdm_ap:
            return False

        self._wait_for_flash_init()

        val = self.mdm_ap.read_reg(MDM_STATUS)
        return (val & MDM_STATUS_SYSTEM_SECURITY) != 0

    def _wait_for_flash_init(self):
        # Wait until flash is inited.
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.mdm_ap.read_reg(MDM_STATUS)
                if status & MDM_STATUS_FLASH_READY:
                    break
                sleep(0.01)
        return not to.did_time_out

    def mass_erase(self):
        """! @brief Perform a mass erase operation.
        @note Reset is held for the duration of this function.
        @return True Mass erase succeeded.
        @return False Mass erase failed or is disabled.
        """
        # Read current reset state so we can restore it, then assert reset if needed.
        wasResetAsserted = self.dp.is_reset_asserted()
        if not wasResetAsserted:
            self.dp.assert_reset(True)

        # Perform the erase.
        result = self._mass_erase()

        # Restore previous reset state.
        if not wasResetAsserted:
            self.dp.assert_reset(False)
        return result

    def _mass_erase(self):
        """! @brief Private mass erase routine."""
        # Flash must finish initing before we can mass erase.
        if not self._wait_for_flash_init():
            LOG.error("Mass erase timeout waiting for flash to finish init")
            return False

        # Check if mass erase is enabled.
        status = self.mdm_ap.read_reg(MDM_STATUS)
        if not (status & MDM_STATUS_MASS_ERASE_ENABLE):
            LOG.error("Mass erase disabled. MDM status: 0x%x", status)
            return False

        # Set Flash Mass Erase in Progress bit to start erase.
        self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS)

        # Wait for Flash Mass Erase Acknowledge to be set.
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                val = self.mdm_ap.read_reg(MDM_STATUS)
                if val & MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE:
                    break
                sleep(0.1)
            else: #if to.did_time_out:
                LOG.error("Mass erase timeout waiting for Flash Mass Erase Ack to set")
                return False

        # Wait for Flash Mass Erase in Progress bit to clear when erase is completed.
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                val = self.mdm_ap.read_reg(MDM_CTRL)
                if ((val & MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS) == 0):
                    break
                sleep(0.1)
            else: #if to.did_time_out:
                LOG.error("Mass erase timeout waiting for Flash Mass Erase in Progress to clear")
                return False

        # Confirm the part was unlocked
        val = self.mdm_ap.read_reg(MDM_STATUS)
        if (val & MDM_STATUS_SYSTEM_SECURITY) == 0:
            LOG.warning("%s secure state: unlocked successfully", self.part_number)
            return True
        else:
            LOG.error("Failed to unlock. MDM status: 0x%x", val)
            return False

