"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from ...coresight import (dap, ap)
from ...coresight.cortex_m import CortexM
from ...core.target import Target
from ...core.coresight_target import CoreSightTarget
from ...utility.timeout import (Timeout, TimeoutException)
import logging
from time import sleep

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
MDM_CTRL_CORE_HOLD_RESET = (1 << 4)

MASS_ERASE_TIMEOUT = 10.0

class Kinetis(CoreSightTarget):

    def __init__(self, link, memoryMap=None):
        super(Kinetis, self).__init__(link, memoryMap)
        self.mdm_idr = 0
        self.mdm_ap = None
        self.do_auto_unlock = True

    def setAutoUnlock(self, doAutoUnlock):
        self.do_auto_unlock = doAutoUnlock

    def init(self):
        super(Kinetis, self).init(bus_accessible=False)

        self.mdm_ap = ap.AccessPort(self.dp, 1)
        self.aps[1] = self.mdm_ap
        self.mdm_ap.init(False)

        # check MDM-AP ID
        if self.mdm_ap.idr != self.mdm_idr:
            logging.error("%s: bad MDM-AP IDR (is 0x%08x, expected 0x%08x)", self.part_number, self.mdm_ap.idr, self.mdm_idr)

        # check for flash security
        isLocked = self.isLocked()
        if isLocked:
            if self.do_auto_unlock:
                logging.warning("%s in secure state: will try to unlock via mass erase", self.part_number)
                # keep the target in reset until is had been erased and halted
                self.dp.assert_reset(True)
                if not self.massErase():
                    self.dp.assert_reset(False)
                    logging.error("%s: mass erase failed", self.part_number)
                    raise Exception("unable to unlock device")
                # Use the MDM to keep the target halted after reset has been released
                self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)
                # Enable debug
                self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)
                self.dp.assert_reset(False)
                while self.mdm_ap.read_reg(MDM_STATUS) & MDM_STATUS_CORE_HALTED != MDM_STATUS_CORE_HALTED:
                    logging.debug("Waiting for mdm halt (erase)")
                    sleep(0.01)

                # release MDM halt once it has taken effect in the DHCSR
                self.mdm_ap.write_reg(MDM_CTRL, 0)

                isLocked = False
            else:
                logging.warning("%s in secure state: not automatically unlocking", self.part_number)
        else:
            logging.info("%s not in secure state", self.part_number)

        # Can't do anything more if the target is secure
        if isLocked:
            return

        if self.halt_on_connect:
            # Prevent the target from resetting if it has invalid code
            self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET)
            while self.mdm_ap.read_reg(MDM_CTRL) & (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET) != (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET):
                self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET)
            # Enable debug
            self.writeMemory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)
            # Disable holding the core in reset, leave MDM halt on
            self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)

            # Wait until the target is halted
            while self.mdm_ap.read_reg(MDM_STATUS) & MDM_STATUS_CORE_HALTED != MDM_STATUS_CORE_HALTED:
                logging.debug("Waiting for mdm halt")
                sleep(0.01)

            # release MDM halt once it has taken effect in the DHCSR
            self.mdm_ap.write_reg(MDM_CTRL, 0)

            # sanity check that the target is still halted
            if self.getState() == Target.TARGET_RUNNING:
                raise Exception("Target failed to stay halted during init sequence")

        self.aps[0].init(bus_accessible=True)
        self.cores[0].init()

    def isLocked(self):
        val = self.mdm_ap.read_reg(MDM_STATUS)
        if val & MDM_STATUS_SYSTEM_SECURITY:
            return True
        else:
            return False

    ## @brief Perform a mass erase operation.
    # @note Reset should be held for the duration of this function
    # @return True Mass erase succeeded.
    # @return False Mass erase failed or is disabled.
    def massErase(self):
        # Wait until flash is inited.
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.mdm_ap.read_reg(MDM_STATUS)
                if status & MDM_STATUS_FLASH_READY:
                    break
                sleep(0.01)
        if to.did_time_out:
            logging.error("Mass erase timeout waiting for flash to finish init")
            return False

        # Check if mass erase is enabled.
        status = self.mdm_ap.read_reg(MDM_STATUS)
        if not (status & MDM_STATUS_MASS_ERASE_ENABLE):
            logging.error("Mass erase disabled. MDM status: 0x%x", status)
            return False

        # Set Flash Mass Erase in Progress bit to start erase.
        self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS)

        # Wait for Flash Mass Erase Acknowledge to be set.
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                val = self.mdm_ap.read_reg(MDM_STATUS)
                if val & MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE:
                    break
                sleep(0.01)
        if to.did_time_out:
            logging.error("Mass erase timeout waiting for Flash Mass Erase Ack to set")
            return False

        # Wait for Flash Mass Erase in Progress bit to clear when erase is completed.
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                val = self.mdm_ap.read_reg(MDM_CTRL)
                if (val == 0):
                    break
                sleep(0.01)
        if to.did_time_out:
            logging.error("Mass erase timeout waiting for Flash Mass Erase in Progress to clear")
            return False

        # Confirm the part was unlocked
        val = self.mdm_ap.read_reg(MDM_STATUS)
        if (val & MDM_STATUS_SYSTEM_SECURITY) == 0:
            logging.warning("%s secure state: unlocked successfully", self.part_number)
            return True
        else:
            logging.error("Failed to unlock. MDM status: 0x%x", val)
            return False

