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

from cortex_m import CortexM, DHCSR, DBGKEY, C_DEBUGEN, C_HALT
from pyOCD.target.target import TARGET_RUNNING
import logging
from time import sleep


MDM_STATUS = 0x01000000
MDM_CTRL = 0x01000004
MDM_IDR = 0x010000fc

MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE = (1 << 0)
MDM_STATUS_FLASH_READY = (1 << 1)
MDM_STATUS_SYSTEM_SECURITY = (1 << 2)
MDM_STATUS_MASS_ERASE_ENABLE = (1 << 5)
MDM_STATUS_CORE_HALTED = (1 << 16)

MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS = (1 << 0)
MDM_CTRL_DEBUG_REQUEST = (1 << 2)
MDM_CTRL_CORE_HOLD_RESET = (1 << 4)

# Kinetis FCF byte array to disable flash security.
fcf = [0xff] * 12
fcf += [0xfe, 0xff, 0xff, 0xff]

# Location of FCF in the memory map.
FCF_ADDR = 0x400

class Kinetis(CortexM):

    def __init__(self, transport):
        super(Kinetis, self).__init__(transport)
        self.mdm_idr = 0
        self.do_auto_unlock = True

    def setAutoUnlock(self, doAutoUnlock):
        self.do_auto_unlock = doAutoUnlock

    def init(self):
        CortexM.init(self, initial_setup=True, bus_accessible=False)

        # check MDM-AP ID
        val = self.transport.readAP(MDM_IDR)
        if val != self.mdm_idr:
            logging.error("%s: bad MDM-AP IDR (is 0x%08x, expected 0x%08x)", self.part_number, val, self.mdm_idr)

        # check for flash security
        isLocked = self.isLocked()
        if isLocked:
            if self.do_auto_unlock:
                logging.warning("%s in secure state: will try to unlock via mass erase", self.part_number)
                # keep the target in reset until is had been erased and halted
                self.transport.assertReset(True)
                if not self.massErase():
                    self.transport.assertReset(False)
                    logging.error("%s: mass erase failed", self.part_number)
                    raise Exception("unable to unlock device")
                # Use the MDM to keep the target halted after reset has been released
                self.transport.writeAP(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)
                # Enable debug
                self.writeMemory(DHCSR, DBGKEY | C_DEBUGEN)
                self.transport.assertReset(False)
                while self.transport.readAP(MDM_STATUS) & MDM_STATUS_CORE_HALTED != MDM_STATUS_CORE_HALTED:
                    logging.debug("Waiting for mdm halt (erase)")
                    sleep(0.01)

                # release MDM halt once it has taken effect in the DHCSR
                self.transport.writeAP(MDM_CTRL, 0)

                isLocked = False
            else:
                logging.warning("%s in secure state: not automatically unlocking", self.part_number)
        else:
            logging.info("%s not in secure state", self.part_number)

        # Can't do anything more if the target is secure
        if isLocked:
            return

        # Prevent the target from resetting if it has invalid code
        self.transport.writeAP(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET)
        while self.transport.readAP(MDM_CTRL) & (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET) != (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET):
            self.transport.writeAP(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET)
        # Enable debug
        self.writeMemory(DHCSR, DBGKEY | C_DEBUGEN)
        # Disable holding the core in reset, leave MDM halt on
        self.transport.writeAP(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)

        # Wait until the target is halted
        while self.transport.readAP(MDM_STATUS) & MDM_STATUS_CORE_HALTED != MDM_STATUS_CORE_HALTED:
            logging.debug("Waiting for mdm halt")
            sleep(0.01)

        # release MDM halt once it has taken effect in the DHCSR
        self.transport.writeAP(MDM_CTRL, 0)
        
        # sanity check that the target is still halted
        if self.getState() == TARGET_RUNNING:
            raise Exception("Target failed to stay halted during init sequence")

        CortexM.init(self, initial_setup=False, bus_accessible=True)

    def isLocked(self):
        val = self.transport.readAP(MDM_STATUS)
        if val & MDM_STATUS_SYSTEM_SECURITY:
            return True
        else:
            return False

    ## @brief Returns True if mass erase succeeded, False if it failed or is disabled.
    # Note: reset should be held for the duration of this function
    def massErase(self):
        # Wait until flash is inited.
        while True:
            status = self.transport.readAP(MDM_STATUS)
            if status & MDM_STATUS_FLASH_READY:
                break
            sleep(0.01)
        
        # Check if mass erase is enabled.
        status = self.transport.readAP(MDM_STATUS)
        if not (status & MDM_STATUS_MASS_ERASE_ENABLE):
            logging.error("Mass erase disabled. MDM status: 0x%x", status)
            return False
        
        # Set Flash Mass Erase in Progress bit to start erase.
        self.transport.writeAP(MDM_CTRL, MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS)
        
        # Wait for Flash Mass Erase Acknowledge to be set.
        while True:
            val = self.transport.readAP(MDM_STATUS)
            if val & MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE:
                break
            sleep(0.01)
                
        # Wait for Flash Mass Erase in Progress bit to clear when erase is completed.
        while True:
            val = self.transport.readAP(MDM_CTRL)
            if (val == 0):
                break
            sleep(0.01)
        
        # Confirm the part was unlocked
        val = self.transport.readAP(MDM_STATUS)
        if (val & MDM_STATUS_SYSTEM_SECURITY) == 0:
            logging.warning("%s secure state: unlocked successfully", self.part_number)
            return True
        else:
            logging.error("Failed to unlock. MDM status: 0x%x", val)
            return False

    ## @brief Write the unsecure FSEC value to flash.
    #
    # This will prevent the device from being secured after the next reset.
    def unlockFlash(self):
        logging.info("Unlocking chip...")

        logging.info("Performing mass erase")
        self.massErase()

        # Write FCF
        logging.info("Writing FCF = %s" % repr(fcf))
        self.flash.init()
        self.flash.programPage(FCF_ADDR, fcf)

