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

from cortex_m import CortexM
import logging


MDM_STATUS = 0x01000000
MDM_CTRL = 0x01000004
MDM_IDR = 0x010000fc

class Kinetis(CortexM):
    
    def __init__(self, transport):
        CortexM.__init__(self, transport)
        self.auto_increment_page_size = 0x400
        self.mdm_idr = 0
        
    def init(self):
        CortexM.init(self, False)
        
        # check for flash security
        val = self.transport.readAP(MDM_IDR)
        if val != self.mdm_idr:
            logging.error("%s: bad MDM-AP IDR (is 0x%08x, expected 0x%08x)", self.part_number, val, self.mdm_idr)
        self.checkSecurity()
        self.halt()
        self.setupFPB()
        self.readCoreType()
        self.checkForFPU()
    
    def checkSecurity(self):
        val = self.transport.readAP(MDM_STATUS)
        if (val & (1 << 2)):
            logging.warning("%s in secure state: will try to unlock via mass erase", self.part_number)
            if not self.massErase():
                logging.error("%s: mass erase failed", self.part_number)
        else:
            logging.info("%s not in secure state", self.part_number)

    ## @brief Returns True if mass erase succeeded, False if it failed or is disabled.
    def massErase(self):
        self.transport.assertReset(True)
        
        # Wait until flash is inited.
        while True:
            status = self.transport.readAP(MDM_STATUS)
            if status & (1 << 1):
                break
        
        # Check if mass erase is enabled.
        status = self.transport.readAP(MDM_STATUS)
        if not (status & (1 << 5)):
            return False
        
        # Set Flash Mass Erase in Progress bit to start erase.
        self.transport.writeAP(MDM_CTRL, 1)
        
        # Wait for Flash Mass Erase Acknowledge to be set.
        while True:
            val = self.transport.readAP(MDM_STATUS)
            #logging.info(val)
            if (val & 1):
                break
                
        # Wait for Flash Mass Erase in Progress bit to clear when erase is completed.
        while True:
            #self.transport.writeAP(MDM_CTRL, 0)
            val = self.transport.readAP(MDM_CTRL)
            if (val == 0):
                break
        
        val = self.transport.readAP(MDM_STATUS)
        if (val & (1 << 2)) == 0:
            logging.warning("%s secure state: unlocked successfully", self.part_number)
            return True
        else:
            return False
    

        
