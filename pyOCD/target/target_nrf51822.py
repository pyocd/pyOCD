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

from cortex_m import CortexM, DHCSR, DBGKEY, C_DEBUGEN, C_MASKINTS, C_STEP, DEMCR, VC_CORERESET, NVIC_AIRCR, NVIC_AIRCR_VECTKEY, NVIC_AIRCR_SYSRESETREQ
from pyOCD.target.target import TARGET_RUNNING, TARGET_HALTED
import logging

# NRF51 specific registers
RESET = 0x40000544
RESET_ENABLE = (1 << 0)

class NRF51822(CortexM):

    memoryMapXML =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x0" length="0x40000"> <property name="blocksize">0x400</property></memory>
    <memory type="ram" start="0x20000000" length="0x4000"> </memory>
</memory-map>
"""
    
    def __init__(self, transport):
        super(NRF51822, self).__init__(transport)
        self.auto_increment_page_size = 0x400

    def reset(self, software_reset = True):
        """
        reset a core. After a call to this function, the core
        is running
        """
        # Keep call to CortexM version of reset but make the default a
        # software reset since a hardware reset does not work when 
        # debugging is enabled
        CortexM.reset(self, software_reset)

    def resetn(self):
        """
        reset a core. After a call to this function, the core
        is running
        """
        #Regular reset will kick NRF out of DBG mode
        logging.debug("target_nrf518.reset: enable reset pin")
        self.writeMemory(RESET, RESET_ENABLE)
        #reset
        logging.debug("target_nrf518.reset: trigger nRST pin")
        CortexM.reset(self)

    def resetStopOnReset(self, software_reset = True):
        """
        perform a reset and stop the core on the reset handler
        """
        # Keep call to CortexM version of resetStopOnReset but make 
        # the default a software reset since a hardware reset does 
        # not work when debugging is enabled
        CortexM.resetStopOnReset(self, software_reset)
