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

from target_kinetis import Kinetis
import logging
from cortex_m import (NVIC_AIRCR, NVIC_AIRCR_SYSRESETREQ)
from ..transport.transport import TransferError

SIM_SDID = 0x40075024
SIM_SDID_KEYATTR_MASK = 0x70
SIM_SDID_KEYATTR_SHIFT = 4

KEYATTR_DUAL_CORE = 1

class KL28x(Kinetis):

    memoryMapXMLSingle =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x0" length="0x80000"> <property name="blocksize">0x800</property></memory>
    <memory type="ram" start="0x1fff8000" length="0x20000"> </memory>
    <memory type="ram" start="0x40100000" length="0x800"> </memory>
</memory-map>
"""

    memoryMapXMLDual =  """<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="flash" start="0x0" length="0x80000"> <property name="blocksize">0x800</property></memory>
    <memory type="flash" start="0x1d200000" length="0x40000"> <property name="blocksize">0x800</property></memory>
    <memory type="ram" start="0x1fffa000" length="0x12000"> </memory>
    <memory type="flash" start="0x2d200000" length="0x40000"> <property name="blocksize">0x800</property></memory>
    <memory type="ram" start="0x2d300000" length="0x8000"> </memory>
    <memory type="ram" start="0x40100000" length="0x800"> </memory>
</memory-map>
"""

    def __init__(self, transport):
        super(KL28x, self).__init__(transport)
        self.mdm_idr = 0x001c0020
        self.is_dual_core = False

    def init(self):
        super(KL28x, self).init()

        # Check if this is the dual core part.
        sdid = self.readMemory(SIM_SDID)
        keyattr = (sdid & SIM_SDID_KEYATTR_MASK) >> SIM_SDID_KEYATTR_SHIFT
        logging.debug("KEYATTR=0x%x SDID=0x%08x", keyattr, sdid)
        self.is_dual_core = (keyattr == KEYATTR_DUAL_CORE)
        if self.is_dual_core:
            logging.info("KL28 is dual core")

    def getMemoryMapXML(self):
        if self.is_dual_core:
            return self.memoryMapXMLDual
        else:
            return self.memoryMapXMLSingle

    def reset(self, software_reset = None):
        try:
            super(KL28x, self).reset(software_reset)
        except TransferError:
            # KL28 causes a SWD transfer fault for the AIRCR write when
            # it resets. Just ignore this error.
            pass


