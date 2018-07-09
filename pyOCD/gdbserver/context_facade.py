"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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

from ..utility import conversion
from . import signals
import logging
import six

# Maps the fault code found in the IPSR to a GDB signal value.
FAULT = [
            signals.SIGSTOP,
            signals.SIGSTOP,    # Reset
            signals.SIGINT,     # NMI
            signals.SIGSEGV,    # HardFault
            signals.SIGSEGV,    # MemManage
            signals.SIGBUS,     # BusFault
            signals.SIGILL,     # UsageFault
                                                # The rest are not faults
         ]

## @brief Provides GDB specific transformations to a DebugContext.
class GDBDebugContextFacade(object):
    def __init__(self, context):
        self._context = context
        self._register_list = self._context.core.register_list

    @property
    def context(self):
        return self._context

    def set_context(self, newContext):
        self._context = newContext

    def getRegisterContext(self):
        """
        return hexadecimal dump of registers as expected by GDB
        """
        logging.debug("GDB getting register context")
        resp = b''
        reg_num_list = [reg.reg_num for reg in self._register_list]
        vals = self._context.readCoreRegistersRaw(reg_num_list)
        #print("Vals: %s" % vals)
        for reg, regValue in zip(self._register_list, vals):
            resp += six.b(conversion.u32beToHex8le(regValue))
            logging.debug("GDB reg: %s = 0x%X", reg.name, regValue)

        return resp

    def setRegisterContext(self, data):
        """
        Set registers from GDB hexadecimal string.
        """
        logging.debug("GDB setting register context")
        reg_num_list = []
        reg_data_list = []
        for reg in self._register_list:
            regValue = conversion.hex8leToU32be(data)
            reg_num_list.append(reg.reg_num)
            reg_data_list.append(regValue)
            logging.debug("GDB reg: %s = 0x%X", reg.name, regValue)
            data = data[8:]
        self._context.writeCoreRegistersRaw(reg_num_list, reg_data_list)

    def setRegister(self, reg, data):
        """
        Set single register from GDB hexadecimal string.
        reg parameter is the index of register in targetXML sent to GDB.
        """
        if reg < 0:
            return
        elif reg < len(self._register_list):
            regName = self._register_list[reg].name
            value = conversion.hex8leToU32be(data)
            logging.debug("GDB: write reg %s: 0x%X", regName, value)
            self._context.writeCoreRegisterRaw(regName, value)

    def gdbGetRegister(self, reg):
        resp = ''
        if reg < len(self._register_list):
            regName = self._register_list[reg].name
            regValue = self._context.readCoreRegisterRaw(regName)
            resp = six.b(conversion.u32beToHex8le(regValue))
            logging.debug("GDB reg: %s = 0x%X", regName, regValue)
        return resp

    def getTResponse(self, forceSignal=None):
        """
        Returns a GDB T response string.  This includes:
            The signal encountered.
            The current value of the important registers (sp, lr, pc).
        """
        if forceSignal is not None:
            response = six.b('T' + conversion.byteToHex2(forceSignal))
        else:
            response = six.b('T' + conversion.byteToHex2(self.getSignalValue()))

        # Append fp(r7), sp(r13), lr(r14), pc(r15)
        response += self.getRegIndexValuePairs([7, 13, 14, 15])

        return response

    def getSignalValue(self):
        if self._context.core.isDebugTrap():
            return signals.SIGTRAP

        fault = self._context.readCoreRegister('xpsr') & 0xff
        try:
            signal = FAULT[fault]
        except:
            # If not a fault then default to SIGSTOP
            signal = signals.SIGSTOP
        logging.debug("GDB lastSignal: %d", signal)
        return signal

    def getRegIndexValuePairs(self, regIndexList):
        """
        Returns a string like NN:MMMMMMMM;NN:MMMMMMMM;...
            for the T response string.  NN is the index of the
            register to follow MMMMMMMM is the value of the register.
        """
        str = b''
        regList = self._context.readCoreRegistersRaw(regIndexList)
        for regIndex, reg in zip(regIndexList, regList):
            str += six.b(conversion.byteToHex2(regIndex) + ':' + conversion.u32beToHex8le(reg) + ';')
        return str

    def getMemoryMapXML(self):
        if self._context.core.memory_map:
            return self._context.core.memory_map.getXML()
        else:
            return None

    def getTargetXML(self):
        return self._context.core.getTargetXML()

    def flush(self):
        self._context.core.flush()


