# pyOCD debugger
# Copyright (c) 2016,2018 Arm Limited
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

from ..utility import conversion
from ..core.memory_map import MemoryType
from . import signals
import logging
import six
from xml.etree import ElementTree

LOG = logging.getLogger(__name__)

MAP_XML_HEADER = b"""<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
"""

## @brief Maps the fault code found in the IPSR to a GDB signal value.
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

## @brief Map from the memory type enums to gdb's memory region type names.
GDB_TYPE_MAP = {
    MemoryType.RAM: 'ram',
    MemoryType.ROM: 'rom',
    MemoryType.FLASH: 'flash',
    }

class GDBDebugContextFacade(object):
    """! @brief Provides GDB specific transformations to a DebugContext."""

    def __init__(self, context):
        self._context = context
        self._register_list = self._context.core.register_list

    @property
    def context(self):
        return self._context

    def set_context(self, newContext):
        self._context = newContext

    def get_register_context(self):
        """! @brief Return hexadecimal dump of registers as expected by GDB.
        """
        LOG.debug("GDB getting register context")
        resp = b''
        reg_num_list = [reg.reg_num for reg in self._register_list]
        vals = self._context.read_core_registers_raw(reg_num_list)
        #print("Vals: %s" % vals)
        for reg, regValue in zip(self._register_list, vals):
            if reg.bitsize == 64:
                resp += six.b(conversion.u64_to_hex16le(regValue))
            else:
                resp += six.b(conversion.u32_to_hex8le(regValue))
            LOG.debug("GDB reg: %s = 0x%X", reg.name, regValue)

        return resp

    def set_register_context(self, data):
        """! @brief Set registers from GDB hexadecimal string.
        """
        LOG.debug("GDB setting register context")
        reg_num_list = []
        reg_data_list = []
        for reg in self._register_list:
            if reg.bitsize == 64:
                regValue = conversion.hex16_to_u64be(data)
                data = data[16:]
            else:
                regValue = conversion.hex8_to_u32be(data)
                data = data[8:]
            reg_num_list.append(reg.reg_num)
            reg_data_list.append(regValue)
            LOG.debug("GDB reg: %s = 0x%X", reg.name, regValue)
        self._context.write_core_registers_raw(reg_num_list, reg_data_list)

    def set_register(self, reg, data):
        """! @brief Set single register from GDB hexadecimal string.
        
        @param reg The index of register in targetXML sent to GDB.
        """
        if reg < 0:
            return
        elif reg < len(self._register_list):
            regName = self._register_list[reg].name
            regBits = self._register_list[reg].bitsize
            if regBits == 64:
                value = conversion.hex16_to_u64be(data)
            else:
                value = conversion.hex8_to_u32be(data)
            LOG.debug("GDB: write reg %s: 0x%X", regName, value)
            self._context.write_core_register_raw(regName, value)

    def gdb_get_register(self, reg):
        resp = ''
        if reg < len(self._register_list):
            regName = self._register_list[reg].name
            regBits = self._register_list[reg].bitsize
            regValue = self._context.read_core_register_raw(regName)
            if regBits == 64:
                resp = six.b(conversion.u64_to_hex16le(regValue))
            else:
                resp = six.b(conversion.u32_to_hex8le(regValue))
            LOG.debug("GDB reg: %s = 0x%X", regName, regValue)
        return resp

    def get_t_response(self, forceSignal=None):
        """! @brief Returns a GDB T response string.
        
        This includes:
        - The signal encountered.
        - The current value of the important registers (sp, lr, pc).
        """
        if forceSignal is not None:
            response = six.b('T' + conversion.byte_to_hex2(forceSignal))
        else:
            response = six.b('T' + conversion.byte_to_hex2(self.get_signal_value()))

        # Append fp(r7), sp(r13), lr(r14), pc(r15)
        response += self.get_reg_index_value_pairs([7, 13, 14, 15])

        return response

    def get_signal_value(self):
        if self._context.core.is_debug_trap():
            return signals.SIGTRAP

        # If not a fault then default to SIGSTOP
        signal = signals.SIGSTOP

        if self._context.core.is_vector_catch():
            fault = self._context.core.read_core_register('ipsr')
            try:
                signal = FAULT[fault]
            except IndexError:
                pass

        LOG.debug("GDB lastSignal: %d", signal)
        return signal

    def get_reg_index_value_pairs(self, regIndexList):
        """! @brief Return register values as pairs.
        
        Returns a string like NN:MMMMMMMM;NN:MMMMMMMM;...
        for the T response string.  NN is the index of the
        register to follow MMMMMMMM is the value of the register.
        """
        str = b''
        regList = self._context.read_core_registers_raw(regIndexList)
        for regIndex, reg in zip(regIndexList, regList):
            str += six.b(conversion.byte_to_hex2(regIndex) + ':' + conversion.u32_to_hex8le(reg) + ';')
        return str

    def get_memory_map_xml(self):
        """! @brief Generate GDB memory map XML.
        """
        root = ElementTree.Element('memory-map')
        for r in  self._context.core.memory_map:
            # Look up the region type name. Regions default to ram if gdb doesn't
            # have a concept of the region type.
            gdbType = GDB_TYPE_MAP.get(r.type, 'ram')
            
            start = hex(r.start).rstrip("L")
            length = hex(r.length).rstrip("L")
            mem = ElementTree.SubElement(root, 'memory', type=gdbType, start=start, length=length)
            if r.is_flash:
                prop = ElementTree.SubElement(mem, 'property', name='blocksize')
                prop.text = hex(r.blocksize).rstrip("L")
        return MAP_XML_HEADER + ElementTree.tostring(root)

    def get_target_xml(self):
        return self._context.core.get_target_xml()

    def flush(self):
        self._context.core.flush()


