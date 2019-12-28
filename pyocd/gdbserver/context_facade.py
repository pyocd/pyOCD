# pyOCD debugger
# Copyright (c) 2016,2018-2020 Arm Limited
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
import six
from xml.etree import ElementTree
from itertools import groupby

from ..utility import conversion
from ..core import exceptions
from ..core.target import Target
from ..core.memory_map import MemoryType
from ..core.core_registers import CoreRegisterInfo
from . import signals

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
        
        # Note: Use the gdb 'maint print remote-registers' command to see it's view of the g/G commands.
        
        ## List of CoreRegisterInfos sorted by gdb_regnum, excluding any registers not communicated to gdb.
        #
        # This list is in the order expected by the g/G commands for reading/writing full register contexts.
        # It contains de-duplicated core registers with a valid GDB regnum, sorted by regnum.
        self._register_list = sorted(set(self._context.core.core_registers.iter_matching(
                lambda reg: reg.gdb_regnum is not None)), key=lambda v: v.gdb_regnum)
        
        ## List of internal register numbers corresponding to gdb registers.
        self._full_reg_num_list = [reg.index for reg in self._register_list]
        
        ## Map of gdb regnum to register info.
        self._gdb_regnum_map = {reg.gdb_regnum: reg for reg in self._register_list}

    @property
    def context(self):
        return self._context

    def set_context(self, newContext):
        self._context = newContext

    def get_register_context(self):
        """! @brief Return hexadecimal dump of registers as expected by GDB.
        
        @exception CoreRegisterAccessError
        """
        LOG.debug("GDB getting register context")
        resp = b''
        try:
            vals = self._context.read_core_registers_raw(self._full_reg_num_list)
        except exceptions.CoreRegisterAccessError:
            vals = [None] * len(self._full_reg_num_list)
            
        for reg, regValue in zip(self._register_list, vals):
            # Return x's to indicate unavailable register value.
            if regValue is None:
                resp += b"xx" * (reg.bitsize // 8)
            elif reg.bitsize == 64:
                resp += six.b(conversion.u64_to_hex16le(regValue))
            else:
                resp += six.b(conversion.u32_to_hex8le(regValue))
            LOG.debug("GDB reg: %s = 0x%X", reg.name, regValue)

        return resp

    def set_register_context(self, data):
        """! @brief Set registers from GDB hexadecimal string.
        
        @exception CoreRegisterAccessError
        """
        LOG.debug("GDB setting register context")
        reg_num_list = []
        reg_data_list = []
        offset = 0
        for reg in self._register_list:
            if offset >= len(data):
                break
            if reg.bitsize == 64:
                regValue = conversion.hex16_to_u64be(data[offset:offset+16])
                offset += 16
            else:
                regValue = conversion.hex8_to_u32be(data[offset:offset+8])
                offset += 8
            reg_num_list.append(reg.index)
            reg_data_list.append(regValue)
            LOG.debug("GDB reg: %s = 0x%X", reg.name, regValue)
        self._context.write_core_registers_raw(reg_num_list, reg_data_list)

    def set_register(self, gdb_regnum, data):
        """! @brief Set single register from GDB hexadecimal string.
        
        @param self The object.
        @param gdb_regnum The regnum of register in target XML sent to GDB.
        @param data String of hex-encoded value for the register.
        
        @exception CoreRegisterAccessError
        """
        reg = self._gdb_regnum_map.get(gdb_regnum, None)
        if reg is not None:
            if reg.bitsize == 64:
                value = conversion.hex16_to_u64be(data)
            else:
                value = conversion.hex8_to_u32be(data)
            LOG.debug("GDB: write reg %s: 0x%X", reg.name, value)
            self._context.write_core_register_raw(reg.name, value)
        else:
            LOG.warining("GDB: attempt to set invalid register (regnum %d)", gdb_regnum)

    def gdb_get_register(self, gdb_regnum):
        """! @brief Set single core register.
        
        @param self The object.
        @param gdb_regnum The regnum of register in target XML sent to GDB.
        @return String of hex-encoded value for the register.
        
        @exception CoreRegisterAccessError
        """
        reg = self._gdb_regnum_map.get(gdb_regnum, None)
        if reg is None:
            return b''
        
        try:
            regValue = self._context.read_core_register_raw(reg.name)
            if reg.bitsize == 64:
                resp = six.b(conversion.u64_to_hex16le(regValue))
            else:
                resp = six.b(conversion.u32_to_hex8le(regValue))
        except exceptions.CoreRegisterAccessError:
            # Return x's if the register read failed.
            resp = b"xx" * (reg.bitsize // 8)
        LOG.debug("GDB reg: %s = 0x%X", reg.name, regValue)
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
        response += self._get_reg_index_value_pairs(['r7', 'sp', 'lr', 'pc'])

        return response

    def get_signal_value(self):
        if self._context.core.is_debug_trap():
            return signals.SIGTRAP

        # If not a fault then default to SIGSTOP
        signal = signals.SIGSTOP

        if self._context.core.is_vector_catch():
            fault = self._context.core.read_core_register('ipsr')
            assert fault is not None, "Failed to read IPSR"
            try:
                signal = FAULT[fault]
            except IndexError:
                pass

        LOG.debug("GDB lastSignal: %d", signal)
        return signal

    def _get_reg_index_value_pairs(self, reg_list):
        """! @brief Return register values as pairs.
        
        Returns a string like NN:MMMMMMMM;NN:MMMMMMMM;...
        for the T response string.  NN is the index of the
        register to follow MMMMMMMM is the value of the register.
        """
        result = b''
        try:
            reg_values = self._context.read_core_registers_raw(reg_list)
        except exceptions.CoreRegisterAccessError:
            reg_values = [None] * len(reg_list)

        for reg_name, reg_value in zip(reg_list, reg_values):
            reg = self._context.core.core_registers.by_name[reg_name]
            # Return x's if the register read failed.
            if reg_value is None:
                encoded_reg = "xx" * (reg.bitsize // 8)
            elif reg.bitsize == 64:
                encoded_reg = conversion.u64_to_hex16le(reg_value)
            else:
                encoded_reg = conversion.u32_to_hex8le(reg_value)
            result += six.b(conversion.byte_to_hex2(reg.gdb_regnum) + ':' + encoded_reg + ';')
        return result

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


