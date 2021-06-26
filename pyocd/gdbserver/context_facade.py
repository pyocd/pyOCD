# pyOCD debugger
# Copyright (c) 2016,2018-2020 Arm Limited
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
import six
from xml.etree import ElementTree
from itertools import groupby

from ..utility import conversion
from ..utility.mask import (align_up, round_up_div)
from ..core import exceptions
from ..core.target import Target
from ..core.memory_map import MemoryType
from . import signals

LOG = logging.getLogger(__name__)

MAP_XML_HEADER = b"""<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
"""

TARGET_XML_HEADER = b"""<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
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

    ## The order certain target features should appear in target XML.        
    REQUIRED_FEATURE_ORDER = ("org.gnu.gdb.arm.m-profile", "org.gnu.gdb.arm.vfp")

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
        
        ## String of XML target description for gdb.
        self._target_xml = self._build_target_xml()

    @property
    def context(self):
        return self._context

    def set_context(self, new_context):
        self._context = new_context

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
            
        for reg, reg_value in zip(self._register_list, vals):
            # Return x's to indicate unavailable register value.
            if reg_value is None:
                r = b"xx" * round_up_div(reg.bitsize, 8)
            else:
                r = six.b(conversion.uint_to_hex_le(reg_value, reg.bitsize))
            resp += r
            LOG.debug("GDB get_reg_context: %s = %s -> %s", reg.name,
                    "None" if (reg_value is None) else ("0x%08X" % reg_value), r)

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
            hex_byte_count = align_up(reg.bitsize // 4, 2)
            reg_data = data[offset:(offset + hex_byte_count)]
            reg_value = conversion.hex_le_to_uint(reg_data, reg.bitsize)
            offset += hex_byte_count
            reg_num_list.append(reg.index)
            reg_data_list.append(reg_value)
            LOG.debug("GDB reg: %s = 0x%X", reg.name, reg_value)
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
            value = conversion.hex_le_to_uint(data, reg.bitsize)
            LOG.debug("GDB: write reg %s: 0x%X", reg.name, value)
            self._context.write_core_register_raw(reg.name, value)
        else:
            LOG.warning("GDB: attempt to set invalid register (regnum %d)", gdb_regnum)

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
            reg_value = self._context.read_core_register_raw(reg.name)
            resp = six.b(conversion.uint_to_hex_le(reg_value, reg.bitsize))
            LOG.debug("GDB reg: %s = 0x%X", reg.name, reg_value)
        except exceptions.CoreRegisterAccessError:
            # Return x's if the register read failed.
            resp = b"xx" * round_up_div(reg.bitsize, 8)
            LOG.debug("GDB reg: %s = <error reading>", reg.name)
        return resp

    def get_t_response(self, force_signal=None):
        """! @brief Returns a GDB T response string.
        
        This includes:
        - The signal encountered.
        - The current value of the important registers (sp, lr, pc).
        """
        if force_signal is not None:
            response = six.b('T' + conversion.byte_to_hex2(force_signal))
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
            try:
                signal = FAULT[fault]
            except IndexError:
                # Default to SIGSTOP as set above.
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
                encoded_reg = "xx" * round_up_div(reg.bitsize, 8)
            else:
                encoded_reg = conversion.uint_to_hex_le(reg_value, reg.bitsize)
            result += six.b(conversion.byte_to_hex2(reg.gdb_regnum) + ':' + encoded_reg + ';')
        return result

    def get_memory_map_xml(self):
        """! @brief Generate GDB memory map XML.
        """
        root = ElementTree.Element('memory-map')
        for r in  self._context.core.memory_map:
            # Look up the region type name. Regions default to ram if gdb doesn't
            # have a concept of the region type.
            gdb_type = GDB_TYPE_MAP.get(r.type, 'ram')
            
            start = hex(r.start).rstrip("L")
            length = hex(r.length).rstrip("L")
            mem = ElementTree.SubElement(root, 'memory', type=gdb_type, start=start, length=length)
            if r.is_flash:
                prop = ElementTree.SubElement(mem, 'property', name='blocksize')
                prop.text = hex(r.blocksize).rstrip("L")
        return MAP_XML_HEADER + ElementTree.tostring(root)

    def _define_xpsr_control_fields(self, xml_feature):
        """! @brief Define XPSR and CONTROL register types with fields."""
        control = ElementTree.SubElement(xml_feature, 'flags', id="control", size="4")
        ElementTree.SubElement(control, "field", name="nPRIV", start="0", end="0", type="bool")
        ElementTree.SubElement(control, "field", name="SPSEL", start="1", end="1", type="bool")
        if self._context.core.has_fpu:
            ElementTree.SubElement(control, "field", name="FPCA", start="2", end="2", type="bool")
        if Target.SecurityState.SECURE in self._context.core.supported_security_states:
            ElementTree.SubElement(control, "field", name="SFPA", start="3", end="3", type="bool")

        apsr = ElementTree.SubElement(xml_feature, 'flags', id="apsr", size="4")
        ElementTree.SubElement(apsr, "field", name="N", start="31", end="31", type="bool")
        ElementTree.SubElement(apsr, "field", name="Z", start="30", end="30", type="bool")
        ElementTree.SubElement(apsr, "field", name="C", start="29", end="29", type="bool")
        ElementTree.SubElement(apsr, "field", name="V", start="28", end="28", type="bool")
        ElementTree.SubElement(apsr, "field", name="Q", start="27", end="27", type="bool")
        ElementTree.SubElement(apsr, "field", name="GE", start="16", end="19", type="int")

        ipsr = ElementTree.SubElement(xml_feature, 'struct', id="ipsr", size="4")
        ElementTree.SubElement(ipsr, "field", name="EXC", start="0", end="8", type="int")

        xpsr = ElementTree.SubElement(xml_feature, 'union', id="xpsr")
        ElementTree.SubElement(xpsr, "field", name="xpsr", type="uint32")
        ElementTree.SubElement(xpsr, "field", name="apsr", type="apsr")
        ElementTree.SubElement(xpsr, "field", name="ipsr", type="ipsr")

    def _build_target_xml(self):
        # Extract list of registers, group into gdb features.
        regs_sorted_by_feature = sorted(self._register_list, key=lambda r: r.gdb_feature) # Must sort for groupby().
        regs_by_feature = {k: list(g) for k, g in groupby(regs_sorted_by_feature, key=lambda r: r.gdb_feature)}
        unordered_features = list(regs_by_feature.keys())
        features = []
        
        # Get a list of gdb features with some features having a determined order.
        for feature_name in self.REQUIRED_FEATURE_ORDER:
            if feature_name in unordered_features:
                features.append(feature_name)
                unordered_features.remove(feature_name)
        # Add any remaining features at the end of the feature list.
        features += unordered_features
        
        use_xpsr_control_fields = self._context.session.options.get('xpsr_control_fields')
        
        xml_root = ElementTree.Element('target')
        
        for feature_name in features:
            regs = regs_by_feature[feature_name]
        
            xml_feature = ElementTree.SubElement(xml_root, "feature", name=feature_name)

            # Special case for XPSR and CONTROL bitfield presentation.
            if (feature_name == "org.gnu.gdb.arm.m-profile") and use_xpsr_control_fields:
                self._define_xpsr_control_fields(xml_feature)
            
            # Add XML for the registers in this feature.
            for reg in regs:
                if use_xpsr_control_fields and (reg.name in ('xpsr', 'control')):
                    reg_type = reg.name
                else:
                    reg_type = reg.gdb_type
                ElementTree.SubElement(xml_feature, 'reg', name=reg.name, bitsize=str(reg.bitsize),
                        type=reg_type, group=reg.group, regnum=str(reg.gdb_regnum))

        return TARGET_XML_HEADER + ElementTree.tostring(xml_root)

    def get_target_xml(self):
        return self._target_xml

    def flush(self):
        self._context.core.flush()


