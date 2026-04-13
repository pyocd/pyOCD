# pyOCD debugger
# Copyright (c) 2016,2018-2020,2025 Arm Limited
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
from xml.etree import ElementTree
from itertools import groupby

from ..utility import conversion
from ..utility.mask import (align_up, round_up_div)
from ..core import exceptions
from ..core.target import Target
from ..core.memory_map import MemoryType
from ..coresight.core_ids import (CoreArchitecture, CortexMExtension)
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
    """@brief Provides GDB specific transformations to a DebugContext."""

    ## The order certain target features should appear in target XML.
    REQUIRED_FEATURE_ORDER = ("org.gnu.gdb.arm.m-profile", "org.gnu.gdb.arm.m-system", "org.gnu.gdb.arm.secext",
                              "org.gnu.gdb.arm.m-profile-mve", "org.gnu.gdb.arm.vfp")

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
        """@brief Return hexadecimal dump of registers as expected by GDB.

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
                r = conversion.uint_to_hex_le(reg_value, reg.bitsize).encode()
            resp += r
            LOG.debug("GDB get_reg_context: %s = %s -> %s", reg.name,
                    "None" if (reg_value is None) else ("0x%08X" % reg_value), r)

        return resp

    def set_register_context(self, data):
        """@brief Set registers from GDB hexadecimal string.

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
        """@brief Set single register from GDB hexadecimal string.

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

    def get_register(self, gdb_regnum):
        """@brief get single core register.

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
            resp = conversion.uint_to_hex_le(reg_value, reg.bitsize).encode()
            LOG.debug("GDB reg: %s = 0x%X", reg.name, reg_value)
        except exceptions.CoreRegisterAccessError:
            # Return x's if the register read failed.
            resp = b"xx" * round_up_div(reg.bitsize, 8)
            LOG.debug("GDB reg: %s = <error reading>", reg.name)
        return resp

    def get_t_response(self, force_signal=None):
        """@brief Returns a GDB T response string.

        This includes:
        - The signal encountered.
        - The current value of the important registers (sp, lr, pc).
        """
        if force_signal is not None:
            response = ('T' + conversion.byte_to_hex2(force_signal)).encode()
        else:
            response = ('T' + conversion.byte_to_hex2(self.get_signal_value())).encode()

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
        """@brief Return register values as pairs for the T response.

        Returns a string like NN:MMMMMMMM;NN:MMMMMMMM;...
        for the T response string.  NN is the index of the
        register to follow MMMMMMMM is the value of the register.
        """
        result = b''
        try:
            reg_values = self._context.read_core_registers_raw(reg_list)
        except exceptions.CoreRegisterAccessError:
            # If we cannot read registers, return an empty string. We mustn't return 'x's like the other
            # register read methods do, because gdb terribly dislikes 'x's in a T response.
            return result

        for reg_name, reg_value in zip(reg_list, reg_values):
            reg = self._context.core.core_registers.by_name[reg_name]
            assert reg_value is not None
            encoded_reg = conversion.uint_to_hex_le(reg_value, reg.bitsize)
            result += (conversion.byte_to_hex2(reg.gdb_regnum) + ':' + encoded_reg + ';').encode()
        return result

    def get_memory_map_xml(self):
        """@brief Generate GDB memory map XML.
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

    def _define_m_profile_types(self, xml_feature):
        """@brief Define 'org.gnu.gdb.arm.m-profile' types."""
        xpsr = ElementTree.SubElement(xml_feature, 'flags', id="xpsr", size="4")
        # APSR fields
        ElementTree.SubElement(xpsr, "field", name="N",   start="31", end="31", type="bool")
        ElementTree.SubElement(xpsr, "field", name="Z",   start="30", end="30", type="bool")
        ElementTree.SubElement(xpsr, "field", name="C",   start="29", end="29", type="bool")
        ElementTree.SubElement(xpsr, "field", name="V",   start="28", end="28", type="bool")
        ElementTree.SubElement(xpsr, "field", name="Q",   start="27", end="27", type="bool")
        ElementTree.SubElement(xpsr, "field", name="GE",  start="16", end="19", type="int")
        #IPSR fields
        ElementTree.SubElement(xpsr, "field", name="EXC", start="0",  end="8",  type="int")
        #EPSR fields
        ElementTree.SubElement(xpsr, "field", name="T",   start="24", end="24", type="bool")

    def _define_m_system_types(self, xml_feature):
        """@brief Define 'org.gnu.gdb.arm.m-system' types."""
        control = ElementTree.SubElement(xml_feature, 'flags', id="control", size="4")
        ElementTree.SubElement(control, "field", name="nPRIV", start="0", end="0", type="bool")
        ElementTree.SubElement(control, "field", name="SPSEL", start="1", end="1", type="bool")
        if self._context.core.has_fpu:
            ElementTree.SubElement(control, "field", name="FPCA", start="2", end="2", type="bool")
            if Target.SecurityState.SECURE in self._context.core.supported_security_states:
                ElementTree.SubElement(control, "field", name="SFPA", start="3", end="3", type="bool")
        if (CortexMExtension.PACBTI in self._context.core.extensions):
            ElementTree.SubElement(control, "field", name="BTI_EN",  start="4", end="4", type="bool")
            ElementTree.SubElement(control, "field", name="UBTI_EN", start="5", end="5", type="bool")
            ElementTree.SubElement(control, "field", name="PAC_EN",  start="6", end="6", type="bool")
            ElementTree.SubElement(control, "field", name="UPAC_EN", start="7", end="7", type="bool")

    def _define_m_profile_mve_types(self, xml_feature):
        """@brief Define 'org.gnu.gdb.arm.m-profile-mve' types."""
        vpr = ElementTree.SubElement(xml_feature, 'flags', id="vpr", size="4")
        ElementTree.SubElement(vpr, "field", name="P0",     start="0",  end="15", type="int")
        ElementTree.SubElement(vpr, "field", name="MASK01", start="16", end="19", type="int")
        ElementTree.SubElement(vpr, "field", name="MASK23", start="20", end="23", type="int")

    def _define_vfp_types(self, xml_feature):
        """@brief Define 'org.gnu.gdb.arm.vfp' types."""
        fpscr = ElementTree.SubElement(xml_feature, 'flags', id="fpscr", size="4")
        ElementTree.SubElement(fpscr, "field", name="N",     start="31", end="31", type="bool")
        ElementTree.SubElement(fpscr, "field", name="Z",     start="30", end="30", type="bool")
        ElementTree.SubElement(fpscr, "field", name="C",     start="29", end="29", type="bool")
        ElementTree.SubElement(fpscr, "field", name="V",     start="28", end="28", type="bool")
        if (CortexMExtension.MVE in self._context.core.extensions):
            ElementTree.SubElement(fpscr, "field", name="QC",   start="27", end="27", type="bool")
        ElementTree.SubElement(fpscr, "field", name="AHP",   start="26", end="26", type="bool")
        ElementTree.SubElement(fpscr, "field", name="DN",    start="25", end="25", type="bool")
        ElementTree.SubElement(fpscr, "field", name="FZ",    start="24", end="24", type="bool")
        ElementTree.SubElement(fpscr, "field", name="RMode", start="22", end="23", type="int")
        if (CortexMExtension.FPU_HP in self._context.core.extensions):
            ElementTree.SubElement(fpscr, "field", name="FZ16", start="19", end="19", type="bool")
        if (self._context.core.architecture_version == (8, 1)):
            ElementTree.SubElement(fpscr, "field", name="LTPSIZE", start="16", end="18", type="int")
        ElementTree.SubElement(fpscr, "field", name="IDC",   start="7",  end="7",  type="bool")
        ElementTree.SubElement(fpscr, "field", name="IXC",   start="4",  end="4",  type="bool")
        ElementTree.SubElement(fpscr, "field", name="UFC",   start="3",  end="3",  type="bool")
        ElementTree.SubElement(fpscr, "field", name="OFC",   start="2",  end="2",  type="bool")
        ElementTree.SubElement(fpscr, "field", name="DZC",   start="1",  end="1",  type="bool")
        ElementTree.SubElement(fpscr, "field", name="IOC",   start="0",  end="0",  type="bool")

    def _build_target_xml(self):
        xml_root = ElementTree.Element('target')

        # Add architecture element.
        architecture = 'arm'
        arch = self._context.core.architecture
        if arch == CoreArchitecture.ARMv6M:
            architecture = 'armv6s-m'
        elif arch == CoreArchitecture.ARMv7M:
            if (CortexMExtension.DSP in self._context.core.extensions):
                architecture = 'armv7e-m'
            else:
                # gdb does not recognize 'armv7-m', use 'armv7e-m' instead.
                # architecture = 'armv7-m'
                architecture = 'armv7e-m'
        elif arch == CoreArchitecture.ARMv8M_BASE:
            architecture = 'armv8-m.base'
        elif arch == CoreArchitecture.ARMv8M_MAIN:
            if self._context.core.architecture_version == (8, 1):
                architecture = 'armv8.1-m.main'
            else:
                architecture = 'armv8-m.main'
        ElementTree.SubElement(xml_root, 'architecture').text = architecture

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

        use_register_fields = self._context.session.options.get('register_fields')

        for feature_name in features:
            regs = regs_by_feature[feature_name]

            xml_feature = ElementTree.SubElement(xml_root, 'feature', name=feature_name)

            # Define feature types when option 'register_fields' is enabled.
            if use_register_fields:
                if feature_name == "org.gnu.gdb.arm.m-profile":
                    self._define_m_profile_types(xml_feature)
                elif feature_name == "org.gnu.gdb.arm.m-system":
                    self._define_m_system_types(xml_feature)
                elif feature_name == "org.gnu.gdb.arm.m-profile-mve":
                    self._define_m_profile_mve_types(xml_feature)
                elif feature_name == "org.gnu.gdb.arm.vfp":
                    self._define_vfp_types(xml_feature)

            # Add XML for the registers in this feature.
            for reg in regs:
                if use_register_fields and (reg.name in ('xpsr', 'control', 'vpr', 'fpscr')):
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
