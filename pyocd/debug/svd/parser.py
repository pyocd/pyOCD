#
# Copyright 2015 Paul Osborne <osbpau@gmail.com>
# Copyright (c) 2019 Arm Ltd
# Copyright (c) 2021 Chris Reed
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
#
from xml.etree import ElementTree as ET
import re

from .model import SVDDevice
from .model import SVDPeripheral
from .model import SVDInterrupt
from .model import SVDAddressBlock
from .model import SVDRegister, SVDRegisterArray
from .model import SVDRegisterCluster, SVDRegisterClusterArray
from .model import SVDField
from .model import SVDEnumeratedValue
from .model import SVDCpu


def _get_text(node, tag, default=None):
    """! @brief Get the text for the provided tag from the provided node"""
    try:
        return node.find(tag).text
    except AttributeError:
        return default


def _get_int(node, tag, default=None):
    text_value = _get_text(node, tag, default)
    try:
        if text_value != default:
            text_value = text_value.strip().lower()
            if text_value.startswith('0x'):
                return int(text_value[2:], 16)  # hexadecimal
            elif text_value.startswith('#'):
                # TODO(posborne): Deal with strange #1xx case better
                #
                # Freescale will sometimes provide values that look like this:
                #   #1xx
                # In this case, there are a number of values which all mean the
                # same thing as the field is a "don't care".  For now, we just
                # replace those bits with zeros.
                text_value = text_value.replace('x', '0')[1:]
                is_bin = all(x in '01' for x in text_value)
                return int(text_value, 2) if is_bin else int(text_value)  # binary
            elif text_value.startswith('true'):
                return 1
            elif text_value.startswith('false'):
                return 0
            else:
                return int(text_value)  # decimal
    except ValueError:
        return default
    return default


class SVDParser(object):
    """! @brief The SVDParser is responsible for mapping the SVD XML to Python Objects"""

    @classmethod
    def for_xml_file(cls, path, remove_reserved=False):
        return cls(ET.parse(path), remove_reserved)

    def __init__(self, tree, remove_reserved=False):
        self.remove_reserved = remove_reserved
        self._tree = tree
        self._root = self._tree.getroot()

    def _parse_enumerated_value(self, enumerated_value_node):
        return SVDEnumeratedValue(
            name=_get_text(enumerated_value_node, 'name'),
            description=_get_text(enumerated_value_node, 'description'),
            value=_get_int(enumerated_value_node, 'value'),
            is_default=_get_int(enumerated_value_node, 'isDefault')
        )

    def _parse_field(self, field_node):
        enumerated_values = []
        for enumerated_value_node in field_node.findall("./enumeratedValues/enumeratedValue"):
            enumerated_values.append(self._parse_enumerated_value(enumerated_value_node))

        modified_write_values=_get_text(field_node, 'modifiedWriteValues')
        read_action=_get_text(field_node, 'readAction')
        bit_range = _get_text(field_node, 'bitRange')
        bit_offset = _get_int(field_node, 'bitOffset')
        bit_width = _get_int(field_node, 'bitWidth')
        msb = _get_int(field_node, 'msb')
        lsb = _get_int(field_node, 'lsb')
        if bit_range is not None:
            m = re.search(r'\[([0-9]+):([0-9]+)\]', bit_range)
            bit_offset = int(m.group(2))
            bit_width = 1 + (int(m.group(1)) - int(m.group(2)))
        elif msb is not None:
            bit_offset = lsb
            bit_width = 1 + (msb - lsb)

        return SVDField(
            name=_get_text(field_node, 'name'),
            derived_from=_get_text(field_node, 'derivedFrom'),
            description=_get_text(field_node, 'description'),
            bit_offset=bit_offset,
            bit_width=bit_width,
            access=_get_text(field_node, 'access'),
            enumerated_values=enumerated_values or None,
            modified_write_values=modified_write_values,
            read_action=read_action,
        )

    def _parse_registers(self, register_node):
        fields = []
        for field_node in register_node.findall('.//field'):
            node = self._parse_field(field_node)
            if self.remove_reserved or 'reserved' not in node.name.lower():
                fields.append(node)

        dim = _get_int(register_node, 'dim')
        name = _get_text(register_node, 'name')
        derived_from = _get_text(register_node, 'derivedFrom')
        description = _get_text(register_node, 'description')
        address_offset = _get_int(register_node, 'addressOffset')
        size = _get_int(register_node, 'size')
        access = _get_text(register_node, 'access')
        protection = _get_text(register_node, 'protection')
        reset_value = _get_int(register_node, 'resetValue')
        reset_mask = _get_int(register_node, 'resetMask')
        dim_increment = _get_int(register_node, 'dimIncrement')
        dim_index_text = _get_text(register_node, 'dimIndex')
        display_name = _get_text(register_node, 'displayName')
        alternate_group = _get_text(register_node, 'alternateGroup')
        modified_write_values = _get_text(register_node, 'modifiedWriteValues')
        read_action = _get_text(register_node, 'readAction')

        if dim is None:
            return SVDRegister(
                name=name,
                fields=fields,
                derived_from=derived_from,
                description=description,
                address_offset=address_offset,
                size=size,
                access=access,
                protection=protection,
                reset_value=reset_value,
                reset_mask=reset_mask,
                display_name=display_name,
                alternate_group=alternate_group,
                modified_write_values=modified_write_values,
                read_action=read_action,
            )
        else:
            # the node represents a register array
            if dim_index_text is None:
                dim_indices = range(0, dim)  # some files omit dimIndex
            elif ',' in dim_index_text:
                dim_indices = dim_index_text.split(',')
            elif '-' in dim_index_text:  # some files use <dimIndex>0-3</dimIndex> as an inclusive inclusive range
                m = re.search(r'([0-9]+)-([0-9]+)', dim_index_text)
                dim_indices = range(int(m.group(1)), int(m.group(2)) + 1)
            else:
                raise ValueError("Unexpected dim_index_text: %r" % dim_index_text)

            # yield `SVDRegisterArray` (caller will differentiate on type)
            return SVDRegisterArray(
                name=name,
                fields=fields,
                derived_from=derived_from,
                description=description,
                address_offset=address_offset,
                size=size,
                access=access,
                protection=protection,
                reset_value=reset_value,
                reset_mask=reset_mask,
                display_name=display_name,
                alternate_group=alternate_group,
                modified_write_values=modified_write_values,
                read_action=read_action,
                dim=dim,
                dim_indices=dim_indices,
                dim_increment=dim_increment,
            )

    def _parse_cluster(self, cluster_node):
        dim = _get_int(cluster_node, 'dim')
        name = _get_text(cluster_node, 'name')
        derived_from = _get_text(cluster_node, 'derivedFrom')
        description = _get_text(cluster_node, 'description')
        address_offset = _get_int(cluster_node, 'addressOffset')
        size = _get_int(cluster_node, 'size')
        access = _get_text(cluster_node, 'access')
        protection = _get_text(cluster_node, 'protection')
        reset_value = _get_int(cluster_node, 'resetValue')
        reset_mask = _get_int(cluster_node, 'resetMask')
        dim_increment = _get_int(cluster_node, 'dimIncrement')
        dim_index_text = _get_text(cluster_node, 'dimIndex')
        alternate_cluster = _get_text(cluster_node, 'alternateGluster')
        header_struct_name = _get_text(cluster_node, 'headerStructName')
        cluster = []
        for sub_cluster_node in cluster_node.findall("./cluster"):
            cluster.append(self._parse_cluster(sub_cluster_node))
        register = []
        for reg_node in cluster_node.findall("./register"):
            register.append(self._parse_registers(reg_node))

        if dim is None:
            return SVDRegisterCluster(
                name=name,
                derived_from=derived_from,
                description=description,
                address_offset=address_offset,
                size=size,
                access=access,
                protection=protection,
                reset_value=reset_value,
                reset_mask=reset_mask,
                alternate_cluster=alternate_cluster,
                header_struct_name=header_struct_name,
                register=register,
                cluster=cluster,
            )
        else:
            # the node represents a register array
            if dim_index_text is None:
                dim_indices = range(0, dim)  # some files omit dimIndex
            elif ',' in dim_index_text:
                dim_indices = dim_index_text.split(',')
            elif '-' in dim_index_text:  # some files use <dimIndex>0-3</dimIndex> as an inclusive inclusive range
                m = re.search(r'([0-9]+)-([0-9]+)', dim_index_text)
                dim_indices = range(int(m.group(1)), int(m.group(2)) + 1)
            else:
                raise ValueError("Unexpected dim_index_text: %r" % dim_index_text)

            # yield `SVDRegisterArray` (caller will differentiate on type)
            return SVDRegisterClusterArray(
                name=name,
                derived_from=derived_from,
                description=description,
                address_offset=address_offset,
                size=size,
                access=access,
                protection=protection,
                reset_value=reset_value,
                reset_mask=reset_mask,
                alternate_cluster=alternate_cluster,
                header_struct_name=header_struct_name,
                register=register,
                cluster=cluster,
                dim=dim,
                dim_increment=dim_increment,
                dim_indices=dim_indices,
            )

    def _parse_address_block(self, address_block_node):
        return SVDAddressBlock(
            _get_int(address_block_node, 'offset'),
            _get_int(address_block_node, 'size'),
            _get_text(address_block_node, 'usage')
        )

    def _parse_interrupt(self, interrupt_node):
        return SVDInterrupt(
            name=_get_text(interrupt_node, 'name'),
            value=_get_int(interrupt_node, 'value'),
            description=_get_text(interrupt_node, 'description')
        )

    def _parse_peripheral(self, peripheral_node):
        # parse registers
        registers = None if peripheral_node.find('registers') is None else []
        register_arrays = None if peripheral_node.find('registers') is None else []
        for register_node in peripheral_node.findall('./registers/register'):
            reg = self._parse_registers(register_node)
            if isinstance(reg, SVDRegisterArray):
                register_arrays.append(reg)
            else:
                registers.append(reg)

        clusters = []
        for cluster_node in peripheral_node.findall('./registers/cluster'):
            reg = self._parse_cluster(cluster_node)
            clusters.append(reg)

        # parse all interrupts for the peripheral
        interrupts = []
        for interrupt_node in peripheral_node.findall('./interrupt'):
            interrupts.append(self._parse_interrupt(interrupt_node))
        interrupts = interrupts if interrupts else None

        # parse address block if any
        address_block_nodes = peripheral_node.findall('./addressBlock')
        if address_block_nodes:
            address_block = self._parse_address_block(address_block_nodes[0])
        else:
            address_block = None

        return SVDPeripheral(
            # <name>identifierType</name>
            # <version>xs:string</version>
            # <description>xs:string</description>
            name=_get_text(peripheral_node, 'name'),
            version=_get_text(peripheral_node, 'version'),
            derived_from=peripheral_node.get('derivedFrom'),
            description=_get_text(peripheral_node, 'description'),

            # <groupName>identifierType</groupName>
            # <prependToName>identifierType</prependToName>
            # <appendToName>identifierType</appendToName>
            # <disableCondition>xs:string</disableCondition>
            # <baseAddress>scaledNonNegativeInteger</baseAddress>
            group_name=_get_text(peripheral_node, 'groupName'),
            prepend_to_name=_get_text(peripheral_node, 'prependToName'),
            append_to_name=_get_text(peripheral_node, 'appendToName'),
            disable_condition=_get_text(peripheral_node, 'disableCondition'),
            base_address=_get_int(peripheral_node, 'baseAddress'),

            # <!-- registerPropertiesGroup -->
            # <size>scaledNonNegativeInteger</size>
            # <access>accessType</access>
            # <resetValue>scaledNonNegativeInteger</resetValue>
            # <resetMask>scaledNonNegativeInteger</resetMask>
            size=_get_int(peripheral_node, "size"),
            access=_get_text(peripheral_node, 'access'),
            reset_value=_get_int(peripheral_node, "resetValue"),
            reset_mask=_get_int(peripheral_node, "resetMask"),

            # <addressBlock>
            #     <offset>scaledNonNegativeInteger</offset>
            #     <size>scaledNonNegativeInteger</size>
            #     <usage>usageType</usage>
            #     <protection>protectionStringType</protection>
            # </addressBlock>
            address_block=address_block,

            # <interrupt>
            #     <name>identifierType</name>
            #     <value>scaledNonNegativeInteger</value>
            #     <description>xs:string</description>
            # </interrupt>
            interrupts=interrupts,

            # <registers>
            #     ...
            # </registers>
            register_arrays=register_arrays,
            registers=registers,

            # <cluster>
            #    ...
            # </cluster>
            clusters=clusters,

            # (not mentioned in docs -- applies to all registers)
            protection=_get_text(peripheral_node, 'protection'),
        )

    def _parse_device(self, device_node):
        peripherals = []
        for peripheral_node in device_node.findall('.//peripheral'):
            peripherals.append(self._parse_peripheral(peripheral_node))
        cpu_node = device_node.find('./cpu')
        cpu = SVDCpu(
            name=_get_text(cpu_node, 'name'),
            revision=_get_text(cpu_node, 'revision'),
            endian=_get_text(cpu_node, 'endian'),
            mpu_present=_get_int(cpu_node, 'mpuPresent'),
            fpu_present=_get_int(cpu_node, 'fpuPresent'),
            fpu_dp=_get_int(cpu_node, 'fpuDP'),
            icache_present=_get_int(cpu_node, 'icachePresent'),
            dcache_present=_get_int(cpu_node, 'dcachePresent'),
            itcm_present=_get_int(cpu_node, 'itcmPresent'),
            dtcm_present=_get_int(cpu_node, 'dtcmPresent'),
            vtor_present=_get_int(cpu_node, 'vtorPresent'),
            nvic_prio_bits=_get_int(cpu_node, 'nvicPrioBits'),
            vendor_systick_config=_get_int(cpu_node, 'vendorSystickConfig'),
            device_num_interrupts=_get_int(cpu_node, 'vendorSystickConfig'),
            sau_num_regions=_get_int(cpu_node, 'vendorSystickConfig'),
            sau_regions_config=_get_text(cpu_node, 'sauRegionsConfig')
        )

        return SVDDevice(
            vendor=_get_text(device_node, 'vendor'),
            vendor_id=_get_text(device_node, 'vendorID'),
            name=_get_text(device_node, 'name'),
            version=_get_text(device_node, 'version'),
            description=_get_text(device_node, 'description'),
            cpu=cpu,
            address_unit_bits=_get_int(device_node, 'addressUnitBits'),
            width=_get_int(device_node, 'width'),
            peripherals=peripherals,
            size=_get_int(device_node, "size"),
            access=_get_text(device_node, 'access'),
            protection=_get_text(device_node, 'protection'),
            reset_value=_get_int(device_node, "resetValue"),
            reset_mask=_get_int(device_node, "resetMask")
        )

    def get_device(self):
        """! @brief Get the device described by this SVD"""
        return self._parse_device(self._root)


def duplicate_array_of_registers(svdreg):  # expects a SVDRegister which is an array of registers
    assert (svdreg.dim == len(svdreg.dim_index))
