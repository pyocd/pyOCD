# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

from __future__ import print_function
import os
import struct
import binascii
import logging
from collections import namedtuple
import itertools
from elftools.common.py3compat import bytes2str

from ...debug.elf.elf import ELFBinaryFile
from ...utility.py3_helpers import to_str_safe
from ...core.memory_map import MemoryRange

LOG = logging.getLogger(__name__)

class PackFlashAlgo(object):
    """!
    @brief Class to wrap a flash algo

    This class is intended to provide easy access to the information
    provided by a flash algorithm, such as symbols and the flash
    algorithm itself.
    """

    REQUIRED_SYMBOLS = {
        "Init",
        "UnInit",
        "EraseSector",
        "ProgramPage",
        }

    EXTRA_SYMBOLS = {
        "BlankCheck",
        "EraseChip",
        "Verify",
        }
        
    SECTIONS_TO_FIND = (
        ("PrgCode", "SHT_PROGBITS"),
        ("PrgData", "SHT_PROGBITS"),
        ("PrgData", "SHT_NOBITS"),
        )

    def __init__(self, data):
        """! @brief Construct a PackFlashAlgo from an ELFBinaryFile"""
        self.elf = ELFBinaryFile(data)
        self.flash_info = PackFlashInfo(self.elf)

        self.flash_start = self.flash_info.start
        self.flash_size = self.flash_info.size
        self.page_size = self.flash_info.page_size
        self.sector_sizes = self.flash_info.sector_info_list

        symbols = {}
        symbols.update(self._extract_symbols(self.REQUIRED_SYMBOLS))
        symbols.update(self._extract_symbols(self.EXTRA_SYMBOLS,
                                        default=0xFFFFFFFF))
        self.symbols = symbols

        ro_rw_zi = self._find_sections(self.SECTIONS_TO_FIND)
        ro_rw_zi = self._algo_fill_zi_if_missing(ro_rw_zi)
        error_msg = self._algo_check_for_section_problems(ro_rw_zi)
        if error_msg is not None:
            raise Exception(error_msg)

        sect_ro, sect_rw, sect_zi = ro_rw_zi
        self.ro_start = sect_ro.start
        self.ro_size = sect_ro.length
        self.rw_start = sect_rw.start
        self.rw_size = sect_rw.length
        self.zi_start = sect_zi.start
        self.zi_size = sect_zi.length

        self.algo_data = self._create_algo_bin(ro_rw_zi)

    def _extract_symbols(self, symbols, default=None):
        """! @brief Fill 'symbols' field with required flash algo symbols"""
        to_ret = {}
        for symbol in symbols:
            symbolInfo = self.elf.symbol_decoder.get_symbol_for_name(symbol)
            if symbolInfo is None:
                if default is not None:
                    to_ret[symbol] = default
                    continue
                raise Exception("Missing symbol %s" % symbol)
            to_ret[symbol] = symbolInfo.address
        return to_ret

    def _find_sections(self, name_type_pairs):
        """! @brief Return a list of sections the same length and order of the input list"""
        sections = [None] * len(name_type_pairs)
        for section in self.elf.sections:
            section_name = to_str_safe(section.name)
            section_type = section.type
            for i, name_and_type in enumerate(name_type_pairs):
                if name_and_type != (section_name, section_type):
                    continue
                if sections[i] is not None:
                    raise Exception("Elf contains duplicate section %s attr %s" %
                                    (section_name, section_type))
                sections[i] = section
        return sections

    def _algo_fill_zi_if_missing(self, ro_rw_zi):
        """! @brief Create an empty zi section if it is missing"""
        s_ro, s_rw, s_zi = ro_rw_zi
        if s_rw is None:
            return ro_rw_zi
        if s_zi is not None:
            return ro_rw_zi
        s_zi = MemoryRange(start=(s_rw.start + s_rw.length), length=0)
        return s_ro, s_rw, s_zi

    def _algo_check_for_section_problems(self, ro_rw_zi):
        """! @brief Return a string describing any errors with the layout or None if good"""
        s_ro, s_rw, s_zi = ro_rw_zi
        if s_ro is None:
            return "RO section is missing"
        if s_rw is None:
            return "RW section is missing"
        if s_zi is None:
            return "ZI section is missing"
        if s_ro.start != 0:
            return "RO section does not start at address 0"
        if s_ro.start + s_ro.length != s_rw.start:
            return "RW section does not follow RO section"
        if s_rw.start + s_rw.length != s_zi.start:
            return "ZI section does not follow RW section"
        return None

    def _create_algo_bin(self, ro_rw_zi):
        """Create a binary blob of the flash algo which can execute from ram"""
        sect_ro, sect_rw, sect_zi = ro_rw_zi
        algo_size = sect_ro.length + sect_rw.length + sect_zi.length
        algo_data = bytearray(algo_size)
        for section in (sect_ro, sect_rw):
            start = section.start
            size = section.length
            data = section.data
            assert len(data) == size
            algo_data[start:start + size] = data
        return algo_data


class PackFlashInfo(object):
    """! @brief Wrapper class for the non-executable information in an FLM file"""

    FLASH_DEVICE_STRUCT = "<H128sHLLLLBxxxLL"
    FLASH_DEVICE_STRUCT_SIZE = struct.calcsize(FLASH_DEVICE_STRUCT)
    FLASH_SECTORS_STRUCT = "<LL"
    FLASH_SECTORS_STRUCT_SIZE = struct.calcsize(FLASH_SECTORS_STRUCT)
    SECTOR_END = 0xFFFFFFFF

    def __init__(self, elf):
        dev_info = elf.symbol_decoder.get_symbol_for_name("FlashDevice")
        info_start = dev_info.address
        info_size = struct.calcsize(self.FLASH_DEVICE_STRUCT)
        data = elf.read(info_start, self.FLASH_DEVICE_STRUCT_SIZE)
        values = struct.unpack(self.FLASH_DEVICE_STRUCT, data)

        self.version = values[0]
        self.name = values[1].strip(b"\x00")
        self.type = values[2]
        self.start = values[3]
        self.size = values[4]
        self.page_size = values[5]
        self.value_empty = values[7]
        self.prog_timeout_ms = values[8]
        self.erase_timeout_ms = values[9]

        sector_gen = self._sector_and_sz_itr(elf, info_start + info_size)
        self.sector_info_list = list(sector_gen)

    def __str__(self):
        desc =  "Flash Device:" + os.linesep
        desc += "  name=%s" % self.name + os.linesep
        desc += "  version=0x%x" % self.version + os.linesep
        desc += "  type=%i" % self.type + os.linesep
        desc += "  start=0x%x" % self.start + os.linesep
        desc += "  size=0x%x" % self.size + os.linesep
        desc += "  page_size=0x%x" % self.page_size + os.linesep
        desc += "  value_empty=0x%x" % self.value_empty + os.linesep
        desc += "  prog_timeout_ms=%i" % self.prog_timeout_ms + os.linesep
        desc += "  erase_timeout_ms=%i" % self.erase_timeout_ms + os.linesep
        desc += "  sectors:" + os.linesep
        for sector_start, sector_size in self.sector_info_list:
            desc += ("    start=0x%x, size=0x%x" %
                     (sector_start, sector_size) + os.linesep)
        return desc

    def _sector_and_sz_itr(self, elf, data_start):
        """Iterator which returns starting address and sector size"""
        for entry_start in itertools.count(data_start, self.FLASH_SECTORS_STRUCT_SIZE):
            data = elf.read(entry_start, self.FLASH_SECTORS_STRUCT_SIZE)
            size, start = struct.unpack(self.FLASH_SECTORS_STRUCT, data)
            start_and_size = start, size
            if start_and_size == (self.SECTOR_END, self.SECTOR_END):
                return
            yield start_and_size


