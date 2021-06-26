# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

import os
import struct
import logging
import itertools

from ...debug.elf.elf import ELFBinaryFile
from ...utility.compatibility import to_str_safe
from ...core.memory_map import MemoryRange
from ...core import exceptions
from ...utility.conversion import byte_list_to_u32le_list

LOG = logging.getLogger(__name__)

FLASH_ALGO_STACK_SIZE = 512

class FlashAlgoException(exceptions.TargetSupportError):
    """! @brief Exception class for errors parsing an FLM file."""
    pass

class PackFlashAlgo(object):
    """!
    @brief Class to wrap a flash algo

    This class is intended to provide easy access to the information
    provided by a flash algorithm, such as symbols and the flash
    algorithm itself.
    
    @sa PackFlashInfo
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

    ## @brief Standard flash blob header that starts with a breakpoint instruction.
    _FLASH_BLOB_HEADER = [
        0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040,
        0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x04770D1F
        ]
    ## @brief Size of the flash blob header in bytes.
    _FLASH_BLOB_HEADER_SIZE = len(_FLASH_BLOB_HEADER) * 4

    def __init__(self, data):
        """! @brief Construct a PackFlashAlgo from a file-like object."""
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
            raise FlashAlgoException(error_msg)

        sect_ro, sect_rw, sect_zi = ro_rw_zi
        self.ro_start = sect_ro.start
        self.ro_size = sect_ro.length
        self.rw_start = sect_rw.start
        self.rw_size = sect_rw.length
        self.zi_start = sect_zi.start
        self.zi_size = sect_zi.length

        self.algo_data = self._create_algo_bin(ro_rw_zi)

    def get_pyocd_flash_algo(self, blocksize, ram_region):
        """! @brief Return a dictionary representing a pyOCD flash algorithm, or None.
        
        The most interesting operation this method performs is dynamically allocating memory
        for the flash algo from a given RAM region. Note that the .data and .bss sections are
        concatenated with .text. That's why there isn't a specific allocation for those sections.
        
        Double buffering is supported as long as there is enough RAM.
        
        Memory layout:
        ```
        [stack] [code] [buf1] [buf2]
        ```
        
        @param self
        @param blocksize The size to use for page buffers, normally the erase block size.
        @param ram_region A RamRegion object where the flash algo will be allocated.
        @return A pyOCD-style flash algo dictionary. If None is returned, the flash algo did
            not fit into the provided ram_region.
        """
        instructions = self._FLASH_BLOB_HEADER + byte_list_to_u32le_list(self.algo_data)

        offset = 0

        # Stack
        offset += FLASH_ALGO_STACK_SIZE
        addr_stack = ram_region.start + offset

        # Load address
        addr_load = ram_region.start + offset
        offset += len(instructions) * 4

        # Data buffer 1
        addr_data = ram_region.start + offset
        offset += blocksize

        if offset > ram_region.length:
            # Not enough space for flash algorithm
            LOG.warning("Not enough space for flash algorithm")
            return None

        # Data buffer 2
        addr_data2 = ram_region.start + offset
        offset += blocksize

        if offset > ram_region.length:
            page_buffers = [addr_data]
        else:
            page_buffers = [addr_data, addr_data2]

        # TODO - analyzer support

        code_start = addr_load + self._FLASH_BLOB_HEADER_SIZE
        flash_algo = {
            "load_address": addr_load,
            "instructions": instructions,
            "pc_init": code_start + self.symbols["Init"],
            "pc_unInit": code_start + self.symbols["UnInit"],
            "pc_eraseAll": code_start + self.symbols["EraseChip"],
            "pc_erase_sector": code_start + self.symbols["EraseSector"],
            "pc_program_page": code_start + self.symbols["ProgramPage"],
            "page_buffers": page_buffers,
            "begin_data": page_buffers[0],
            "begin_stack": addr_stack,
            "static_base": code_start + self.rw_start,
            "min_program_length": self.page_size,
            "analyzer_supported": False
        }
        return flash_algo

    def _extract_symbols(self, symbols, default=None):
        """! @brief Fill 'symbols' field with required flash algo symbols"""
        to_ret = {}
        for symbol in symbols:
            symbolInfo = self.elf.symbol_decoder.get_symbol_for_name(symbol)
            if symbolInfo is None:
                if default is not None:
                    to_ret[symbol] = default
                    continue
                raise FlashAlgoException("Missing symbol %s" % symbol)
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
                    raise FlashAlgoException("Elf contains duplicate section %s attr %s" %
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
        if dev_info is None:
            values = [0] * 10
            values[1] = b""
            self.sector_info_list = []
        else:
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

        if dev_info is not None:
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


