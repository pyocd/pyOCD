# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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
from typing import (TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple)

from ...debug.elf.elf import ELFBinaryFile
from ...utility.compatibility import to_str_safe
from ...core.memory_map import MemoryRange
from ...core import exceptions
from ...utility.conversion import byte_list_to_u32le_list
from ...utility.mask import align_down

if TYPE_CHECKING:
    from ...debug.elf.elf import ELFSection
    from ...core.memory_map import RamRegion

LOG = logging.getLogger(__name__)

class FlashAlgoException(exceptions.TargetSupportError):
    """@brief Exception class for errors parsing an FLM file."""
    pass

RoRwZiType = Tuple[Optional["ELFSection"], Optional["ELFSection"], Optional[MemoryRange]]

class PackFlashAlgo:
    """@brief Class to wrap a flash algo

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

    ## @brief Standard flash blob header with a breakpoint instruction.
    #
    # This header consists of two instructions:
    #
    # ```
    # bkpt  #0
    # b     .-2     # branch to the bkpt
    # ```
    #
    # Before running a flash algo operation, LR is set to the address of the `bkpt` instruction,
    # so when the operation function returns it will halt the CPU.
    _FLASH_BLOB_HEADER = [ 0xE7FDBE00 ]
    ## @brief Size of the flash blob header in bytes.
    _FLASH_BLOB_HEADER_SIZE = len(_FLASH_BLOB_HEADER) * 4

    # Minimum size that must be allocated for the flash algo stack.
    _MIN_STACK_SIZE = 512

    # Alignment for page buffers.
    _PAGE_BUFFER_ALIGN = 16

    def __init__(self, data):
        """@brief Construct a PackFlashAlgo from a file-like object."""
        self.elf = ELFBinaryFile(data)
        self.flash_info = PackFlashInfo(self.elf)

        self.flash_start = self.flash_info.start
        self.flash_size = self.flash_info.size
        self.page_size = self.flash_info.page_size
        self.sector_sizes = self.flash_info.sector_info_list

        symbols: Dict[str, int] = {}
        x = self._extract_symbols(self.REQUIRED_SYMBOLS)
        symbols.update(x)
        symbols.update(self._extract_symbols(self.EXTRA_SYMBOLS,
                                        default=0xFFFFFFFF))
        self.symbols = symbols

        ro_rw_zi = self._find_sections(self.SECTIONS_TO_FIND)
        ro_rw_zi = self._algo_fill_zi_if_missing(ro_rw_zi)
        error_msg = self._algo_check_for_section_problems(ro_rw_zi)
        if error_msg is not None:
            raise FlashAlgoException(error_msg)

        sect_ro, sect_rw, sect_zi = ro_rw_zi
        assert sect_ro and sect_rw and sect_zi
        self.ro_start = sect_ro.start
        self.ro_size = sect_ro.length
        self.rw_start = sect_rw.start
        self.rw_size = sect_rw.length
        self.zi_start = sect_zi.start
        self.zi_size = sect_zi.length

        self.algo_data = self._create_algo_bin(ro_rw_zi)

    def iter_sector_size_ranges(self) -> Iterator[Tuple[MemoryRange, int]]:
        """@brief Iterator yielding tuples with a memory ranges and sector size for each of the algo's
            sector sizes.
        """
        # The sector_sizes attribute is a list of bi-tuples of (start-address, sector-size), sorted by start address.
        for j, (offset, sector_size) in enumerate(self.sector_sizes):
            start = self.flash_start + offset

            # Determine the end address of the this sector range. For the last range, the end
            # is just the end of the entire region. Otherwise it's the start of the next
            # range - 1.
            if j + 1 >= len(self.sector_sizes):
                end = self.flash_start + self.flash_size - 1
            else:
                end = self.flash_start + self.sector_sizes[j + 1][0] - 1

            # Skip wrong start and end addresses
            if end < start:
                continue

            yield MemoryRange(start, end), sector_size

    def get_pyocd_flash_algo(self, blocksize: int, ram_region: "RamRegion") -> Dict[str, Any]:
        """@brief Return a dictionary representing a pyOCD flash algorithm, or None.

        The most interesting operation this method performs is dynamically allocating memory
        for the flash algo from a given RAM region. Note that the .data and .bss sections are
        concatenated with .text. That's why there isn't a specific allocation for those sections.

        Double buffering is supported as long as there is enough RAM.

        Memory layout:
        ```
        [<--stack] [buf2] [buf1] [code]
        ^ ram start                   ^ ram end
        ```

        @param self
        @param blocksize The size to use for page buffers, normally the erase block size.
        @param ram_region A RamRegion object where the flash algo will be allocated.
        @return A pyOCD-style flash algo dictionary. If None is returned, the flash algo did
            not fit into the provided ram_region.

        @exception FlashAlgoException Raised if the algo cannot be placed in memory.
        """
        instructions = self._FLASH_BLOB_HEADER + byte_list_to_u32le_list(self.algo_data)

        # Start at end of RAM and work backwards.
        addr = ram_region.start + ram_region.length

        # Load address
        addr -= len(instructions) * 4
        addr_load = addr

        # Data buffer 1
        unaligned_buffer_addr = addr - blocksize
        addr = align_down(unaligned_buffer_addr, self._PAGE_BUFFER_ALIGN)
        addr_data = addr

        if addr_data < ram_region.start:
            # Not enough space for flash algorithm
            raise FlashAlgoException("not enough memory space to fit flash algorithm")

        # Data buffer 2
        unaligned_buffer_addr = addr - blocksize
        addr = align_down(unaligned_buffer_addr, self._PAGE_BUFFER_ALIGN)
        addr_data2 = addr

        # Stack
        # Select best fit for one or two data buffers and a variable size stack.
        # TODO Switching down from two to one buffer should probably be done with the stack size around
        #   mid-level instead of going all the way down to minimum first.
        stack_size_one_buf = addr_data - ram_region.start
        stack_size_two_bufs = addr_data2 - ram_region.start

        if stack_size_two_bufs < self._MIN_STACK_SIZE:
            # One buffer
            stack_size = stack_size_one_buf
            addr_stack = addr_data
            page_buffers = [addr_data]

            LOG.debug("flash algo: [stack=%#x; %#x b] [b1=%#x,+%#x] [code=%#x,+%#x,%#x b] (ram=%#010x, %#x b)",
                addr_stack, stack_size,
                addr_data, addr_data - ram_region.start,
                addr_load, addr_load - ram_region.start, len(instructions) * 4,
                ram_region.start, ram_region.length
            )
        else:
            stack_size = stack_size_two_bufs
            addr_stack = addr_data2
            page_buffers = [addr_data, addr_data2]

            LOG.debug("flash algo: [stack=%#x; %#x b] [b2=%#x,+%#x] [b1=%#x,+%#x] [code=%#x,+%#x,%#x b] (ram=%#010x, %#x b)",
                addr_stack, stack_size,
                addr_data, addr_data - ram_region.start,
                addr_data2, addr_data2 - ram_region.start,
                addr_load, addr_load - ram_region.start, len(instructions) * 4,
                ram_region.start, ram_region.length
            )
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
            "end_stack": addr_stack - stack_size,
            "static_base": code_start + self.rw_start,
            "min_program_length": self.page_size,
            "analyzer_supported": False
        }
        return flash_algo

    def _extract_symbols(self, symbols: Set[str], default: Optional[int] = None) -> Dict[str, int]:
        """@brief Fill 'symbols' field with required flash algo symbols"""
        to_ret: Dict[str, int] = {}
        for symbol in symbols:
            symbolInfo = self.elf.symbol_decoder.get_symbol_for_name(symbol)
            if symbolInfo is None:
                if default is not None:
                    to_ret[symbol] = default
                    continue
                raise FlashAlgoException("Missing symbol %s" % symbol)
            to_ret[symbol] = symbolInfo.address
        return to_ret

    def _find_sections(self, name_type_pairs: Sequence[Tuple[str, str]]) -> Tuple[Optional["ELFSection"], ...]:
        """@brief Return a list of sections the same length and order of the input list"""
        sections: List[Optional["ELFSection"]] = [None] * len(name_type_pairs)
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
        return tuple(sections)

    def _algo_fill_zi_if_missing(self, ro_rw_zi: RoRwZiType) -> RoRwZiType:
        """@brief Create an empty zi section if it is missing"""
        s_ro, s_rw, s_zi = ro_rw_zi
        if s_rw is None:
            return ro_rw_zi
        if s_zi is not None:
            return ro_rw_zi
        s_zi = MemoryRange(start=(s_rw.start + s_rw.length), length=0)
        return s_ro, s_rw, s_zi

    def _algo_check_for_section_problems(self, ro_rw_zi: RoRwZiType) -> Optional[str]:
        """@brief Return a string describing any errors with the layout or None if good"""
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

    def _create_algo_bin(self, ro_rw_zi: RoRwZiType):
        """Create a binary blob of the flash algo which can execute from ram"""
        sect_ro, sect_rw, sect_zi = ro_rw_zi
        assert sect_ro and sect_rw and sect_zi
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
    """@brief Wrapper class for the non-executable information in an FLM file"""

    FLASH_DEVICE_STRUCT = "<H128sHLLLLBxxxLL"
    FLASH_DEVICE_STRUCT_SIZE = struct.calcsize(FLASH_DEVICE_STRUCT)
    FLASH_SECTORS_STRUCT = "<LL"
    FLASH_SECTORS_STRUCT_SIZE = struct.calcsize(FLASH_SECTORS_STRUCT)
    SECTOR_END = 0xFFFFFFFF

    def __init__(self, elf):
        dev_info = elf.symbol_decoder.get_symbol_for_name("FlashDevice")
        if dev_info is None:
            values: Sequence[Any] = [0] * 10
            values[1] = b""
            self.sector_info_list = []
            info_start = 0
            info_size = 0
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


