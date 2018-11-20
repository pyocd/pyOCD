# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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
import sys
import logging
import itertools
from struct import unpack
from intelhex import IntelHex
from enum import Enum

from ..utility.progress import print_progress
from ..debug.elf.elf import (ELFBinaryFile, SH_FLAGS)

LOG = logging.getLogger(__name__)

def ranges(i):
    for a, b in itertools.groupby(enumerate(i), lambda x: x[1] - x[0]):
        b = list(b)
        yield b[0][1], b[-1][1]

class FileProgrammer(object):
    """! @brief Class to manage programming a file in any supported format with many options.
    
    Most specifically, this class implements the behaviour provided by the command-line flash
    programming tool.
    """
    def __init__(self, session, args):
        self._session = session
        self._args = args
        
        self._progress = print_progress()
        if self._session.options.get("hide_progress", False):
            self._progress = None

        if self._args.erase == 'chip':
            self._chip_erase = True
        elif self._args.erase == 'sector':
            self._chip_erase = False
        elif self._args.erase == 'auto':
            self._chip_erase = None
        else:
            raise ValueError("unsupported erase mode '%s'" % self._args.erase)
    
    def program(self, path):
        if not path:
            LOG.warning("No file provided")
            return
        
        # If no format provided, use the file's extension.
        if not self._args.format:
            self._args.format = os.path.splitext(path)[1][1:]
            if self._args.format == 'axf':
                self._args.format = 'elf'

        # Binary file format
        if self._args.format == 'bin':
            self._program_bin(path)
        # Intel hex file format
        elif self._args.format == 'hex':
            self._program_hex(path)
        # ELF format
        elif self._args.format == 'elf':
            self._program_elf(path)
        else:
            LOG.error("unknown file format '%s'", self._args.format)

    # Binary file format
    def _program_bin(self, path):
        board = self._session.board
        flash = board.flash

        # If no address is specified use the start of rom
        if self._args.base_address is None:
            self._args.base_address = self._session.board.flash.get_flash_info().rom_start

        with open(path, "rb") as f:
            f.seek(self._args.skip, 0)
            data = f.read()
        address = self._args.base_address + self._args.skip
        data = unpack(str(len(data)) + 'B', data)
        flash.flash_block(address, data, chip_erase=self._chip_erase, progress_cb=self._progress,
             fast_verify=self._args.trust_crc)

    # Intel hex file format
    def _program_hex(self, path):
        board = self._session.board
        flash = board.flash

        hexfile = IntelHex(path)
        addresses = hexfile.addresses()
        addresses.sort()

        flash_builder = flash.get_flash_builder()

        data_list = list(ranges(addresses))
        for start, end in data_list:
            size = end - start + 1
            data = list(hexfile.tobinarray(start=start, size=size))
            flash_builder.add_data(start, data)
        flash_builder.program(chip_erase=self._chip_erase, progress_cb=self._progress,
            fast_verify=self._args.trust_crc)
    
    # ELF format
    def _program_elf(self, path):
        board = self._session.board
        flash = board.flash
        flash_builder = flash.get_flash_builder()

        with open(path, "rb") as f:
            elf = ELFBinaryFile(f, board.target.memory_map)
            for section in elf.sections:
                if ((section.type == 'SHT_PROGBITS')
                        and ((section.flags & (SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_WRITE)) == SH_FLAGS.SHF_ALLOC)
                        and (section.length > 0)
                        and (section.region.is_flash)):
                    LOG.debug("Writing section %s", repr(section))
                    flash_builder.add_data(section.start, section.data)
                else:
                    LOG.debug("Skipping section %s", repr(section))
                    
        flash_builder.program(chip_erase=self._chip_erase, progress_cb=self._progress,
            fast_verify=self._args.trust_crc)

class FlashEraser(object):
    """! @brief Class that manages high level flash erasing.
    """
    class Mode(Enum):
        MASS = 1
        CHIP = 2
        SECTOR = 3
    
    def __init__(self, session, mode):
        self._session = session
        self._mode = mode
    
    def erase(self, addresses=[]):
        board = self._session.board
        flash = board.flash
    
        if self._mode == self.Mode.MASS:
            LOG.info("Mass erasing device...")
            if board.target.mass_erase():
                LOG.info("Successfully erased.")
            else:
                LOG.error("Mass erase failed.")
        elif self._mode == self.Mode.CHIP:
            LOG.info("Erasing chip...")
            flash.init()
            flash.erase_all()
            LOG.info("Done")
            flash.cleanup()
        elif self._mode == self.Mode.SECTOR and len(addresses):
            flash.init()

            for spec in addresses:
                # Convert spec from string to range.
                if '-' in spec:
                    a, b = spec.split('-')
                    page_addr = int(a, base=0)
                    end_addr = int(b, base=0)
                elif '+' in spec:
                    a, b = spec.split('+')
                    page_addr = int(a, base=0)
                    length = int(b, base=0)
                    end_addr = page_addr + length
                else:
                    page_addr = int(spec, base=0)
                    end_addr = page_addr + 1
            
                # Align first page address.
                page_info = flash.get_page_info(page_addr)
                if not page_info:
                    LOG.warning("sector address 0x%08x is invalid", page_addr)
                    continue
                delta = page_addr % page_info.size
                if delta:
                    old_page_addr = page_addr
                    page_addr -= delta
                    LOG.warning("sector address 0x%08x is unaligned", page_addr)
            
                # Erase pages.
                while page_addr < end_addr:
                    page_info = flash.get_page_info(page_addr)
                    if not page_info:
                        LOG.warning("sector address 0x%08x is invalid", page_addr)
                        break
                    LOG.info("Erasing sector 0x%08x (%d bytes)", page_addr, page_info.size)
                    flash.erase_page(page_addr)
                    page_addr += page_info.size

            flash.cleanup()
        else:
            LOG.warning("No operation performed")

