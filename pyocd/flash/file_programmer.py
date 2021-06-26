# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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
import logging
import itertools
from elftools.elf.elffile import ELFFile
from intelhex import IntelHex
import errno

from .loader import FlashLoader
from ..core import exceptions

LOG = logging.getLogger(__name__)

def ranges(i):
    """!
    Accepts a sorted list of byte addresses. Breaks the addresses into contiguous ranges.
    Yields 2-tuples of the start and end address for each contiguous range.
    
    For instance, the input [0, 1, 2, 3, 32, 33, 34, 35] will yield the following 2-tuples:
    (0, 3) and (32, 35).
    """
    for a, b in itertools.groupby(enumerate(i), lambda x: x[1] - x[0]):
        b = list(b)
        yield b[0][1], b[-1][1]

class FileProgrammer(object):
    """! @brief Class to manage programming a file in any supported format with many options.
    
    Most specifically, this class implements the behaviour provided by the command-line flash
    programming tool. The code in this class simply extracts data from the given file, potentially
    respecting format-specific options such as the base address for binary files. Then the heavy
    lifting of flash programming is handled by FlashLoader, and beneath that, FlashBuilder.
    
    Support file formats are:
    - Binary (.bin)
    - Intel Hex (.hex)
    - ELF (.elf or .axf)
    """
    def __init__(self, session, progress=None, chip_erase=None, smart_flash=None,
        trust_crc=None, keep_unwritten=None):
        """! @brief Constructor.
        
        @param self
        @param session The session object.
        @param progress A progress report handler as a callable that takes a percentage completed.
            If not set or None, a default progress handler will be used unless the session option
            'hide_programming_progress' is set to True, in which case progress will be disabled.
        @param chip_erase Sets whether to use chip erase or sector erase. The value must be one of
            "auto", "sector", or "chip". "auto" means the fastest erase method should be used.
        @param smart_flash If set to True, the programmer will attempt to not program pages whose
            contents are not going to change by scanning target flash memory. A value of False will
            force all pages to be erased and programmed.
        @param trust_crc Boolean indicating whether to use only the sector CRC32 to decide whether a
            sector already contains the data to be programmed. Use with caution, as CRC32 may return
            the same value for different content.
        @param keep_unwritten Depending on the sector versus page size and the amount of data
            written, there may be ranges of flash that would be erased but not written with new
            data. This parameter sets whether the existing contents of those unwritten ranges will
            be read from memory and restored while programming.
        """
        self._session = session
        self._chip_erase = chip_erase
        self._smart_flash = smart_flash
        self._trust_crc = trust_crc
        self._keep_unwritten = keep_unwritten
        self._progress = progress
        self._loader = None
        
        self._format_handlers = {
            'axf': self._program_elf,
            'bin': self._program_bin,
            'elf': self._program_elf,
            'hex': self._program_hex,
            }
    
    def program(self, file_or_path, file_format=None, **kwargs):
        """! @brief Program a file into flash.
        
        @param self
        @param file_or_path Either a string that is a path to a file, or a file-like object.
        @param file_format Optional file format name, one of "bin", "hex", "elf", "axf". If not provided,
            the file's extension will be used. If a file object is passed for _file_or_path_ then
            this parameter must be used to set the format.
        @param kwargs Optional keyword arguments for format-specific parameters.
        
        The only current format-specific keyword parameters are for the binary format:
        - `base_address`: Memory address at which to program the binary data. If not set, the base
            of the boot memory will be used.
        - `skip`: Number of bytes to skip at the start of the binary file. Does not affect the
            base address.
        
        @exception FileNotFoundError Provided file_or_path string does not reference a file.
        @exception ValueError Invalid argument value, for instance providing a file object but
            not setting file_format.
        """
        isPath = isinstance(file_or_path, str)
        
        # Check for valid path first.
        if isPath and not os.path.isfile(file_or_path):
            raise FileNotFoundError(errno.ENOENT, "No such file: '{}'".format(file_or_path))
        
        # If no format provided, use the file's extension.
        if not file_format:
            if isPath:
                # Extract the extension from the path.
                file_format = os.path.splitext(file_or_path)[1][1:]
                
                # Explicitly check for no extension.
                if file_format == '':
                    raise ValueError("file path '{}' does not have an extension and "
                                        "no format is set".format(file_or_path))
            else:
                raise ValueError("file object provided but no format is set")
        
        # Check the format is one we understand.
        if file_format not in self._format_handlers:
            raise ValueError("unknown file format '%s'" % file_format)
            
        self._loader = FlashLoader(self._session,
                                    progress=self._progress,
                                    chip_erase=self._chip_erase,
                                    smart_flash=self._smart_flash,
                                    trust_crc=self._trust_crc,
                                    keep_unwritten=self._keep_unwritten)
        
        file_obj = None
        try:
            # Open the file if a path was provided.
            if isPath:
                mode = 'rb'
                if file_format == 'hex':
                    # hex file must be read as plain text file
                    mode = 'r'
                file_obj = open(file_or_path, mode)
            else:
                file_obj = file_or_path

            # Pass to the format-specific programmer.
            self._format_handlers[file_format](file_obj, **kwargs)
            self._loader.commit()
        finally:
            if isPath and file_obj is not None:
                file_obj.close()

    def _program_bin(self, file_obj, **kwargs):
        """! @brief Binary file format loader"""
        # If no base address is specified use the start of the boot memory.
        address = kwargs.get('base_address', None)
        if address is None:
            boot_memory = self._session.target.memory_map.get_boot_memory()
            if boot_memory is None:
                raise exceptions.TargetSupportError("No boot memory is defined for this device")
            address = boot_memory.start
        
        file_obj.seek(kwargs.get('skip', 0), os.SEEK_SET)
        data = list(bytearray(file_obj.read()))
        
        self._loader.add_data(address, data)

    def _program_hex(self, file_obj, **kwargs):
        """! Intel hex file format loader"""
        hexfile = IntelHex(file_obj)
        addresses = hexfile.addresses()
        addresses.sort()

        data_list = list(ranges(addresses))
        for start, end in data_list:
            size = end - start + 1
            data = list(hexfile.tobinarray(start=start, size=size))
            # Ignore invalid addresses for HEX files only
            # Binary files (obviously) don't contain addresses
            # For ELF files, any metadata that's not part of the application code 
            # will be held in a section that doesn't have the SHF_WRITE flag set
            try:
                self._loader.add_data(start, data)
            except ValueError as e:
                LOG.warning("Failed to add data chunk: %s", e)

    def _program_elf(self, file_obj, **kwargs):
        elf = ELFFile(file_obj)
        for segment in elf.iter_segments():
            addr = segment['p_paddr']
            if segment.header.p_type == 'PT_LOAD' and segment.header.p_filesz != 0:
                data = bytearray(segment.data())
                LOG.debug("Writing segment LMA:0x%08x, VMA:0x%08x, size %d", addr, 
                          segment['p_vaddr'], segment.header.p_filesz)
                try:
                    self._loader.add_data(addr, data)
                except ValueError as e:
                    LOG.warning("Failed to add data chunk: %s", e)
            else:
                LOG.debug("Skipping segment LMA:0x%08x, VMA:0x%08x, size %d", addr,
                          segment['p_vaddr'], segment.header.p_filesz)
