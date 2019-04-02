# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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
import logging
import itertools
from intelhex import IntelHex
from enum import Enum
import six
import errno

from .flash_builder import (FlashBuilder, get_page_count, get_sector_count)
from ..core.memory_map import MemoryType
from ..utility.progress import print_progress
from ..debug.elf.elf import (ELFBinaryFile, SH_FLAGS)
from ..utility.compatibility import FileNotFoundError_

LOG = logging.getLogger(__name__)

## Sentinel object used to identify an unset chip_erase parameter.
CHIP_ERASE_SENTINEL = object()

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
    def __init__(self, session, progress=None, chip_erase=CHIP_ERASE_SENTINEL, smart_flash=None,
        trust_crc=None, keep_unwritten=None):
        """! @brief Constructor.
        
        @param self
        @param session The session object.
        @param progress A progress report handler as a callable that takes a percentage completed.
            If not set or None, a default progress handler will be used unless the session option
            'hide_programming_progress' is set to True, in which case progress will be disabled.
        @param chip_erase Sets whether to use chip erase or sector erase. The value must be one of
            None, True, or False. None means the fastest erase method should be used. True means
            to force chip erase, while False means force sector erase.
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
        isPath = isinstance(file_or_path, six.string_types)
        
        # Check for valid path first.
        if isPath and not os.path.isfile(file_or_path):
            raise FileNotFoundError_(errno.ENOENT, "No such file: '{}'".format(file_or_path))
        
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

    # Binary file format
    def _program_bin(self, file_obj, **kwargs):
        # If no base address is specified use the start of the boot memory.
        address = kwargs.get('base_address', None)
        if address is None:
            address = self._session.target.memory_map.get_boot_memory().start
        
        file_obj.seek(kwargs.get('skip', 0), os.SEEK_SET)
        data = list(bytearray(file_obj.read()))
        
        self._loader.add_data(address, data)

    # Intel hex file format
    def _program_hex(self, file_obj, **kwargs):
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
                logging.warning("Failed to add data chunk: %s", e)

    # ELF format
    def _program_elf(self, file_obj, **kwargs):
        elf = ELFBinaryFile(file_obj, self._session.target.memory_map)
        for section in elf.sections:
            if ((section.type == 'SHT_PROGBITS')
                    and ((section.flags & (SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_WRITE)) == SH_FLAGS.SHF_ALLOC)
                    and (section.length > 0)
                    and (section.region.is_flash)):
                LOG.debug("Writing section %s", repr(section))
                self._loader.add_data(section.start, section.data)
            else:
                LOG.debug("Skipping section %s", repr(section))

class FlashEraser(object):
    """! @brief Class that manages high level flash erasing.
    
    Can erase a target in one of three modes:
    - chip erase: Erase all flash on the target.
    - mass erase: Also erase all flash on the target. However, on some targets, a mass erase has
        special properties such as unlocking security or erasing additional configuration regions
        that are not erased by a chip erase. If a target does not have a special mass erase, then
        it simply reverts to a chip erase.
    - sector erase: One or more sectors are erased.
    """
    class Mode(Enum):
        MASS = 1
        CHIP = 2
        SECTOR = 3
    
    def __init__(self, session, mode):
        """! @brief Constructor.
        
        @param self
        @param session The session instance.
        @param mode One of the FlashEraser.Mode enums to select mass, chip, or sector erase.
        """
        self._session = session
        self._mode = mode
    
    def erase(self, addresses=None):
        """! @brief Perform the type of erase operation selected when the object was created.
        
        For sector erase mode, an iterable of sector addresses specifications must be provided via
        the _addresses_ parameter. The address iterable elements can be either strings, tuples,
        or integers. Tuples must have two elements, the start and end addresses of a range to erase.
        Integers are simply an address within the single page to erase.
        
        String address specifications may be in one of three formats: "<address>", "<start>-<end>",
        or "<start>+<length>". Each field denoted by angled brackets is an integer literal in
        either decimal or hex notation.
        
        Examples:
        - "0x1000" - erase the one sector at 0x1000
        - "0x1000-0x4fff" - erase sectors from 0x1000 up to but not including 0x5000
        - "0x8000+0x800" - erase sectors starting at 0x8000 through 0x87ff
        
        @param self
        @param addresses List of addresses or address ranges of the sectors to erase.
        """
        if self._mode == self.Mode.MASS:
            self._mass_erase()
        elif self._mode == self.Mode.CHIP:
            self._chip_erase()
        elif self._mode == self.Mode.SECTOR and addresses:
            self._sector_erase(addresses)
        else:
            LOG.warning("No operation performed")
    
    def _mass_erase(self):
        LOG.info("Mass erasing device...")
        if self._session.target.mass_erase():
            LOG.info("Successfully erased.")
        else:
            LOG.error("Mass erase failed.")
    
    def _chip_erase(self):
        LOG.info("Erasing chip...")
        # Erase all flash regions. This may be overkill if either each region's algo erases
        # all regions on the chip. But there's no current way to know whether this will happen,
        # so prefer to be certain.
        for region in self._session.target.memory_map.get_regions_of_type(MemoryType.FLASH):
            if region.flash is not None:
                if region.flash.is_erase_all_supported:
                    region.flash.init(region.flash.Operation.ERASE)
                    region.flash.erase_all()
                    region.flash.cleanup()
                else:
                    self._sector_erase((region.start, region.end))
        LOG.info("Done")
    
    def _sector_erase(self, addresses):
        flash = None
        currentRegion = None

        for spec in addresses:
            # Convert the spec into a start and end address.
            page_addr, end_addr = self._convert_spec(spec)
            
            while page_addr < end_addr:
                # Look up the flash memory region for the current address.
                region = self._session.target.memory_map.get_region_for_address(page_addr)
                if region is None:
                    LOG.warning("address 0x%08x is not within a memory region", page_addr)
                    break
                if not region.is_flash:
                    LOG.warning("address 0x%08x is not in flash", page_addr)
                    break
            
                # Handle switching regions.
                if region is not currentRegion:
                    # Clean up previous flash.
                    if flash is not None:
                        flash.cleanup()
                
                    currentRegion = region
                    flash = region.flash
                    flash.init(flash.Operation.ERASE)
        
                # Get page info for the current address.
                page_info = flash.get_page_info(page_addr)
                if not page_info:
                    # Should not fail to get page info within a flash region.
                    raise RuntimeError("sector address 0x%08x within flash region '%s' is invalid" % (page_addr, region.name))
                
                # Align first page address.
                delta = page_addr % page_info.size
                if delta:
                    LOG.warning("sector address 0x%08x is unaligned", page_addr)
                    page_addr -= delta
        
                # Erase this page.
                LOG.info("Erasing sector 0x%08x (%d bytes)", page_addr, page_info.size)
                flash.erase_sector(page_addr)
                
                page_addr += page_info.size

        if flash is not None:
            flash.cleanup()

    def _convert_spec(self, spec):
        if isinstance(spec, six.string_types):
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
        elif isinstance(spec, tuple):
            page_addr = spec[0]
            end_addr = spec[1]
        else:
            page_addr = spec
            end_addr = page_addr + 1
        return page_addr, end_addr

class FlashLoader(object):
    """! @brief Handles high level programming of raw binary data to flash.
    
    If you need file programming, either binary files or other formats, please see the
    FileProgrammer class.
    
    This manager provides a simple interface to programming flash that may cross flash
    region boundaries. To use it, create an instance and pass in the session object. Then call
    add_data() for each chunk of binary data you need to write. When all data is added, call the
    commit() method to write everything to flash. You may reuse a single FlashLoader instance for
    multiple add-commit sequences.
    
    When programming across multiple regions, progress reports are combined so that only a
    one progress output is reported. Similarly, the programming performance report for each region
    is suppresed and a combined report is logged.
    
    Internally, FlashBuilder is used to optimise programming within each memory region.
    """
    def __init__(self, session, progress=None, chip_erase=CHIP_ERASE_SENTINEL, smart_flash=None,
        trust_crc=None, keep_unwritten=None):
        """! @brief Constructor.
        
        @param self
        @param session The session object.
        @param progress A progress report handler as a callable that takes a percentage completed.
            If not set or None, a default progress handler will be used unless the session option
            'hide_programming_progress' is set to True, in which case progress will be disabled.
        @param chip_erase Sets whether to use chip erase or sector erase. The value must be one of
            None, True, or False. None means the fastest erase method should be used. True means
            to force chip erase, while False means force sector erase.
        @param smart_flash If set to True, the flash loader will attempt to not program pages whose
            contents are not going to change by scanning target flash memory. A value of False will
            force all pages to be erased and programmed.
        @param trust_crc Boolean indicating whether to use only the sector CRC32 to decide whether a
            sector already contains the data to be programmed. Use with caution, as CRC32 may return
            the same value for different content. Only applies if smart_flash is True.
        @param keep_unwritten Depending on the sector versus page size and the amount of data
            written, there may be ranges of flash that would be erased but not written with new
            data. This parameter sets whether the existing contents of those unwritten ranges will
            be read from memory and restored while programming.
        """
        self._session = session
        self._map = session.board.target.memory_map

        if progress is not None:
            self._progress = progress
        elif session.options.get('hide_programming_progress', False):
            self._progress = None
        else:
            self._progress = print_progress()

        # We have to use a special sentinel object for chip_erase because None is a valid value.
        self._chip_erase = chip_erase if (chip_erase is not CHIP_ERASE_SENTINEL) \
                            else self._session.options.get('chip_erase', False)
        self._smart_flash = smart_flash if (smart_flash is not None) \
                            else self._session.options.get('smart_flash', True)
        self._trust_crc = trust_crc if (trust_crc is not None) \
                            else self._session.options.get('fast_program', False)
        self._keep_unwritten = keep_unwritten if (keep_unwritten is not None) \
                            else self._session.options.get('keep_unwritten', True)
        
        self._reset_state()
    
    def _reset_state(self):
        """! @brief Clear all state variables. """
        self._builders = {}
        self._total_data_size = 0
        self._progress_offset = 0
        self._current_progress_fraction = 0
    
    def add_data(self, address, data):
        """! @brief Add a chunk of data to be programmed.
        
        The data may cross flash memory region boundaries, as long as the regions are contiguous.
        
        @param self
        @param address Integer address for where the first byte of _data_ should be written.
        @param data A list of byte values to be programmed at the given address.
        
        @return The FlashLoader instance is returned, to allow chaining further add_data()
            calls or a call to commit().
        
        @exception ValueError Raised when the address is not within a flash memory region.
        @exception RuntimeError Raised if the flash memory region does not have a valid Flash
            instance associated with it, which indicates that the target connect sequence did
            not run successfully.
        """
        while len(data):
            # Look up flash region.
            region = self._map.get_region_for_address(address)
            if region is None:
                raise ValueError("no memory region defined for address 0x%08x" % address)
            if not region.is_flash:
                raise ValueError("memory region at address 0x%08x is not flash" % address)
        
            # Get our builder instance.
            if region in self._builders:
                builder = self._builders[region]
            else:
                if region.flash is None:
                    raise RuntimeError("flash memory region at address 0x%08x has no flash instance" % address)
                builder = region.flash.get_flash_builder()
                builder.log_performance = False
                self._builders[region] = builder
        
            # Add as much data to the builder as is contained by this region.
            programLength = min(len(data), region.end - address + 1)
            assert programLength != 0
            builder.add_data(address, data[:programLength])
            
            # Advance.
            data = data[programLength:]
            address += programLength
            self._total_data_size += programLength
        
        return self
    
    def commit(self):
        """! @brief Write all collected data to flash.
        
        This routine ensures that chip erase is only used once if either the auto mode or chip
        erase mode are used. As an example, if two regions are to be written to and True was
        passed to the constructor for chip_erase (or if the session option was set), then only
        the first region will actually use chip erase. The second region will be forced to use
        sector erase. This will not result in extra erasing, as sector erase always verifies whether
        the sectors are already erased. This will, of course, also work correctly if the flash
        algorithm for the first region doesn't actually erase the entire chip (all regions).
        
        After calling this method, the loader instance can be reused to program more data.
        """
        didChipErase = False
        perfList = []
        
        # Iterate over builders we've created and program the data.
        for builder in sorted(self._builders.values(), key=lambda v: v.flash_start):
            # Determine this builder's portion of total progress.
            self._current_progress_fraction = builder.buffered_data_size / self._total_data_size
            
            # Program the data.
            chipErase = self._chip_erase if not didChipErase else False
            perf = builder.program(chip_erase=chipErase,
                                    progress_cb=self._progress_cb,
                                    smart_flash=self._smart_flash,
                                    fast_verify=self._trust_crc,
                                    keep_unwritten=self._keep_unwritten)
            perfList.append(perf)
            didChipErase = True
            
            self._progress_offset += self._current_progress_fraction

        # Report programming statistics.
        self._log_performance(perfList)
        
        # Clear state to allow reuse.
        self._reset_state()
    
    def _log_performance(self, perf_list):
        """! @brief Log a report of programming performance numbers."""
        # Compute overall performance numbers.
        totalProgramTime = sum(perf.program_time for perf in perf_list)
        program_byte_count = sum(perf.total_byte_count for perf in perf_list)
        actual_program_byte_count = sum(perf.program_byte_count for perf in perf_list)
        actual_program_page_count = sum(perf.program_page_count for perf in perf_list)
        skipped_byte_count = sum(perf.skipped_byte_count for perf in perf_list)
        skipped_page_count = sum(perf.skipped_page_count for perf in perf_list)
        
        # Compute kbps while avoiding a potential zero-div error.
        if totalProgramTime == 0:
            kbps = 0
        else:
            kbps = (program_byte_count/1024) / totalProgramTime
        
        if any(perf.program_type == FlashBuilder.FLASH_CHIP_ERASE for perf in perf_list):
            LOG.info("Erased chip, programmed %d bytes (%s), skipped %d bytes (%s) at %.02f kB/s",
                actual_program_byte_count, get_page_count(actual_program_page_count),
                skipped_byte_count, get_page_count(skipped_page_count),
                kbps)
        else:
            erase_byte_count = sum(perf.erase_byte_count for perf in perf_list)
            erase_sector_count = sum(perf.erase_sector_count for perf in perf_list)

            LOG.info("Erased %d bytes (%s), programmed %d bytes (%s), skipped %d bytes (%s) at %.02f kB/s", 
                erase_byte_count, get_sector_count(erase_sector_count),
                actual_program_byte_count, get_page_count(actual_program_page_count),
                skipped_byte_count, get_page_count(skipped_page_count),
                kbps)
        
    def _progress_cb(self, amount):
        if self._progress is not None:
            self._progress((amount * self._current_progress_fraction) + self._progress_offset)
    
    @classmethod
    def program_binary_data(cls, session, address, data):
        """! @brief Helper routine to write a single chunk of data.
        
        The session options for chip_erase and trust_crc are used.
        
        @param cls
        @param session The session instance.
        @param address Start address of the data to program.
        @param data A list of byte values that will be programmed starting at _address_.
        """
        mgr = cls(session)
        mgr.add_data(address, data)
        mgr.commit()

