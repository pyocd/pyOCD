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

import logging

from .builder import (FlashBuilder, get_page_count, get_sector_count)
from ..core import exceptions
from ..utility.progress import print_progress

LOG = logging.getLogger(__name__)

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
        elif session.options.get('hide_programming_progress'):
            self._progress = None
        else:
            self._progress = print_progress()

        # We have to use a special sentinel object for chip_erase because None is a valid value.
        self._chip_erase = chip_erase if (chip_erase is not None) \
                            else self._session.options.get('chip_erase')
        self._smart_flash = smart_flash if (smart_flash is not None) \
                            else self._session.options.get('smart_flash')
        self._trust_crc = trust_crc if (trust_crc is not None) \
                            else self._session.options.get('fast_program')
        self._keep_unwritten = keep_unwritten if (keep_unwritten is not None) \
                            else self._session.options.get('keep_unwritten')
        
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
        @exception TargetSupportError Raised if the flash memory region does not have a valid Flash
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
                    raise exceptions.TargetSupportError("flash memory region at address 0x%08x has no flash instance" % address)
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
            chipErase = self._chip_erase if not didChipErase else "sector"
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

