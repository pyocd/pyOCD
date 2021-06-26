# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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
from time import time
from binascii import crc32

from ..core.target import Target
from ..core.exceptions import (FlashFailure, FlashProgramFailure)
from ..utility.mask import same

# Number of bytes in a page to read to quickly determine if the page has the same data
PAGE_ESTIMATE_SIZE = 32
DATA_TRANSFER_B_PER_S = 40 * 1000 # ~40KB/s, depends on clock speed, theoretical limit for HID is 56,000 B/s

LOG = logging.getLogger(__name__)

def get_page_count(count):
    """! @brief Return string for page count with correct plurality."""
    if count == 1:
        return "1 page"
    else:
        return "{} pages".format(count)

def get_sector_count(count):
    """! @brief Return string for sector count with correct plurality."""
    if count == 1:
        return "1 sector"
    else:
        return "{} sectors".format(count)

class ProgrammingInfo(object):
    def __init__(self):
        self.program_type = None                # Type of programming performed - FLASH_SECTOR_ERASE or FLASH_CHIP_ERASE
        self.program_time = None                # Total programming time
        self.analyze_type = None                # Type of flash analysis performed - FLASH_ANALYSIS_CRC32 or FLASH_ANALYSIS_PARTIAL_PAGE_READ
        self.analyze_time = None                # Time to analyze flash contents
        self.total_byte_count = 0
        self.program_byte_count = 0
        self.program_page_count = 0
        self.erase_byte_count = 0
        self.erase_sector_count = 0
        self.skipped_byte_count = 0
        self.skipped_page_count = 0

def _stub_progress(percent):
    pass

class _FlashSector(object):
    """! @brief Info about an erase sector and all pages to be programmed within it."""
    def __init__(self, sector_info):
        self.addr = sector_info.base_addr
        self.size = sector_info.size
        self.max_page_count = 0
        self.page_list = []
        self.erase_weight = sector_info.erase_weight
    
    def add_page(self, page):
        # The first time a page is added, compute the page count for this sector. This
        # obviously assumes that all the pages in the sector are the same size.
        if len(self.page_list) == 0:
            self.max_page_count = self.size // page.size
            assert (self.size % page.size) == 0, "Flash pages (%d bytes) do not fit evenly " \
                                                "into sector (%d bytes)" % (page.size, self.size)
        assert len(self.page_list) < self.max_page_count
        self.page_list.append(page)
        self.page_list.sort(key=lambda p:p.addr)
    
    def are_any_pages_not_same(self):
        """! @brief Returns True if any pages in this sector might need to be programmed."""
        return any(page.same is not True for page in self.page_list)
    
    def mark_all_pages_not_same(self):
        """! @brief Sets the same flag to False for all pages in this sector."""
        for page in self.page_list:
            page.same = False
    
    def __repr__(self):
        return "<_FlashSector@%x addr=%x size=%x wgt=%g pages=%s>" % (
            id(self), self.addr, self.size, self.erase_weight, self.page_list)

class _FlashPage(object):
    """! @brief A page to be programmed and its data."""
    def __init__(self, page_info):
        self.addr = page_info.base_addr
        self.size = page_info.size
        self.data = []
        self.program_weight = page_info.program_weight
        self.erased = None # Whether the data all matches the erased value.
        self.same = None
        self.crc = None
        self.cached_estimate_data = None

    def get_program_weight(self):
        """! @brief Get time to program a page including the data transfer."""
        return self.program_weight + \
            float(len(self.data)) / float(DATA_TRANSFER_B_PER_S)

    def get_verify_weight(self):
        """! @brief Get time to verify a page."""
        return float(self.size) / float(DATA_TRANSFER_B_PER_S)
    
    def __repr__(self):
        return "<_FlashPage@%x addr=%x size=%x datalen=%x wgt=%g erased=%s same=%s>" % (
            id(self), self.addr, self.size, len(self.data), self.program_weight, self.erased, self.same)

class _FlashOperation(object):
    """! @brief Holds requested data to be programmed at a given address."""
    def __init__(self, addr, data):
        self.addr = addr
        self.data = data

class FlashBuilder(object):
    """! @brief Manages programming flash within one flash memory region.

    The purpose of this class is to optimize flash programming within a single region to achieve
    the highest flash programming performance possible. Various methods are used to estimate the
    fastest programming method.
    
    Individual flash algorithm operations are performed by the @ref pyocd.flash.flash.Flash
    "Flash" instance provided to the contructor.
        
    Assumptions:
    1. Sector erases must be on sector boundaries.
    2. Page writes must be on page boundaries.
    3. Pages are never larger than sectors, but can be smaller.
    4. There must be an even number of pages within a sector.
    5. Entire pages must be programmed.
    """

    # Type of flash operation
    FLASH_SECTOR_ERASE = 1
    FLASH_CHIP_ERASE = 2

    # Type of flash analysis
    FLASH_ANALYSIS_CRC32 = "CRC32"
    FLASH_ANALYSIS_PARTIAL_PAGE_READ = "PAGE_READ"

    def __init__(self, flash):
        self.flash = flash
        self.flash_start = flash.region.start
        self.flash_operation_list = []
        self.sector_list = []
        self.page_list = []
        self.perf = ProgrammingInfo()
        self.enable_double_buffering = True
        self.log_performance = True
        self.buffered_data_size = 0
        self.program_byte_count = 0
        self.sector_erase_count = 0
        self.chip_erase_count = 0 # Number of pages to program using chip erase method.
        self.chip_erase_weight = 0 # Erase/program weight using chip erase method.
        self.sector_erase_count = 0 # Number of pages to program using sector erase method.
        self.sector_erase_weight = 0 # Erase/program weight using sector erase method.
        self.algo_inited_for_read = False

    def enable_double_buffer(self, enable):
        self.enable_double_buffering = enable

    def add_data(self, addr, data):
        """! @brief Add a block of data to be programmed.

        @note Programming does not start until the method program() is called.
        
        @param self
        @param addr Base address of the block of data passed to this method. The entire block of
            data must be contained within the flash memory region associated with this instance.
        @param data Data to be programmed. Should be a list of byte values.
        
        @exception ValueError Attempt to add overlapping data, or address range of added data is
            outside the address range of the flash region associated with the builder.
        """
        # Ignore empty data.
        if len(data) == 0:
            return
        
        # Sanity check
        if not self.flash.region.contains_range(start=addr, length=len(data)):
            raise ValueError("Flash address range 0x%x-0x%x is not contained within region '%s'" %
                (addr, addr + len(data) - 1, self.flash.region.name))

        # Add operation to list
        self.flash_operation_list.append(_FlashOperation(addr, data))
        self.buffered_data_size += len(data)

        # Keep list sorted
        self.flash_operation_list = sorted(self.flash_operation_list, key=lambda operation: operation.addr)
        
        # Verify this does not overlap
        prev_flash_operation = None
        for operation in self.flash_operation_list:
            if prev_flash_operation is not None:
                if prev_flash_operation.addr + len(prev_flash_operation.data) > operation.addr:
                    raise ValueError("Error adding data - Data at 0x%x..0x%x overlaps with 0x%x..0x%x"
                            % (prev_flash_operation.addr, prev_flash_operation.addr + len(prev_flash_operation.data),
                               operation.addr, operation.addr + len(operation.data)))
            prev_flash_operation = operation
    
    def _enable_read_access(self):
        """! @brief Ensure flash is accessible by initing the algo for verify.
        
        Not all flash memories are always accessible. For instance, external QSPI. Initing the
        flash algo for the VERIFY operation is the canonical way to ensure that the flash is
        memory mapped and accessible.
        """
        if not self.algo_inited_for_read:
            try:
                self.flash.init(self.flash.Operation.VERIFY)
            except FlashFailure:
                # If initing for verify fails, then try again in erase mode.
                self.flash.init(self.flash.Operation.ERASE)
            self.algo_inited_for_read = True

    def _build_sectors_and_pages(self, keep_unwritten):
        """! @brief Converts the list of flash operations to flash sectors and pages.
        
        @param self
        @param keep_unwritten If true, unwritten pages in an erased sector and unwritten
            contents of a modified page will be read from the target and added to the data to be
            programmed.

        @exception FlashFailure Could not get sector or page info for an address.
        """
        assert len(self.flash_operation_list) > 0
        
        self.program_byte_count = 0
        
        flash_addr = self.flash_operation_list[0].addr
        sector_info = self.flash.get_sector_info(flash_addr)
        if sector_info is None:
            raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % flash_addr)
        
        page_info = self.flash.get_page_info(flash_addr)
        if page_info is None:
            raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % flash_addr)

        current_sector = _FlashSector(sector_info)
        self.sector_list.append(current_sector)
        current_page = _FlashPage(page_info)
        current_sector.add_page(current_page)
        self.page_list.append(current_page)
        
        def fill_end_of_page_gap():
            # Fill the gap at the end of the soon to be previous page if there is one
            if len(current_page.data) != current_page.size:
                page_data_end = current_page.addr + len(current_page.data)
                old_data_len = current_page.size - len(current_page.data)
                if keep_unwritten and self.flash.region.is_readable:
                    self._enable_read_access()
                    old_data = self.flash.target.read_memory_block8(page_data_end, old_data_len)
                else:
                    old_data = [self.flash.region.erased_byte_value] * old_data_len
                current_page.data.extend(old_data)
                self.program_byte_count += old_data_len
        
        for flash_operation in self.flash_operation_list:
            pos = 0
            while pos < len(flash_operation.data):
                flash_addr = flash_operation.addr + pos
                
                # Check if operation is in a different sector.
                if flash_addr >= current_sector.addr + current_sector.size:
                    sector_info = self.flash.get_sector_info(flash_addr)
                    if sector_info is None:
                        raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % flash_addr)
                    current_sector = _FlashSector(sector_info)
                    self.sector_list.append(current_sector)

                # Check if operation is in a different page
                if flash_addr >= current_page.addr + current_page.size:
                    # Fill any gap at the end of the current page before switching to a new page.
                    fill_end_of_page_gap()
                    
                    # Create the new page.
                    page_info = self.flash.get_page_info(flash_addr)
                    if page_info is None:
                        raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % flash_addr)
                    current_page = _FlashPage(page_info)
                    current_sector.add_page(current_page)
                    self.page_list.append(current_page)

                # Fill the page gap if there is one
                page_data_end = current_page.addr + len(current_page.data)
                if flash_addr != page_data_end:
                    old_data_len = flash_addr - page_data_end
                    if keep_unwritten and self.flash.region.is_readable:
                        self._enable_read_access()
                        old_data = self.flash.target.read_memory_block8(page_data_end, old_data_len)
                    else:
                        old_data = [self.flash.region.erased_byte_value] * old_data_len
                    current_page.data.extend(old_data)
                    self.program_byte_count += old_data_len

                # Copy data to page and increment pos
                space_left_in_page = page_info.size - len(current_page.data)
                space_left_in_data = len(flash_operation.data) - pos
                amount = min(space_left_in_page, space_left_in_data)
                current_page.data.extend(flash_operation.data[pos:pos + amount])
                self.program_byte_count += amount

                #increment position
                pos += amount

        # Fill the page gap at the end if there is one
        fill_end_of_page_gap()
        
        # Go back through sectors and fill any missing pages with existing data.
        if keep_unwritten and self.flash.region.is_readable:
            self._fill_unwritten_sector_pages()
        
    def _fill_unwritten_sector_pages(self):
        """! @brief Fill in missing pages from sectors we are going to modify."""
        for sector in self.sector_list:
            sector_page_number = 0
            sector_page_addr = sector.addr

            def add_page_with_existing_data():
                page_info = self.flash.get_page_info(sector_page_addr)
                if page_info is None:
                    raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % sector_page_addr)
                new_page = _FlashPage(page_info)
                self._enable_read_access()
                new_page.data = self.flash.target.read_memory_block8(new_page.addr, new_page.size)
                new_page.same = True
                sector.add_page(new_page)
                self.page_list.append(new_page)
                self.program_byte_count += len(new_page.data)
                return new_page
        
            # Iterate over pages defined for the sector. If a gap is found, a new page is inserted
            # with the current contents of target memory.
            while sector_page_number < len(sector.page_list):
                page = sector.page_list[sector_page_number]
            
                if page.addr != sector_page_addr:
                    page = add_page_with_existing_data()
            
                sector_page_number += 1
                sector_page_addr += page.size
        
            # Add missing pages at the end of the sector.
            while sector_page_addr < sector.addr + sector.size:
                page = add_page_with_existing_data()
                sector_page_addr += page.size

    def program(self, chip_erase=None, progress_cb=None, smart_flash=True, fast_verify=False, keep_unwritten=True):
        """! @brief Determine fastest method of flashing and then run flash programming.

        Data must have already been added with add_data().
        
        If the flash region's 'are_erased_sectors_readable' attribute is false, then the
        smart_flash, fast_verify, and keep_unwritten options are forced disabled.
        
        @param self
        @param chip_erase A value of "chip" forces chip erase, "sector" forces sector erase, and a
            value of "auto" means that the estimated fastest method should be used. If not
            specified, the default is auto.
        @param progress_cb A callable that accepts a single parameter of the percentage complete.
        @param smart_flash If True, FlashBuilder will scan target memory to attempt to avoid
            programming contents that are not changing with this program request. False forces
            all requested data to be programmed.
        @param fast_verify If smart_flash is enabled and the target supports the CRC32 analyzer,
            this parameter controls whether positive results from the analyzer will be accepted.
            In other words, pages with matching CRCs will be marked as the same. There is a small,
            but non-zero, chance that the CRCs match even though the data is different, but the
            odds of this happing are low: ~1/(2^32) = ~2.33*10^-8%.
        @param keep_unwritten Depending on the sector versus page size and the amount of data
            written, there may be ranges of flash that would be erased but not written with new
            data. This parameter sets whether the existing contents of those unwritten ranges will
            be read from memory and restored while programming.
        """

        # Send notification that we're about to program flash.
        self.flash.target.session.notify(Target.Event.PRE_FLASH_PROGRAM, self)
        
        # Disable options if attempting to read erased sectors will fault.
        if not self.flash.region.are_erased_sectors_readable:
            smart_flash = False
            fast_verify = False
            keep_unwritten = False

        # Examples
        # - lpc4330     -Non 0 base address
        # - nRF51       -UICR location far from flash (address 0x10001000)
        # - LPC1768     -Different sized pages
        program_start = time()

        if progress_cb is None:
            progress_cb = _stub_progress

        # There must be at least 1 flash operation
        if len(self.flash_operation_list) == 0:
            LOG.warning("No pages were programmed")
            return
        
        # Convert chip_erase.
        if (chip_erase is None) or (chip_erase == "auto"):
            chip_erase = None
        elif chip_erase == "sector":
            chip_erase = False
        elif chip_erase == "chip":
            chip_erase = True
        else:
            raise ValueError("invalid chip_erase value '{}'".format(chip_erase))

        # Convert the list of flash operations into flash sectors and pages
        self._build_sectors_and_pages(keep_unwritten)
        assert len(self.sector_list) != 0 and len(self.sector_list[0].page_list) != 0
        self.flash_operation_list = None # Don't need this data in memory anymore.
        
        # If smart flash was set to false then mark all pages
        # as requiring programming
        if not smart_flash:
            self._mark_all_pages_for_programming()
        
        # If the flash algo doesn't support erase all, disable chip erase.
        if not self.flash.is_erase_all_supported:
            chip_erase = False

        # If the first page being programmed is not the first page
        # in flash then don't use a chip erase unless explicitly directed to.
        if self.page_list[0].addr > self.flash_start:
            if chip_erase is None:
                chip_erase = False
            elif chip_erase is True:
                LOG.warning('Chip erase used when flash address 0x%x is not the same as flash start 0x%x',
                    self.page_list[0].addr, self.flash_start)

        chip_erase_count, chip_erase_program_time = self._compute_chip_erase_pages_and_weight()
        sector_erase_min_program_time = self._compute_sector_erase_pages_weight_min()

        # If chip_erase hasn't been specified determine if chip erase is faster
        # than page erase regardless of contents
        if (chip_erase is None) and (chip_erase_program_time < sector_erase_min_program_time):
            chip_erase = True

        # If chip erase isn't True then analyze the flash
        if chip_erase is not True:
            sector_erase_count, page_program_time = self._compute_sector_erase_pages_and_weight(fast_verify)

        # If chip erase hasn't been set then determine fastest method to program
        if chip_erase is None:
            LOG.debug("Chip erase count %i, sector erase est count %i" % (chip_erase_count, sector_erase_count))
            LOG.debug("Chip erase weight %f, sector erase weight %f" % (chip_erase_program_time, page_program_time))
            chip_erase = chip_erase_program_time < page_program_time

        if chip_erase:
            if self.flash.is_double_buffering_supported and self.enable_double_buffering:
                LOG.debug("Using double buffer chip erase program")
                flash_operation = self._chip_erase_program_double_buffer(progress_cb)
            else:
                flash_operation = self._chip_erase_program(progress_cb)
        else:
            if self.flash.is_double_buffering_supported and self.enable_double_buffering:
                LOG.debug("Using double buffer sector erase program")
                flash_operation = self._sector_erase_program_double_buffer(progress_cb)
            else:
                flash_operation = self._sector_erase_program(progress_cb)

        # Cleanup flash algo and reset target after programming.
        self.flash.cleanup()
        self.flash.target.reset_and_halt()

        program_finish = time()
        self.perf.program_time = program_finish - program_start
        self.perf.program_type = flash_operation

        erase_byte_count = 0
        erase_sector_count = 0
        actual_program_byte_count = 0
        actual_program_page_count = 0
        skipped_byte_count = 0
        skipped_page_count = 0
        for page in self.page_list:
            if (page.same is True) or (page.erased and chip_erase):
                skipped_byte_count += page.size
                skipped_page_count += 1
            else:
                actual_program_byte_count += page.size
                actual_program_page_count += 1
        for sector in self.sector_list:
            if sector.are_any_pages_not_same():
                erase_byte_count += sector.size
                erase_sector_count += 1
        
        self.perf.total_byte_count = self.program_byte_count
        self.perf.program_byte_count = actual_program_byte_count
        self.perf.program_page_count = actual_program_page_count
        self.perf.erase_byte_count = erase_byte_count
        self.perf.erase_sector_count = erase_sector_count
        self.perf.skipped_byte_count = skipped_byte_count
        self.perf.skipped_page_count = skipped_page_count
        
        if self.log_performance:
            if chip_erase:
                LOG.info("Erased chip, programmed %d bytes (%s), skipped %d bytes (%s) at %.02f kB/s",
                    actual_program_byte_count, get_page_count(actual_program_page_count),
                    skipped_byte_count, get_page_count(skipped_page_count),
                    ((self.program_byte_count/1024) / self.perf.program_time))
            else:
                LOG.info("Erased %d bytes (%s), programmed %d bytes (%s), skipped %d bytes (%s) at %.02f kB/s", 
                    erase_byte_count, get_sector_count(erase_sector_count),
                    actual_program_byte_count, get_page_count(actual_program_page_count),
                    skipped_byte_count, get_page_count(skipped_page_count),
                    ((self.program_byte_count/1024) / self.perf.program_time))

        # Send notification that we're done programming flash.
        self.flash.target.session.notify(Target.Event.POST_FLASH_PROGRAM, self)

        return self.perf

    def get_performance(self):
        return self.perf

    def _mark_all_pages_for_programming(self):
        for sector in self.sector_list:
            sector.erased = False
            for page in sector.page_list:
                sector.erased = False
                page.same = False

    def _compute_chip_erase_pages_and_weight(self):
        """! @brief Compute the number of erased pages.

        Determine how many pages in the new data are already erased.
        """
        chip_erase_count = 0
        chip_erase_weight = 0
        chip_erase_weight += self.flash.get_flash_info().erase_weight
        for page in self.page_list:
            if page.erased is None:
                page.erased = self.flash.region.is_data_erased(page.data)
            if not page.erased:
                chip_erase_count += 1
                chip_erase_weight += page.get_program_weight()
        self.chip_erase_count = chip_erase_count
        self.chip_erase_weight = chip_erase_weight
        return chip_erase_count, chip_erase_weight

    def _compute_sector_erase_pages_weight_min(self):
        return sum(page.get_verify_weight() for page in self.page_list)

    def _analyze_pages_with_partial_read(self):
        """! @brief Estimate how many pages are the same by reading data.

        Pages are analyzed by reading the first 32 bytes and comparing with data to be
        programmed.
        """
        # Quickly estimate how many pages are the same as current flash contents.
        # Init the flash algo in case it is required in order to access the flash memory.
        self._enable_read_access()
        for page in self.page_list:
            # Analyze pages that haven't been analyzed yet
            if page.same is None:
                size = min(PAGE_ESTIMATE_SIZE, len(page.data))
                data = self.flash.target.read_memory_block8(page.addr, size)
                page_same = same(data, page.data[0:size])
                if page_same is False:
                    page.same = False
                else:
                    # Save the data read for estimation so we don't need to read it again.
                    page.cached_estimate_data = data
        
    def _analyze_pages_with_crc32(self, assume_estimate_correct=False):
        """! @brief Estimate how many pages are the same using a CRC32 analyzer.

        A CRC32 analyzer program is loaded into target RAM and is passed an array of pages
        and sizes. When executed, it computes the CRC32 for every page.

        @param self
        @param assume_estimate_correct If set to True, then pages with matching CRCs will
            be marked as the same.  There is a small chance that the CRCs match even though the
            data is different, but the odds of this happing are low: ~1/(2^32) = ~2.33*10^-8%.
        """
        # Build list of all the pages that need to be analyzed
        sector_list = []
        page_list = []
        for page in self.page_list:
            if page.same is None:
                # Add page to compute_crcs
                sector_list.append((page.addr, page.size))
                page_list.append(page)
                # Compute CRC of data (Padded with 0xFF)
                data = list(page.data)
                pad_size = page.size - len(page.data)
                if pad_size > 0:
                    data.extend([0xFF] * pad_size)
                page.crc = crc32(bytearray(data)) & 0xFFFFFFFF

        # Analyze pages
        if len(page_list) > 0:
            self._enable_read_access()
            crc_list = self.flash.compute_crcs(sector_list)
            for page, crc in zip(page_list, crc_list):
                page_same = page.crc == crc
                if assume_estimate_correct:
                    page.same = page_same
                elif page_same is False:
                    page.same = False

    def _compute_sector_erase_pages_and_weight(self, fast_verify):
        """! @brief Quickly analyze flash contents and compute weights for sector erase.

        Quickly estimate how many pages are the same.  These estimates are used
        by _sector_erase_program so it is recommended to call this before beginning programming
        This is done automatically by smart_program.
        """
        analyze_start = time()
        
        # Analyze unknown pages using either CRC32 analyzer or partial reads.
        if any(page.same is None for page in self.page_list):
            if self.flash.get_flash_info().crc_supported:
                self._analyze_pages_with_crc32(fast_verify)
                self.perf.analyze_type = FlashBuilder.FLASH_ANALYSIS_CRC32
            elif self.flash.region.is_readable:
                self._analyze_pages_with_partial_read()
                self.perf.analyze_type = FlashBuilder.FLASH_ANALYSIS_PARTIAL_PAGE_READ
            else:
                # The CRC analyzer isn't supported and flash isn't directly readable, so
                # just mark all pages as needing programming. This will also prevent
                # _scan_pages_for_same() from trying to read flash.
                self._mark_all_pages_for_programming()

        # Put together page and time estimate.
        sector_erase_count = 0
        sector_erase_weight = 0
        for sector in self.sector_list:
            for page in sector.page_list:
                if page.same is False:
                    sector_erase_count += 1
                    sector_erase_weight += page.get_program_weight()
                elif page.same is None:
                    # Page may be the same but must be read to confirm
                    sector_erase_weight += page.get_verify_weight()
                elif page.same is True:
                    # Page is confirmed to be the same so no programming weight
                    pass
            
            if sector.are_any_pages_not_same():
                sector_erase_weight += sector.erase_weight

        self.sector_erase_count = sector_erase_count
        self.sector_erase_weight = sector_erase_weight

        analyze_finish = time()
        self.perf.analyze_time = analyze_finish - analyze_start
        LOG.debug("Analyze time: %f" % (analyze_finish - analyze_start))
        
        return sector_erase_count, sector_erase_weight

    def _chip_erase_program(self, progress_cb=_stub_progress):
        """! @brief Program by first performing an erase all."""
        LOG.debug("%i of %i pages have erased data", len(self.page_list) - self.chip_erase_count, len(self.page_list))
        progress_cb(0.0)
        progress = 0

        self.flash.init(self.flash.Operation.ERASE)
        self.flash.erase_all()
        self.flash.uninit()
        
        progress += self.flash.get_flash_info().erase_weight
        progress_cb(float(progress) / float(self.chip_erase_weight))
        
        self.flash.init(self.flash.Operation.PROGRAM)
        for page in self.page_list:
            if not page.erased:
                self.flash.program_page(page.addr, page.data)
                progress += page.get_program_weight()
                progress_cb(float(progress) / float(self.chip_erase_weight))
        self.flash.uninit()
        progress_cb(1.0)
        return FlashBuilder.FLASH_CHIP_ERASE

    def _next_unerased_page(self, i):
        if i >= len(self.page_list):
            return None, i
        page = self.page_list[i]
        while page.erased:
            i += 1
            if i >= len(self.page_list):
                return None, i
            page = self.page_list[i]
        return page, i + 1

    def _chip_erase_program_double_buffer(self, progress_cb=_stub_progress):
        """! @brief Double-buffered program by first performing an erase all."""
        LOG.debug("%i of %i pages have erased data", len(self.page_list) - self.chip_erase_count, len(self.page_list))
        progress_cb(0.0)
        progress = 0

        self.flash.init(self.flash.Operation.ERASE)
        self.flash.erase_all()
        self.flash.uninit()
        
        progress += self.flash.get_flash_info().erase_weight
        progress_cb(float(progress) / float(self.chip_erase_weight))

        # Set up page and buffer info.
        current_buf = 0
        next_buf = 1
        page, i = self._next_unerased_page(0)
        assert page is not None

        # Load first page buffer
        self.flash.load_page_buffer(current_buf, page.addr, page.data)

        self.flash.init(self.flash.Operation.PROGRAM)
        while page is not None:
            # Kick off this page program.
            current_addr = page.addr
            current_weight = page.get_program_weight()
            self.flash.start_program_page_with_buffer(current_buf, current_addr)

            # Get next page and load it.
            page, i = self._next_unerased_page(i)
            if page is not None:
                self.flash.load_page_buffer(next_buf, page.addr, page.data)

            # Wait for the program to complete.
            result = self.flash.wait_for_completion()
            if result != 0:
                raise FlashProgramFailure('program_page(0x%x) error: %i'
                        % (current_addr, result), current_addr, result)

            # Swap buffers.
            current_buf, next_buf = next_buf, current_buf

            # Update progress.
            progress += current_weight
            progress_cb(float(progress) / float(self.chip_erase_weight))
        
        self.flash.uninit()
        progress_cb(1.0)
        return FlashBuilder.FLASH_CHIP_ERASE

    def _sector_erase_program(self, progress_cb=_stub_progress):
        """! @brief Program by performing sector erases."""
        actual_sector_erase_count = 0
        actual_sector_erase_weight = 0
        progress = 0

        progress_cb(0.0)

        # Fill in same flag for all pages. This is done up front so we're not trying
        # to read from flash while simultaneously programming it.
        progress = self._scan_pages_for_same(progress_cb)
        
        for sector in self.sector_list:
            if sector.are_any_pages_not_same():
                # Erase the sector
                self.flash.init(self.flash.Operation.ERASE)
                self.flash.erase_sector(sector.addr)
                self.flash.uninit()

                actual_sector_erase_weight += sector.erase_weight

                # Update progress
                if self.sector_erase_weight > 0:
                    progress_cb(float(progress) / float(self.sector_erase_weight))
                
                # The sector was erased, so we must program all pages in the sector
                # regardless of whether they were the same or not.
                for page in sector.page_list:

                    progress += page.get_program_weight()

                    self.flash.init(self.flash.Operation.PROGRAM)
                    self.flash.program_page(page.addr, page.data)
                    self.flash.uninit()
            
                    actual_sector_erase_count += 1
                    actual_sector_erase_weight += page.get_program_weight()

                    # Update progress
                    if self.sector_erase_weight > 0:
                        progress_cb(float(progress) / float(self.sector_erase_weight))

        progress_cb(1.0)

        LOG.debug("Estimated sector erase programmed page count: %i", self.sector_erase_count)
        LOG.debug("Actual sector erase programmed page count: %i", actual_sector_erase_count)

        return FlashBuilder.FLASH_SECTOR_ERASE

    def _scan_pages_for_same(self, progress_cb=_stub_progress):
        """! @brief Read the full page data to determine if it is unchanged.
        
        When this function exits, the same flag will be set to either True or False for
        every page. In addition, sectors that need at least one page programmed will have
        the same flag set to False for all pages within that sector.
        """
        progress = 0
        
        # Read page data if unknown - after this page.same will be True or False
        unknown_pages = [page for page in self.page_list if page.same is None]
        if unknown_pages:
            self._enable_read_access()

            for page in unknown_pages:
                if page.cached_estimate_data is not None:
                    data = page.cached_estimate_data
                    offset = len(data)
                else:
                    data = []
                    offset = 0
                assert len(page.data) == page.size, "page data size (%d) != page size (%d)" % (len(page.data), page.size)
                data.extend(self.flash.target.read_memory_block8(page.addr + offset,
                                                                    page.size - offset))
                page.same = same(page.data, data)
                page.cached_estimate_data = None # This data isn't needed anymore.
                progress += page.get_verify_weight()
            
                # Update progress
                if self.sector_erase_weight > 0:
                    progress_cb(float(progress) / float(self.sector_erase_weight))
        
        # If we have to program any pages of a sector, then mark all pages of that sector
        # as needing to be programmed, since the sector will be erased.
        for sector in self.sector_list:
            if sector.are_any_pages_not_same():
                sector.mark_all_pages_not_same()
        
        return progress

    def _next_nonsame_page(self, i):
        if i >= len(self.page_list):
            return None, i
        page = self.page_list[i]
        while page.same:
            i += 1
            if i >= len(self.page_list):
                return None, i
            page = self.page_list[i]
        return page, i + 1

    def _sector_erase_program_double_buffer(self, progress_cb=_stub_progress):
        """! @brief Double-buffered program by performing sector erases."""
        actual_sector_erase_count = 0
        actual_sector_erase_weight = 0
        progress = 0

        progress_cb(0.0)

        # Fill in same flag for all pages. This is done up front so we're not trying
        # to read from flash while simultaneously programming it.
        progress = self._scan_pages_for_same(progress_cb)

        # Erase all sectors up front.
        self.flash.init(self.flash.Operation.ERASE)
        for sector in self.sector_list:
            if sector.are_any_pages_not_same():
                # Erase the sector
                self.flash.erase_sector(sector.addr)
                
                # Update progress
                progress += sector.erase_weight
                if self.sector_erase_weight > 0:
                    progress_cb(float(progress) / float(self.sector_erase_weight))
        self.flash.uninit()

        # Set up page and buffer info.
        current_buf = 0
        next_buf = 1
        page, i = self._next_nonsame_page(0)

        # Make sure there are actually pages to program differently from current flash contents.
        if page is not None:
            self.flash.init(self.flash.Operation.PROGRAM)

            # Load first page buffer
            self.flash.load_page_buffer(current_buf, page.addr, page.data)

            while page is not None:
                assert page.same is not None

                # Kick off this page program.
                current_addr = page.addr
                current_weight = page.get_program_weight()

                self.flash.start_program_page_with_buffer(current_buf, current_addr)
                
                actual_sector_erase_count += 1
                actual_sector_erase_weight += page.get_program_weight()

                # Get next page and load it.
                page, i = self._next_nonsame_page(i)
                if page is not None:
                    self.flash.load_page_buffer(next_buf, page.addr, page.data)

                # Wait for the program to complete.
                result = self.flash.wait_for_completion()
                if result != 0:
                    raise FlashProgramFailure('program_page(0x%x) error: %i'
                            % (current_addr, result), current_addr, result)
                
                # Swap buffers.
                current_buf, next_buf = next_buf, current_buf

                # Update progress
                progress += current_weight
                if self.sector_erase_weight > 0:
                    progress_cb(float(progress) / float(self.sector_erase_weight))

            self.flash.uninit()

        progress_cb(1.0)

        LOG.debug("Estimated sector erase programmed page count: %i", self.sector_erase_count)
        LOG.debug("Actual sector erase programmed page count: %i", actual_sector_erase_count)

        return FlashBuilder.FLASH_SECTOR_ERASE
