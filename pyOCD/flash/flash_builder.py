"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from ..core.target import Target
from ..utility.notification import Notification
import logging
from struct import unpack
from time import time
from binascii import crc32

# Number of bytes in a page to read to quickly determine if the page has the same data
PAGE_ESTIMATE_SIZE = 32
PAGE_READ_WEIGHT = 0.3
DATA_TRANSFER_B_PER_S = 40 * 1000 # ~40KB/s, depends on clock speed, theoretical limit for HID is 56,000 B/s

## @brief Exception raised when flashing fails outright. 
class FlashFailure(RuntimeError):
    pass

class ProgrammingInfo(object):
    def __init__(self):
        self.program_type = None                # Type of programming performed - FLASH_PAGE_ERASE or FLASH_CHIP_ERASE
        self.program_time = None                # Total programming time
        self.analyze_type = None                # Type of flash analysis performed - FLASH_ANALYSIS_CRC32 or FLASH_ANALYSIS_PARTIAL_PAGE_READ
        self.analyze_time = None                # Time to analyze flash contents

def _same(d1, d2):
    assert len(d1) == len(d2)
    for i in range(len(d1)):
        if d1[i] != d2[i]:
            return False
    return True

def _erased(d):
    for i in range(len(d)):
        if d[i] != 0xFF:
            return False
    return True

def _stub_progress(percent):
    pass

class flash_page(object):
    def __init__(self, addr, size, data, erase_weight, program_weight):
        self.addr = addr
        self.size = size
        self.data = data
        self.erase_weight = erase_weight
        self.program_weight = program_weight
        self.erased = None
        self.same = None

    def getProgramWeight(self):
        """
        Get time to program a page including the data transfer
        """
        return self.program_weight + \
            float(len(self.data)) / float(DATA_TRANSFER_B_PER_S)

    def getEraseProgramWeight(self):
        """
        Get time to erase and program a page including data transfer time
        """
        return self.erase_weight + self.program_weight + \
            float(len(self.data)) / float(DATA_TRANSFER_B_PER_S)

    def getVerifyWeight(self):
        """
        Get time to verify a page
        """
        return float(self.size) / float(DATA_TRANSFER_B_PER_S)

class flash_operation(object):
    def __init__(self, addr, data):
        self.addr = addr
        self.data = data

class FlashBuilder(object):

    # Type of flash operation
    FLASH_PAGE_ERASE = 1
    FLASH_CHIP_ERASE = 2

    # Type of flash analysis
    FLASH_ANALYSIS_CRC32 = "CRC32"
    FLASH_ANALYSIS_PARTIAL_PAGE_READ = "PAGE_READ"

    def __init__(self, flash, base_addr=0):
        self.flash = flash
        self.flash_start = base_addr
        self.flash_operation_list = []
        self.page_list = []
        self.perf = ProgrammingInfo()
        self.enable_double_buffering = True
        self.max_errors = 10

    def enableDoubleBuffer(self, enable):
        self.enable_double_buffering = enable

    def setMaxErrors(self, count):
        self.max_errors = count

    def addData(self, addr, data):
        """
        Add a block of data to be programmed

        Note - programming does not start until the method
        program is called.
        """
        # Sanity check
        if addr < self.flash_start:
            raise Exception("Invalid flash address 0x%x is before flash start 0x%x" % (addr, self.flash_start))

        # Add operation to list
        self.flash_operation_list.append(flash_operation(addr, data))

        # Keep list sorted
        self.flash_operation_list = sorted(self.flash_operation_list, key=lambda operation: operation.addr)
        # Verify this does not overlap
        prev_flash_operation = None
        for operation in self.flash_operation_list:
            if prev_flash_operation != None:
                if prev_flash_operation.addr + len(prev_flash_operation.data) > operation.addr:
                    raise ValueError("Error adding data - Data at 0x%x..0x%x overlaps with 0x%x..0x%x"
                            % (prev_flash_operation.addr, prev_flash_operation.addr + len(prev_flash_operation.data),
                               operation.addr, operation.addr + len(operation.data)))
            prev_flash_operation = operation

    def program(self, chip_erase=None, progress_cb=None, smart_flash=True, fast_verify=False):
        """
        Determine fastest method of flashing and then run flash programming.

        Data must have already been added with addData
        """

        # Send notification that we're about to program flash.
        self.flash.target.notify(Notification(event=Target.EVENT_PRE_FLASH_PROGRAM, source=self))

        # Assumptions
        # 1. Page erases must be on page boundaries ( page_erase_addr % page_size == 0 )
        # 2. Page erase can have a different size depending on location
        # 3. It is safe to program a page with less than a page of data

        # Examples
        # - lpc4330     -Non 0 base address
        # - nRF51       -UICR location far from flash (address 0x10001000)
        # - LPC1768     -Different sized pages
        program_start = time()

        if progress_cb is None:
            progress_cb = _stub_progress

        # There must be at least 1 flash operation
        if len(self.flash_operation_list) == 0:
            logging.warning("No pages were programmed")
            return

        # Convert the list of flash operations into flash pages
        program_byte_count = 0
        flash_addr = self.flash_operation_list[0].addr
        info = self.flash.getPageInfo(flash_addr)
        if info is None:
            raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % flash_addr)
        page_addr = flash_addr - (flash_addr % info.size)
        current_page = flash_page(page_addr, info.size, [], info.erase_weight, info.program_weight)
        self.page_list.append(current_page)
        for flash_operation in self.flash_operation_list:
            pos = 0
            while pos < len(flash_operation.data):

                # Check if operation is in next page
                flash_addr = flash_operation.addr + pos
                if flash_addr >= current_page.addr + current_page.size:
                    info = self.flash.getPageInfo(flash_addr)
                    if info is None:
                        raise FlashFailure("Attempt to program flash at invalid address 0x%08x" % flash_addr)
                    page_addr = flash_addr - (flash_addr % info.size)
                    current_page = flash_page(page_addr, info.size, [], info.erase_weight, info.program_weight)
                    self.page_list.append(current_page)

                # Fill the page gap if there is one
                page_data_end = current_page.addr + len(current_page.data)
                if flash_addr != page_data_end:
                    old_data = self.flash.target.readBlockMemoryUnaligned8(page_data_end, flash_addr - page_data_end)
                    current_page.data.extend(old_data)

                # Copy data to page and increment pos
                space_left_in_page = info.size - len(current_page.data)
                space_left_in_data = len(flash_operation.data) - pos
                amount = min(space_left_in_page, space_left_in_data)
                current_page.data.extend(flash_operation.data[pos:pos + amount])
                program_byte_count += amount

                #increment position
                pos += amount

        # If smart flash was set to false then mark all pages
        # as requiring programming
        if not smart_flash:
            self._mark_all_pages_for_programming()

        # If the first page being programmed is not the first page
        # in ROM then don't use a chip erase
        if self.page_list[0].addr > self.flash_start:
            if chip_erase is None:
                chip_erase = False
            elif chip_erase is True:
                logging.warning('Chip erase used when flash address 0x%x is not the same as flash start 0x%x', self.page_list[0].addr, self.flash_start)

        self.flash.init()

        chip_erase_count, chip_erase_program_time = self._compute_chip_erase_pages_and_weight()
        page_erase_min_program_time = self._compute_page_erase_pages_weight_min()

        # If chip_erase hasn't been specified determine if chip erase is faster
        # than page erase regardless of contents
        if (chip_erase is None) and (chip_erase_program_time < page_erase_min_program_time):
            chip_erase = True

        # If chip erase isn't True then analyze the flash
        if chip_erase != True:
            analyze_start = time()
            if self.flash.getFlashInfo().crc_supported:
                sector_erase_count, page_program_time = self._compute_page_erase_pages_and_weight_crc32(fast_verify)
                self.perf.analyze_type = FlashBuilder.FLASH_ANALYSIS_CRC32
            else:
                sector_erase_count, page_program_time = self._compute_page_erase_pages_and_weight_sector_read()
                self.perf.analyze_type = FlashBuilder.FLASH_ANALYSIS_PARTIAL_PAGE_READ
            analyze_finish = time()
            self.perf.analyze_time = analyze_finish - analyze_start
            logging.debug("Analyze time: %f" % (analyze_finish - analyze_start))

        # If chip erase hasn't been set then determine fastest method to program
        if chip_erase is None:
            logging.debug("Chip erase count %i, Page erase est count %i" % (chip_erase_count, sector_erase_count))
            logging.debug("Chip erase weight %f, Page erase weight %f" % (chip_erase_program_time, page_program_time))
            chip_erase = chip_erase_program_time < page_program_time

        if chip_erase:
            if self.flash.isDoubleBufferingSupported() and self.enable_double_buffering:
                logging.debug("Using double buffer chip erase program")
                flash_operation = self._chip_erase_program_double_buffer(progress_cb)
            else:
                flash_operation = self._chip_erase_program(progress_cb)
        else:
            if self.flash.isDoubleBufferingSupported() and self.enable_double_buffering:
                logging.debug("Using double buffer page erase program")
                flash_operation = self._page_erase_program_double_buffer(progress_cb)
            else:
                flash_operation = self._page_erase_program(progress_cb)

        self.flash.target.resetStopOnReset()

        program_finish = time()
        self.perf.program_time = program_finish - program_start
        self.perf.program_type = flash_operation

        logging.info("Programmed %d bytes (%d pages) at %.02f kB/s", program_byte_count, len(self.page_list), ((program_byte_count/1024) / self.perf.program_time))

        # Send notification that we're done programming flash.
        self.flash.target.notify(Notification(event=Target.EVENT_POST_FLASH_PROGRAM, source=self))

        return self.perf

    def getPerformance(self):
        return self.perf

    def _mark_all_pages_for_programming(self):
        for page in self.page_list:
            page.erased = False
            page.same = False

    def _compute_chip_erase_pages_and_weight(self):
        """
        Compute the number of erased pages.

        Determine how many pages in the new data are already erased.
        """
        chip_erase_count = 0
        chip_erase_weight = 0
        chip_erase_weight += self.flash.getFlashInfo().erase_weight
        for page in self.page_list:
            if page.erased is None:
                page.erased = _erased(page.data)
            if not page.erased:
                chip_erase_count += 1
                chip_erase_weight += page.getProgramWeight()
        self.chip_erase_count = chip_erase_count
        self.chip_erase_weight = chip_erase_weight
        return chip_erase_count, chip_erase_weight

    def _compute_page_erase_pages_weight_min(self):
        page_erase_min_weight = 0
        for page in self.page_list:
            page_erase_min_weight += page.getVerifyWeight()
        return page_erase_min_weight

    def _compute_page_erase_pages_and_weight_sector_read(self):
        """
        Estimate how many pages are the same.

        Quickly estimate how many pages are the same.  These estimates are used
        by page_erase_program so it is recommended to call this before beginning programming
        This is done automatically by smart_program.
        """
        # Quickly estimate how many pages are the same
        page_erase_count = 0
        page_erase_weight = 0
        for page in self.page_list:
            # Analyze pages that haven't been analyzed yet
            if page.same is None:
                size = min(PAGE_ESTIMATE_SIZE, len(page.data))
                data = self.flash.target.readBlockMemoryUnaligned8(page.addr, size)
                page_same = _same(data, page.data[0:size])
                if page_same is False:
                    page.same = False

        # Put together page and time estimate
        for page in self.page_list:
            if page.same is False:
                page_erase_count += 1
                page_erase_weight += page.getEraseProgramWeight()
            elif page.same is None:
                # Page is probably the same but must be read to confirm
                page_erase_weight += page.getVerifyWeight()
            elif page.same is True:
                # Page is confirmed to be the same so no programming weight
                pass

        self.page_erase_count = page_erase_count
        self.page_erase_weight = page_erase_weight
        return page_erase_count, page_erase_weight

    def _compute_page_erase_pages_and_weight_crc32(self, assume_estimate_correct=False):
        """
        Estimate how many pages are the same.

        Quickly estimate how many pages are the same.  These estimates are used
        by page_erase_program so it is recommended to call this before beginning programming
        This is done automatically by smart_program.

        If assume_estimate_correct is set to True, then pages with matching CRCs
        will be marked as the same.  There is a small chance that the CRCs match even though the
        data is different, but the odds of this happing are low: ~1/(2^32) = ~2.33*10^-8%.
        """
        # Build list of all the pages that need to be analyzed
        sector_list = []
        page_list = []
        for page in self.page_list:
            if page.same is None:
                # Add sector to computeCrcs
                sector_list.append((page.addr, page.size))
                page_list.append(page)
                # Compute CRC of data (Padded with 0xFF)
                data = list(page.data)
                pad_size = page.size - len(page.data)
                if pad_size > 0:
                    data.extend([0xFF] * pad_size)
                page.crc = crc32(bytearray(data)) & 0xFFFFFFFF

        # Analyze pages
        page_erase_count = 0
        page_erase_weight = 0
        if len(page_list) > 0:
            crc_list = self.flash.computeCrcs(sector_list)
            for page, crc in zip(page_list, crc_list):
                page_same = page.crc == crc
                if assume_estimate_correct:
                    page.same = page_same
                elif page_same is False:
                    page.same = False

        # Put together page and time estimate
        for page in self.page_list:
            if page.same is False:
                page_erase_count += 1
                page_erase_weight += page.getEraseProgramWeight()
            elif page.same is None:
                # Page is probably the same but must be read to confirm
                page_erase_weight += page.getVerifyWeight()
            elif page.same is True:
                # Page is confirmed to be the same so no programming weight
                pass

        self.page_erase_count = page_erase_count
        self.page_erase_weight = page_erase_weight
        return page_erase_count, page_erase_weight

    def _chip_erase_program(self, progress_cb=_stub_progress):
        """
        Program by first performing a chip erase.
        """
        logging.debug("Smart chip erase")
        logging.debug("%i of %i pages already erased", len(self.page_list) - self.chip_erase_count, len(self.page_list))
        progress_cb(0.0)
        progress = 0
        self.flash.eraseAll()
        progress += self.flash.getFlashInfo().erase_weight
        for page in self.page_list:
            if not page.erased:
                self.flash.programPage(page.addr, page.data)
                progress += page.getProgramWeight()
                progress_cb(float(progress) / float(self.chip_erase_weight))
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
        """
        Program by first performing a chip erase.
        """
        logging.debug("Smart chip erase")
        logging.debug("%i of %i pages already erased", len(self.page_list) - self.chip_erase_count, len(self.page_list))
        progress_cb(0.0)
        progress = 0
        self.flash.eraseAll()
        progress += self.flash.getFlashInfo().erase_weight

        # Set up page and buffer info.
        error_count = 0
        current_buf = 0
        next_buf = 1
        page, i = self._next_unerased_page(0)
        assert page is not None

        # Load first page buffer
        self.flash.loadPageBuffer(current_buf, page.addr, page.data)

        while page is not None:
            # Kick off this page program.
            current_addr = page.addr
            current_weight = page.getProgramWeight()
            self.flash.startProgramPageWithBuffer(current_buf, current_addr)

            # Get next page and load it.
            page, i = self._next_unerased_page(i)
            if page is not None:
                self.flash.loadPageBuffer(next_buf, page.addr, page.data)

            # Wait for the program to complete.
            result = self.flash.waitForCompletion()

            # check the return code
            if result != 0:
                logging.error('programPage(0x%x) error: %i', current_addr, result)
                error_count += 1
                if error_count > self.max_errors:
                    logging.error("Too many page programming errors, aborting program operation")
                    break

            # Swap buffers.
            temp = current_buf
            current_buf = next_buf
            next_buf = temp

            # Update progress.
            progress += current_weight
            progress_cb(float(progress) / float(self.chip_erase_weight))

        progress_cb(1.0)
        return FlashBuilder.FLASH_CHIP_ERASE

    def _page_erase_program(self, progress_cb=_stub_progress):
        """
        Program by performing sector erases.
        """
        actual_page_erase_count = 0
        actual_page_erase_weight = 0
        progress = 0

        progress_cb(0.0)

        for page in self.page_list:

            # If the page is not the same
            if page.same is False:
                progress += page.getEraseProgramWeight()

            # Read page data if unknown - after this page.same will be True or False
            if page.same is None:
                data = self.flash.target.readBlockMemoryUnaligned8(page.addr, len(page.data))
                page.same = _same(page.data, data)
                progress += page.getVerifyWeight()

            # Program page if not the same
            if page.same is False:
                self.flash.erasePage(page.addr)
                self.flash.programPage(page.addr, page.data)
                actual_page_erase_count += 1
                actual_page_erase_weight += page.getEraseProgramWeight()

            # Update progress
            if self.page_erase_weight > 0:
                progress_cb(float(progress) / float(self.page_erase_weight))

        progress_cb(1.0)

        logging.debug("Estimated page erase count: %i", self.page_erase_count)
        logging.debug("Actual page erase count: %i", actual_page_erase_count)

        return FlashBuilder.FLASH_PAGE_ERASE

    def _scan_pages_for_same(self, progress_cb=_stub_progress):
        """
        Program by performing sector erases.
        """
        progress = 0
        count = 0
        same_count = 0

        for page in self.page_list:
            # Read page data if unknown - after this page.same will be True or False
            if page.same is None:
                data = self.flash.target.readBlockMemoryUnaligned8(page.addr, len(page.data))
                page.same = _same(page.data, data)
                progress += page.getVerifyWeight()
                count += 1
                if page.same:
                    same_count += 1

                # Update progress
                progress_cb(float(progress) / float(self.page_erase_weight))
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

    def _page_erase_program_double_buffer(self, progress_cb=_stub_progress):
        """
        Program by performing sector erases.
        """
        actual_page_erase_count = 0
        actual_page_erase_weight = 0
        progress = 0

        progress_cb(0.0)

        # Fill in same flag for all pages. This is done up front so we're not trying
        # to read from flash while simultaneously programming it.
        progress = self._scan_pages_for_same(progress_cb)

        # Set up page and buffer info.
        error_count = 0
        current_buf = 0
        next_buf = 1
        page, i = self._next_nonsame_page(0)

        # Make sure there are actually pages to program differently from current flash contents.
        if page is not None:
            # Load first page buffer
            self.flash.loadPageBuffer(current_buf, page.addr, page.data)

            while page is not None:
                assert page.same is not None

                # Kick off this page program.
                current_addr = page.addr
                current_weight = page.getEraseProgramWeight()
                self.flash.erasePage(current_addr)
                self.flash.startProgramPageWithBuffer(current_buf, current_addr) #, erase_page=True)
                actual_page_erase_count += 1
                actual_page_erase_weight += page.getEraseProgramWeight()

                # Get next page and load it.
                page, i = self._next_nonsame_page(i)
                if page is not None:
                    self.flash.loadPageBuffer(next_buf, page.addr, page.data)

                # Wait for the program to complete.
                result = self.flash.waitForCompletion()

                # check the return code
                if result != 0:
                    logging.error('programPage(0x%x) error: %i', current_addr, result)
                    error_count += 1
                    if error_count > self.max_errors:
                        logging.error("Too many page programming errors, aborting program operation")
                        break

                # Swap buffers.
                temp = current_buf
                current_buf = next_buf
                next_buf = temp

                # Update progress
                progress += current_weight
                if self.page_erase_weight > 0:
                    progress_cb(float(progress) / float(self.page_erase_weight))

        progress_cb(1.0)

        logging.debug("Estimated page erase count: %i", self.page_erase_count)
        logging.debug("Actual page erase count: %i", actual_page_erase_count)

        return FlashBuilder.FLASH_PAGE_ERASE
