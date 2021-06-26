# pyOCD debugger
# Copyright (c) 2013-2020 Arm Limited
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
from enum import Enum

from ..core.target import Target
from ..core.exceptions import (FlashFailure, FlashEraseFailure, FlashProgramFailure)
from ..utility.mask import msb
from .builder import FlashBuilder

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

# Program to compute the CRC of sectors.  This works on cortex-m processors.
# Code is relocatable and only needs to be on a 4 byte boundary.
# 200 bytes of executable data below + 1024 byte crc table = 1224 bytes
# Usage requirements:
# -In memory reserve 0x600 for code & table
# -Make sure data buffer is big enough to hold 4 bytes for each page that could be checked (ie.  >= num pages * 4)
analyzer = (
    0x2780b5f0, 0x25004684, 0x4e2b2401, 0x447e4a2b, 0x0023007f, 0x425b402b, 0x40130868, 0x08584043,
    0x425b4023, 0x40584013, 0x40200843, 0x40104240, 0x08434058, 0x42404020, 0x40584010, 0x40200843,
    0x40104240, 0x08434058, 0x42404020, 0x40584010, 0x40200843, 0x40104240, 0x08584043, 0x425b4023,
    0x40434013, 0xc6083501, 0xd1d242bd, 0xd01f2900, 0x46602301, 0x469c25ff, 0x00894e11, 0x447e1841,
    0x88034667, 0x409f8844, 0x2f00409c, 0x2201d012, 0x4252193f, 0x34017823, 0x402b4053, 0x599b009b,
    0x405a0a12, 0xd1f542bc, 0xc00443d2, 0xd1e74281, 0xbdf02000, 0xe7f82200, 0x000000b2, 0xedb88320,
    0x00000042, 
    )

class SectorInfo(object):
    """! @brief Info about an erase sector."""

    def __init__(self):
        self.base_addr = None           # Start address of this sector
        self.erase_weight = None        # Time it takes to erase a page
        self.size = None                # Size of sector

    def __repr__(self):
        return "<SectorInfo@0x%x base=0x%x size=0x%x erswt=%g>" \
            % (id(self), self.base_addr, self.size, self.erase_weight)

class PageInfo(object):
    """! @brief Info about a program page."""

    def __init__(self):
        self.base_addr = None           # Start address of this page
        self.program_weight = None      # Time it takes to program a page (Not including data transfer time)
        self.size = None                # Size of page

    def __repr__(self):
        return "<PageInfo@0x%x base=0x%x size=0x%x prgwt=%g>" \
            % (id(self), self.base_addr, self.size, self.program_weight)

class FlashInfo(object):
    """! @brief Info about the entire flash region."""

    def __init__(self):
        self.rom_start = None           # Starting address of ROM
        self.erase_weight = None        # Time it takes to perform an erase all
        self.crc_supported = None       # Is the function compute_crcs supported?

    def __repr__(self):
        return "<FlashInfo@0x%x start=0x%x erswt=%g crc=%s>" \
            % (id(self), self.rom_start, self.erase_weight, self.crc_supported)

class Flash(object):
    """!
    @brief Low-level control of flash programming algorithms.
    
    Instances of this class are bound to a flash memory region
    (@ref pyocd.core.memory_map.FlashRegion "FlashRegion") and support
    programming only within that region's address range. To program images that cross flash
    memory region boundaries, use the @ref pyocd.flash.loader.FlashLoader "FlashLoader" or
    @ref pyocd.flash.file_programmer.FileProgrammer "FileProgrammer" classes.
    
    Terminology:
    - sector: The size of an erasable block.
    - page: The size of a nominal programming block. Often flash can be programmed in much smaller
        increments (phrases). In that case, the page size determines the data buffers and the size
        passed to the ProgramPage() flash algo API. Pages must be the same size or smaller than
        sectors.
    - phrase: The minimum programming granularity, often from 1-16 bytes. For some flash
        technologies, the is no distinction between a phrase and a page.
    
    The `flash_algo` parameter of the constructor is a dictionary that defines all the details
    of the flash algorithm. The keys of this dictionary are as follows.
    - `load_address`: Memory address where the flash algo instructions will be loaded.
    - `instructions`: List of 32-bit words containing the position-independant code for the algo.
    - `pc_init`: Address of the `Init()` entry point. Optional.
    - `pc_eraseAll`: Address of the `EraseAll()` entry point. Optional.
    - `pc_erase_sector`: Address of the `EraseSector()` entry point.
    - `pc_program_page`: Address of the `ProgramPage()` entry point.
    - `pc_unInit`: Address of the `UnInit()` entry point. Optional.
    - `begin_data`: Base address of the page buffer. Used if `page_buffers` is not provided.
    - `page_buffers`: An optional list of base addresses for page buffers. The buffers must be at
        least as large as the region's page_size attribute. If at least 2 buffers are included in
        the list, then double buffered programming will be enabled.
    - `begin_stack`: Initial value of the stack pointer when calling any flash algo API.
    - `static_base`: Initial value of the R9 register for calling flash algo entry points, which
        determines where the position-independant data resides.
    - `analyzer_supported`: Whether the CRC32-based analyzer is supported.
    - `analyzer_address`: RAM base address where the analyzer code will be placed. There must be at
        least 0x600 free bytes after this address.
    
    All of the "pc_" entry point key values must have bit 0 set to indicate a Thumb function.
    """
    class Operation(Enum):
        """! @brief Operations passed to init(). """
        ## Erase all or sector erase.
        ERASE = 1
        ## Program page or phrase.
        PROGRAM = 2
        ## Currently unused, but defined as part of the flash algorithm specification.
        VERIFY = 3

    def __init__(self, target, flash_algo):
        self.target = target
        self.flash_algo = flash_algo
        self.flash_algo_debug = False
        self._region = None
        self._did_prepare_target = False
        self._active_operation = None
        if flash_algo is not None:
            self.is_valid = True
            self.use_analyzer = flash_algo['analyzer_supported']
            self.end_flash_algo = flash_algo['load_address'] + len(flash_algo['instructions']) * 4
            self.begin_stack = flash_algo['begin_stack']
            self.begin_data = flash_algo['begin_data']
            self.static_base = flash_algo['static_base']
            self.min_program_length = flash_algo.get('min_program_length', 0)

            # Validate required APIs.
            assert self._is_api_valid('pc_erase_sector')
            assert self._is_api_valid('pc_program_page')

            # Check for double buffering support.
            if 'page_buffers' in flash_algo:
                self.page_buffers = flash_algo['page_buffers']
            else:
                self.page_buffers = [self.begin_data]

            self.double_buffer_supported = len(self.page_buffers) > 1

        else:
            self.is_valid = False
            self.use_analyzer = False
            self.end_flash_algo = None
            self.begin_stack = None
            self.begin_data = None
            self.static_base = None
            self.min_program_length = 0
            self.page_buffers = []
            self.double_buffer_supported = False
        
    def _is_api_valid(self, api_name):
        return (api_name in self.flash_algo) \
                and (self.flash_algo[api_name] >= self.flash_algo['load_address']) \
                and (self.flash_algo[api_name] < self.end_flash_algo)

    @property
    def minimum_program_length(self):
        return self.min_program_length or self.region.phrase_size

    @property
    def page_buffer_count(self):
        return len(self.page_buffers)
    
    @property
    def is_erase_all_supported(self):
        return self._is_api_valid('pc_eraseAll')

    @property
    def is_double_buffering_supported(self):
        return self.double_buffer_supported
    
    @property
    def region(self):
        return self._region
    
    @region.setter
    def region(self, flashRegion):
        assert flashRegion.is_flash
        self._region = flashRegion

    def init(self, operation, address=None, clock=0, reset=True):
        """!
        @brief Prepare the flash algorithm for performing operations.
        
        First, the target is prepared to execute flash algo operations, including loading the algo
        to target RAM. This step is skipped if the target is already prepared, i.e., init() has been
        called, but cleanup() not called yet.
        
        Next, the algo's Init() function is called with the provided parameters. If the algo does
        not have an Init() function, this step is skipped. Calling Init() is also skipped if the
        algo was previously inited for the same operation without an intervening uninit. If the
        algo is already inited for a different operation, uninit() is automatically called prior
        to intiting for the new operation.
        
        @exception FlashFailure
        """
        if address is None:
            address = self.get_flash_info().rom_start
        
        assert isinstance(operation, self.Operation)
        assert (self._did_prepare_target) or (not self._did_prepare_target and self._active_operation is None)
        
        self.target.halt()
        
        # Handle the algo already being inited.
        if self._active_operation is not None:
            # Uninit if the algo was left inited for a different operation.
            if self._active_operation != operation:
                self.uninit()
            # Don't need to reinit for the same operation.
            else:
                return

        # Setup target for running the flash algo.
        if not self._did_prepare_target:
            TRACE.debug("algo init and load to %#010x", self.flash_algo['load_address'])
            
            if reset:
                self.target.reset_and_halt(Target.ResetType.SW)
            self.prepare_target()

            # Load flash algo code into target RAM.
            self.target.write_memory_block32(self.flash_algo['load_address'], self.flash_algo['instructions'])

            self._did_prepare_target = True

        # update core register to execute the init subroutine
        if self._is_api_valid('pc_init'):
            TRACE.debug("algo call init(addr=%d, clock=%d, op=%d)", address, clock, operation.value)
            result = self._call_function_and_wait(self.flash_algo['pc_init'],
                                              r0=address, r1=clock, r2=operation.value, init=True)

            # check the return code
            TRACE.debug("init result = %d", result)
            if result != 0:
                raise FlashFailure('init error: %i' % result, result_code=result)
        
        self._active_operation = operation

    def cleanup(self):
        """! @brief Deinitialize the flash algo and restore the target.
        
        Before further operations are executed, the algo must be reinited. Unlike uninit(), this
        method marks the target and unprepared to execute flash algo functions. So on the next call
        to init(), the target will be prepared and the algo loaded into RAM.
        """
        self.uninit()
        self.restore_target()
        self._did_prepare_target = False

    def uninit(self):
        """! @brief Uninitialize the flash algo.
        
        Before further operations are executed, the algo must be reinited. The target is left in
        a state where algo does not have to be reloaded when init() is called.
        
        @exception FlashFailure
        """
        if self._active_operation is None:
            return
        
        if self._is_api_valid('pc_unInit'):
            TRACE.debug("call uninit(%d)", self._active_operation.value)

            # update core register to execute the uninit subroutine
            result = self._call_function_and_wait(self.flash_algo['pc_unInit'],
                                                    r0=self._active_operation.value)
            
            # check the return code
            TRACE.debug("uninit result = %d", result)
            if result != 0:
                raise FlashFailure('uninit error: %i' % result, result_code=result)
            
        self._active_operation = None

    def prepare_target(self):
        """! @brief Subclasses can override this method to perform special target configuration."""
        pass
    
    def restore_target(self):
        """! @brief Subclasses can override this method to undo any target configuration changes."""
        pass

    def compute_crcs(self, sectors):
        assert self.use_analyzer
        
        data = []

        # Load analyzer code into target RAM.
        self.target.write_memory_block32(self.flash_algo['analyzer_address'], analyzer)

        # Convert address, size pairs into commands
        # for the crc computation algorithm to preform
        for addr, size in sectors:
            size_val = msb(size)
            addr_val = addr // size
            # Size must be a power of 2
            assert (1 << size_val) == size
            # Address must be a multiple of size
            assert (addr % size) == 0
            val = (size_val << 0) | (addr_val << 16)
            data.append(val)

        self.target.write_memory_block32(self.begin_data, data)

        # update core register to execute the subroutine
        TRACE.debug("call compute crc(%x, %x)", self.begin_data, len(data))
        self._call_function_and_wait(self.flash_algo['analyzer_address'], self.begin_data, len(data))

        # Read back the CRCs for each section
        data = self.target.read_memory_block32(self.begin_data, len(data))
        return data

    def erase_all(self):
        """!
        @brief Erase all the flash.
        
        @exception FlashEraseFailure
        """
        assert self._active_operation == self.Operation.ERASE
        assert self.is_erase_all_supported

        # update core register to execute the erase_all subroutine
        TRACE.debug("call erase_all")
        result = self._call_function_and_wait(self.flash_algo['pc_eraseAll'])

        # check the return code
        TRACE.debug("erase_all result = %d", result)
        if result != 0:
            raise FlashEraseFailure('erase_all error: %i' % result, result_code=result)

    def erase_sector(self, address):
        """!
        @brief Erase one sector.
        
        @exception FlashEraseFailure
        """
        assert self._active_operation == self.Operation.ERASE

        # update core register to execute the erase_sector subroutine
        TRACE.debug("call erase_sector(%x)", address)
        result = self._call_function_and_wait(self.flash_algo['pc_erase_sector'], address)

        # check the return code
        TRACE.debug("erase_sector result = %d", result)
        if result != 0:
            raise FlashEraseFailure('erase_sector(0x%x) error: %i' % (address, result), address, result)

    def program_page(self, address, bytes):
        """!
        @brief Flash one or more pages.
        
        @exception FlashProgramFailure
        """
        assert self._active_operation == self.Operation.PROGRAM

        # prevent security settings from locking the device
        bytes = self.override_security_bits(address, bytes)

        # first transfer in RAM
        self.target.write_memory_block8(self.begin_data, bytes)

        # update core register to execute the program_page subroutine
        TRACE.debug("call program_page(addr=%x, len=%x, data=%x)", address, len(bytes), self.begin_data)
        result = self._call_function_and_wait(self.flash_algo['pc_program_page'], address, len(bytes), self.begin_data)

        # check the return code
        TRACE.debug("program_page result = %d", result)
        if result != 0:
            raise FlashProgramFailure('program_page(0x%x) error: %i' % (address, result), address, result)

    def start_program_page_with_buffer(self, buffer_number, address):
        """!
        @brief Start flashing one or more pages.
        """
        assert buffer_number < len(self.page_buffers), "Invalid buffer number"
        assert self._active_operation == self.Operation.PROGRAM

        # update core register to execute the program_page subroutine
        TRACE.debug("start_program_page_with_buffer(addr=%x, len=%x, data=%x)", address, self.region.page_size,
                self.page_buffers[buffer_number])
        self._call_function(self.flash_algo['pc_program_page'], address, self.region.page_size, self.page_buffers[buffer_number])

    def load_page_buffer(self, buffer_number, address, bytes):
        """!
        @brief Load data to a numbered page buffer.
        
        This method is used in conjunction with start_program_page_with_buffer() to implement
        double buffered programming.
        """
        assert buffer_number < len(self.page_buffers), "Invalid buffer number"

        # prevent security settings from locking the device
        bytes = self.override_security_bits(address, bytes)

        # transfer the buffer to device RAM
        self.target.write_memory_block8(self.page_buffers[buffer_number], bytes)

    def program_phrase(self, address, bytes):
        """!
        @brief Flash a portion of a page.
        
        @exception FlashFailure The address or data length is not aligned to the minimum
            programming length specified in the flash algorithm.
        @exception FlashProgramFailure
        """
        assert self._active_operation == self.Operation.PROGRAM

        # Get min programming length. If one was not specified, use the page size.
        if self.min_program_length:
            min_len = self.min_program_length
        else:
            min_len = self.region.page_size

        # Require write address and length to be aligned to min write size.
        if address % min_len:
            raise FlashFailure("unaligned flash write address")
        if len(bytes) % min_len:
            raise FlashFailure("phrase length is unaligned or too small")

        # prevent security settings from locking the device
        bytes = self.override_security_bits(address, bytes)

        # first transfer in RAM
        self.target.write_memory_block8(self.begin_data, bytes)

        # update core register to execute the program_page subroutine
        TRACE.debug("call program_phrase(addr=%x, len=%x, data=%x)", address, len(bytes), self.begin_data)
        result = self._call_function_and_wait(self.flash_algo['pc_program_page'], address, len(bytes), self.begin_data)

        # check the return code
        if result != 0:
            raise FlashProgramFailure('program_phrase(0x%x) error: %i' % (address, result), address, result)

    def get_sector_info(self, addr):
        """!
        @brief Get info about the sector that contains this address.
        """
        assert self.region is not None
        if not self.region.contains_address(addr):
            return None

        info = SectorInfo()
        info.erase_weight = self.region.erase_sector_weight
        info.size = self.region.sector_size
        info.base_addr = addr - (addr % info.size)
        return info

    def get_page_info(self, addr):
        """!
        @brief Get info about the page that contains this address.
        """
        assert self.region is not None
        if not self.region.contains_address(addr):
            return None

        info = PageInfo()
        info.program_weight = self.region.program_page_weight
        info.size = self.region.page_size
        info.base_addr = addr - (addr % info.size)
        return info

    def get_flash_info(self):
        """!
        @brief Get info about the flash.

        Override this method to return different values.
        """
        assert self.region is not None

        info = FlashInfo()
        info.rom_start = self.region.start
        info.erase_weight = self.region.erase_all_weight
        info.crc_supported = self.use_analyzer
        return info

    def get_flash_builder(self):
        return FlashBuilder(self)

    def flash_block(self, addr, data, smart_flash=True, chip_erase=None, progress_cb=None, fast_verify=False):
        """!
        @brief Flash a block of data.
        """
        assert self.region is not None
        assert self.region.contains_range(start=addr, length=len(data))
        
        fb = FlashBuilder(self)
        fb.add_data(addr, data)
        info = fb.program(chip_erase, progress_cb, smart_flash, fast_verify)
        return info

    def _call_function(self, pc, r0=None, r1=None, r2=None, r3=None, init=False):
        reg_list = []
        data_list = []

        if self.flash_algo_debug:
            # Save vector catch state for use in wait_for_completion()
            self._saved_vector_catch = self.target.get_vector_catch()
            self.target.set_vector_catch(Target.VectorCatch.ALL)

        reg_list.append('pc')
        data_list.append(pc)
        if r0 is not None:
            reg_list.append('r0')
            data_list.append(r0)
        if r1 is not None:
            reg_list.append('r1')
            data_list.append(r1)
        if r2 is not None:
            reg_list.append('r2')
            data_list.append(r2)
        if r3 is not None:
            reg_list.append('r3')
            data_list.append(r3)
        if init:
            reg_list.append('r9')
            data_list.append(self.static_base)
        if init:
            reg_list.append('sp')
            data_list.append(self.begin_stack)
        reg_list.append('lr')
        data_list.append(self.flash_algo['load_address'] + 1)
        self.target.write_core_registers_raw(reg_list, data_list)

        # resume target
        self.target.resume()

    def wait_for_completion(self):
        """!
        @brief Wait until the breakpoint is hit.
        """
        while self.target.get_state() == Target.State.RUNNING:
            pass

        if self.flash_algo_debug:
            regs = self.target.read_core_registers_raw(list(range(19)) + [20])
            LOG.debug("Registers after flash algo: [%s]", " ".join("%08x" % r for r in regs))

            expected_fp = self.flash_algo['static_base']
            expected_sp = self.flash_algo['begin_stack']
            expected_pc = self.flash_algo['load_address']
            final_ipsr = self.target.read_core_register('ipsr')
            final_fp = self.target.read_core_register('r9')
            final_sp = self.target.read_core_register('sp')
            final_pc = self.target.read_core_register('pc')
            #TODO - uncomment if Read/write and zero init sections can be moved into a separate flash algo section
            #expected_flash_algo = self.flash_algo['instructions']
            #if self.use_analyzer:
            #    expected_analyzer = analyzer
            #final_flash_algo = self.target.read_memory_block32(self.flash_algo['load_address'], len(self.flash_algo['instructions']))
            #if self.use_analyzer:
            #    final_analyzer = self.target.read_memory_block32(self.flash_algo['analyzer_address'], len(analyzer))

            error = False
            if final_ipsr != 0:
                LOG.error("IPSR should be 0 but is 0x%x", final_ipsr)
                error = True
            if final_fp != expected_fp:
                # Frame pointer should not change
                LOG.error("Frame pointer should be 0x%x but is 0x%x" % (expected_fp, final_fp))
                error = True
            if final_sp != expected_sp:
                # Stack pointer should return to original value after function call
                LOG.error("Stack pointer should be 0x%x but is 0x%x" % (expected_sp, final_sp))
                error = True
            if final_pc != expected_pc:
                # PC should be pointing to breakpoint address
                LOG.error("PC should be 0x%x but is 0x%x" % (expected_pc, final_pc))
                error = True
            #TODO - uncomment if Read/write and zero init sections can be moved into a separate flash algo section
            #if not _same(expected_flash_algo, final_flash_algo):
            #    LOG.error("Flash algorithm overwritten!")
            #    error = True
            #if self.use_analyzer and not _same(expected_analyzer, final_analyzer):
            #    LOG.error("Analyzer overwritten!")
            #    error = True
            assert error == False
            self.target.set_vector_catch(self._saved_vector_catch)

        return self.target.read_core_register('r0')

    def _call_function_and_wait(self, pc, r0=None, r1=None, r2=None, r3=None, init=False):
        self._call_function(pc, r0, r1, r2, r3, init)
        return self.wait_for_completion()

    def set_flash_algo_debug(self, enable):
        """!
        @brief Turn on extra flash algorithm checking

        When set this may slow down flash algo performance.
        """
        self.flash_algo_debug = enable

    def override_security_bits(self, address, data):
        return data
