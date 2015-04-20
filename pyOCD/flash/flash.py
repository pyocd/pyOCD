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

from pyOCD.target.target import TARGET_RUNNING
import logging
from struct import unpack
from time import time
from flash_builder import FLASH_PAGE_ERASE, FLASH_CHIP_ERASE, FlashBuilder

DEFAULT_PAGE_PROGRAM_WEIGHT = 0.130
DEFAULT_PAGE_ERASE_WEIGHT   = 0.048
DEFAULT_CHIP_ERASE_WEIGHT   = 0.174

# Program to compute the CRC of sectors.  This works on cortex-m processors.
# Code is relocatable and only needs to be on a 4 byte boundary.
# 200 bytes of executable data below + 1024 byte crc table = 1224 bytes
# Usage requirements:
# -In memory reserve 0x600 for code & table
# -Make sure data buffer is big enough to hold 4 bytes for each page that could be checked (ie.  >= num pages * 4)
analyzer = (
    0x2180468c, 0x2600b5f0, 0x4f2c2501, 0x447f4c2c, 0x1c2b0049, 0x425b4033, 0x40230872, 0x085a4053,
    0x425b402b, 0x40534023, 0x402b085a, 0x4023425b, 0x085a4053, 0x425b402b, 0x40534023, 0x402b085a,
    0x4023425b, 0x085a4053, 0x425b402b, 0x40534023, 0x402b085a, 0x4023425b, 0x085a4053, 0x425b402b,
    0x40534023, 0xc7083601, 0xd1d2428e, 0x2b004663, 0x4663d01f, 0x46b4009e, 0x24ff2701, 0x44844d11,
    0x1c3a447d, 0x88418803, 0x4351409a, 0xd0122a00, 0x22011856, 0x780b4252, 0x40533101, 0x009b4023,
    0x0a12595b, 0x42b1405a, 0x43d2d1f5, 0x4560c004, 0x2000d1e7, 0x2200bdf0, 0x46c0e7f8, 0x000000b6,
    0xedb88320, 0x00000044, 
    )

def _msb( n ):
    ndx = 0
    while ( 1 < n ):
        n = ( n >> 1 )
        ndx += 1
    return ndx

class PageInfo(object):

    def __init__(self):
        self.erase_weight = None        # Time it takes to erase a page
        self.program_weight = None      # Time it takes to program a page (Not including data transfer time)
        self.size = None                # Size of page
        self.crc_supported = None       # Is the function computeCrcs supported?

class FlashInfo(object):

    def __init__(self):
        self.rom_start = None           # Starting address of ROM
        self.erase_weight = None        # Time it takes to perform a chip erase

class Flash(object):
    """
    This class is responsible to flash a new binary in a target
    """

    def __init__(self, target, flash_algo):
        self.target = target
        self.flash_algo = flash_algo
        self.end_flash_algo = flash_algo['load_address'] + len(flash_algo)*4
        self.begin_stack = flash_algo['begin_stack']
        self.begin_data = flash_algo['begin_data']
        self.static_base = flash_algo['static_base']
        self.page_size = flash_algo['page_size']

    def init(self):
        """
        Download the flash algorithm in RAM
        """
        self.target.halt()
        self.target.setTargetState("PROGRAM")

        # download flash algo in RAM
        self.target.writeBlockMemoryAligned32(self.flash_algo['load_address'], self.flash_algo['instructions'])
        if self.flash_algo['analyzer_supported']:
            self.target.writeBlockMemoryAligned32(self.flash_algo['analyzer_address'], analyzer)

        # update core register to execute the init subroutine
        self.updateCoreRegister(0, 0, 0, 0, self.flash_algo['pc_init'])
        # resume and wait until the breakpoint is hit
        self.target.resume()
        while(self.target.getState() == TARGET_RUNNING):
            pass

        # check the return code
        result = self.target.readCoreRegister('r0')
        if result != 0:
            logging.error('init error: %i', result)

        return

    def computeCrcs(self, sectors):

        data = []

        # Convert address, size pairs into commands
        # for the crc computation algorithm to preform
        for addr, size in sectors:
            size_val = _msb(size)
            addr_val = addr // size
            # Size must be a power of 2
            assert (1 << size_val) == size
            # Address must be a multiple of size
            assert (addr % size) == 0
            val = (size_val << 0) | (addr_val << 16)
            data.append(val)

        self.target.writeBlockMemoryAligned32(self.begin_data, data)

        # update core register to execute the subroutine
        self.updateCoreRegister(self.begin_data, len(data), 0, 0, self.flash_algo['analyzer_address'])

        # resume and wait until the breakpoint is hit
        self.target.resume()
        while(self.target.getState() == TARGET_RUNNING):
            pass

        # Read back the CRCs for each section
        data = self.target.readBlockMemoryAligned32(self.begin_data, len(data))
        return data

    def eraseAll(self):
        """
        Erase all the flash
        """

        # update core register to execute the eraseAll subroutine
        self.updateCoreRegister(0, 0, 0, 0, self.flash_algo['pc_eraseAll'])

        # resume and wait until the breakpoint is hit
        self.target.resume()
        while(self.target.getState() == TARGET_RUNNING):
            pass

        # check the return code
        result = self.target.readCoreRegister('r0')
        if result != 0:
            logging.error('eraseAll error: %i', result)

        return

    def erasePage(self, flashPtr):
        """
        Erase one page
        """

        # update core register to execute the erasePage subroutine
        self.updateCoreRegister(flashPtr, 0, 0, 0, self.flash_algo['pc_erase_sector'])

        # resume and wait until the breakpoint is hit
        self.target.resume()
        while(self.target.getState() == TARGET_RUNNING):
            pass

        # check the return code
        result = self.target.readCoreRegister('r0')
        if result != 0:
            logging.error('erasePage error: %i', result)

        return

    def programPage(self, flashPtr, bytes):
        """
        Flash one page
        """

        # prevent security settings from locking the device
        bytes = self.overrideSecurityBits(flashPtr, bytes)

        # first transfer in RAM
        self.target.writeBlockMemoryUnaligned8(self.begin_data, bytes)

        # update core register to execute the program_page subroutine
        self.updateCoreRegister(flashPtr, self.page_size, self.begin_data, 0, self.flash_algo['pc_program_page'])

        # resume and wait until the breakpoint is hit
        self.target.resume()
        while(self.target.getState() == TARGET_RUNNING):
            pass

        # check the return code
        result = self.target.readCoreRegister('r0')
        if result != 0:
            logging.error('programPage error: %i', result)

        return

    def getPageInfo(self, addr):
        """
        Get info about the page that contains this address

        Override this function if variable page sizes are supported
        """
        info = PageInfo()
        info.erase_weight = DEFAULT_PAGE_ERASE_WEIGHT
        info.program_weight = DEFAULT_PAGE_PROGRAM_WEIGHT
        info.size = self.flash_algo['page_size']
        return info

    def getFlashInfo(self):
        """
        Get info about the flash

        Override this function to return differnt values
        """
        info = FlashInfo()
        info.rom_start = 0
        info.erase_weight = DEFAULT_CHIP_ERASE_WEIGHT
        info.crc_supported = self.flash_algo['analyzer_supported']
        return info

    def getFlashBuilder(self):
        return FlashBuilder(self, self.getFlashInfo().rom_start)

    def flashBlock(self, addr, data, smart_flash = True, chip_erase = None, progress_cb = None):
        """
        Flash a block of data
        """
        start = time()

        flash_start = self.getFlashInfo().rom_start
        fb = FlashBuilder(self, flash_start)
        fb.addData(addr, data)
        operation = fb.program(chip_erase, progress_cb, smart_flash)

        end = time()
        logging.debug("%f kbytes flashed in %f seconds ===> %f kbytes/s" %(len(data)/1024, end-start, len(data)/(1024*(end - start))))
        return operation

    def flashBinary(self, path_file, flashPtr = 0x0000000, smart_flash = True, chip_erase = None, progress_cb = None):
        """
        Flash a binary
        """
        f = open(path_file, "rb")

        with open(path_file, "rb") as f:
            data = f.read()
        data = unpack(str(len(data)) + 'B', data)
        self.flashBlock(flashPtr, data, smart_flash, chip_erase, progress_cb)

    def updateCoreRegister(self, r0, r1, r2, r3, pc):
        self.target.writeCoreRegister('pc', pc)
        self.target.writeCoreRegister('r0', r0)
        self.target.writeCoreRegister('r1', r1)
        self.target.writeCoreRegister('r2', r2)
        self.target.writeCoreRegister('r3', r3)
        self.target.writeCoreRegister('r9', self.static_base)
        self.target.writeCoreRegister('sp', self.begin_stack)
        self.target.writeCoreRegister('lr', self.flash_algo['load_address'] + 1)
        return

    def overrideSecurityBits(self, address, data):
        return data
