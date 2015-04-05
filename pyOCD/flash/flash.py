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

class PageInfo(object):

    def __init__(self):
        self.erase_weight = None        # Time it takes to erase a page
        self.program_weight = None      # Time it takes to program a page (Not including data transfer time)
        self.size = None                # Size of page

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
