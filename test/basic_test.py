# pyOCD debugger
# Copyright (c) 2006-2020 Arm Limited
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

import argparse
import os
import sys
from time import sleep
from random import randrange
import math
import logging

from pyocd.core.helpers import ConnectHelper
from pyocd.core.memory_map import MemoryType
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.utility.conversion import (float32_to_u32, u16le_list_to_byte_list)
from pyocd.utility.mask import same

from test_util import (
    Test,
    get_session_options,
    get_test_binary_path,
    )

# Simple code sequence used to test range stepping.
# The important part is that it has no branches.
RANGE_STEP_CODE = u16le_list_to_byte_list([
        0x3001, # adds    r0, #1
        0x43C1, # mvns    r1, r0
        0x3101, # adds    r1, #1
        0x0102, # movs    r2, r0, lsl #4
        0x0013, # movs    r3, r2
        0x404B, # eors    r3, r1
        0x1840, # adds    r0, r1
        0x1880, # adds    r0, r2
        0x1AC0, # subs    r0, r3
        0xBE00, # bkpt    #0
        ])

class BasicTest(Test):
    def __init__(self):
        super(BasicTest, self).__init__("Basic Test", run_basic_test)
    
def run_basic_test(board_id):
    return basic_test(board_id, None)

def basic_test(board_id, file):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        addr = 0
        size = 0
        f = None
        binary_file = "l1_"

        if file is None:
            binary_file = get_test_binary_path(board.test_binary)
        else:
            binary_file = file

        print("binary file: %s" % binary_file)

        memory_map = board.target.get_memory_map()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)
        rom_region = memory_map.get_boot_memory()

        addr = ram_region.start
        size = 0x502
        addr_bin = rom_region.start

        target = board.target
        flash = rom_region.flash

        print("\n\n------ GET Unique ID ------")
        print("Unique ID: %s" % board.unique_id)

        print("\n\n------ TEST READ / WRITE CORE REGISTER ------")
        pc = target.read_core_register('pc')
        print("initial pc: 0x%X" % target.read_core_register('pc'))
        # write in pc dummy value
        target.write_core_register('pc', 0x3D82)
        print("now pc: 0x%X" % target.read_core_register('pc'))
        # write initial pc value
        target.write_core_register('pc', pc)
        print("initial pc value rewritten: 0x%X" % target.read_core_register('pc'))

        msp = target.read_core_register('msp')
        psp = target.read_core_register('psp')
        print("MSP = 0x%08x; PSP = 0x%08x" % (msp, psp))

        if 'faultmask' in target.core_registers.by_name:
            control = target.read_core_register('control')
            faultmask = target.read_core_register('faultmask')
            basepri = target.read_core_register('basepri')
            primask = target.read_core_register('primask')
            print("CONTROL = 0x%02x; FAULTMASK = 0x%02x; BASEPRI = 0x%02x; PRIMASK = 0x%02x" % (control, faultmask, basepri, primask))
        else:
            control = target.read_core_register('control')
            primask = target.read_core_register('primask')
            print("CONTROL = 0x%02x; PRIMASK = 0x%02x" % (control, primask))

        target.write_core_register('primask', 1)
        newPrimask = target.read_core_register('primask')
        print("New PRIMASK = 0x%02x" % newPrimask)
        target.write_core_register('primask', primask)
        newPrimask = target.read_core_register('primask')
        print("Restored PRIMASK = 0x%02x" % newPrimask)

        if target.selected_core.has_fpu:
            s0 = target.read_core_register('s0')
            print("S0 = %g (0x%08x)" % (s0, float32_to_u32(s0)))
            target.write_core_register('s0', math.pi)
            newS0 = target.read_core_register('s0')
            print("New S0 = %g (0x%08x)" % (newS0, float32_to_u32(newS0)))
            target.write_core_register('s0', s0)
            newS0 = target.read_core_register('s0')
            print("Restored S0 = %g (0x%08x)" % (newS0, float32_to_u32(newS0)))


        print("\n\n------ TEST HALT / RESUME ------")

        print("resume")
        target.resume()
        sleep(0.2)

        print("halt")
        target.halt()
        print("HALT: pc: 0x%X" % target.read_core_register('pc'))
        sleep(0.2)


        print("\n\n------ TEST STEP ------")

        print("reset and halt")
        target.reset_and_halt()
        currentPC = target.read_core_register('pc')
        print("HALT: pc: 0x%X" % currentPC)
        sleep(0.2)

        for i in range(4):
            print("step")
            target.step()
            newPC = target.read_core_register('pc')
            print("STEP: pc: 0x%X" % newPC)
            sleep(0.2)

        print("\n\n------ TEST RANGE STEP ------")

        # Add some extra room before end of memory, and a second copy so there are instructions
        # after the final bkpt. Add 1 because region end is always odd.
        test_addr = ram_region.end + 1 - len(RANGE_STEP_CODE) * 2 - 32
        # Since the end address is inclusive, we need to exclude the last instruction.
        test_end_addr = test_addr + len(RANGE_STEP_CODE) - 2
        print("range start = %#010x; range_end = %#010x" % (test_addr, test_end_addr))
        # Load up some code into ram to test range step.
        target.write_memory_block8(test_addr, RANGE_STEP_CODE * 2)
        check_data = target.read_memory_block8(test_addr, len(RANGE_STEP_CODE) * 2)
        if not same(check_data, RANGE_STEP_CODE * 2):
            print("Failed to write range step test code to RAM")
        else:
            print("wrote range test step code to RAM successfully")
        
        target.write_core_register('pc', test_addr)
        currentPC = target.read_core_register('pc')
        print("start PC: 0x%X" % currentPC)
        target.step(start=test_addr, end=test_end_addr)
        newPC = target.read_core_register('pc')
        print("end PC: 0x%X" % newPC)

        # Now test again to ensure the bkpt stops it.
        target.write_core_register('pc', test_addr)
        currentPC = target.read_core_register('pc')
        print("start PC: 0x%X" % currentPC)
        target.step(start=test_addr, end=test_end_addr + 4) # include bkpt
        newPC = target.read_core_register('pc')
        print("end PC: 0x%X" % newPC)
        halt_reason = target.get_halt_reason()
        print("halt reason: %s (should be BREAKPOINT)" % halt_reason.name)

        print("\n\n------ TEST READ / WRITE MEMORY ------")
        target.halt()
        print("READ32/WRITE32")
        val = randrange(0, 0xffffffff)
        print("write32 0x%X at 0x%X" % (val, addr))
        target.write_memory(addr, val)
        res = target.read_memory(addr)
        print("read32 at 0x%X: 0x%X" % (addr, res))
        if res != val:
            print("ERROR in READ/WRITE 32")

        print("\nREAD16/WRITE16")
        val = randrange(0, 0xffff)
        print("write16 0x%X at 0x%X" % (val, addr + 2))
        target.write_memory(addr + 2, val, 16)
        res = target.read_memory(addr + 2, 16)
        print("read16 at 0x%X: 0x%X" % (addr + 2, res))
        if res != val:
            print("ERROR in READ/WRITE 16")

        print("\nREAD8/WRITE8")
        val = randrange(0, 0xff)
        print("write8 0x%X at 0x%X" % (val, addr + 1))
        target.write_memory(addr + 1, val, 8)
        res = target.read_memory(addr + 1, 8)
        print("read8 at 0x%X: 0x%X" % (addr + 1, res))
        if res != val:
            print("ERROR in READ/WRITE 8")


        print("\n\n------ TEST READ / WRITE MEMORY BLOCK ------")
        data = [randrange(1, 50) for x in range(size)]
        target.write_memory_block8(addr, data)
        block = target.read_memory_block8(addr, size)
        error = False
        for i in range(len(block)):
            if (block[i] != data[i]):
                error = True
                print("ERROR: 0x%X, 0x%X, 0x%X!!!" % ((addr + i), block[i], data[i]))
        if error:
            print("TEST FAILED")
        else:
            print("TEST PASSED")


        print("\n\n------ TEST RESET ------")
        target.reset()
        sleep(0.1)
        target.halt()

        for i in range(5):
            target.step()
            print("pc: 0x%X" % target.read_core_register('pc'))

        print("\n\n------ TEST PROGRAM/ERASE PAGE ------")
        # Fill 3 pages with 0x55
        sector_size = rom_region.sector_size
        page_size = rom_region.page_size
        sectors_to_test = min(rom_region.length // sector_size, 3)
        addr_flash = rom_region.start + rom_region.length - sector_size * sectors_to_test
        fill = [0x55] * page_size
        for i in range(0, sectors_to_test):
            address = addr_flash + sector_size * i
            # Test only supports a location with 3 aligned
            # pages of the same size
            current_page_size = flash.get_page_info(addr_flash).size
            assert page_size == current_page_size
            assert address % current_page_size == 0

            print("Erasing sector @ 0x%x (%d bytes)" % (address, sector_size))
            flash.init(flash.Operation.ERASE)
            flash.erase_sector(address)

            print("Verifying erased sector @ 0x%x (%d bytes)" % (address, sector_size))
            data = target.read_memory_block8(address, sector_size)
            if data != [flash.region.erased_byte_value] * sector_size:
                print("FAILED to erase sector @ 0x%x (%d bytes)" % (address, sector_size))
            else:
                print("Programming page @ 0x%x (%d bytes)" % (address, page_size))
                flash.init(flash.Operation.PROGRAM)
                flash.program_page(address, fill)

                print("Verifying programmed page @ 0x%x (%d bytes)" % (address, page_size))
                data = target.read_memory_block8(address, page_size)
                if data != fill:
                    print("FAILED to program page @ 0x%x (%d bytes)" % (address, page_size))

        # Erase the middle sector
        if sectors_to_test > 1:
            address = addr_flash + sector_size
            print("Erasing sector @ 0x%x (%d bytes)" % (address, sector_size))
            flash.init(flash.Operation.ERASE)
            flash.erase_sector(address)
        flash.cleanup()

        print("Verifying erased sector @ 0x%x (%d bytes)" % (address, sector_size))
        data = target.read_memory_block8(address, sector_size)
        if data != [flash.region.erased_byte_value] * sector_size:
            print("FAILED to erase sector @ 0x%x (%d bytes)" % (address, sector_size))
       
        # Re-verify the 1st and 3rd page were not erased, and that the 2nd page is fully erased
        did_pass = False
        for i in range(0, sectors_to_test):
            address = addr_flash + sector_size * i
            print("Verifying page @ 0x%x (%d bytes)" % (address, page_size))
            data = target.read_memory_block8(address, page_size)
            expected = ([flash.region.erased_byte_value] * page_size) if (i == 1) else fill
            did_pass = (data == expected)
            if not did_pass:
                print("FAILED verify for page @ 0x%x (%d bytes)" % (address, page_size))
                break
        if did_pass:
            print("TEST PASSED")
        else:
            print("TEST FAILED")

        print("\n\n----- FLASH NEW BINARY -----")
        FileProgrammer(session).program(binary_file, base_address=addr_bin)

        target.reset()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A CMSIS-DAP python debugger')
    parser.add_argument('-f', help='binary file', dest="file")
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    file = args.file
    basic_test(None, file)
