"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

import os, sys
from time import sleep, time
from random import randrange

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard

import logging
logging.basicConfig(level=logging.INFO)

with MbedBoard.chooseBoard(frequency = 1000000) as board:
    target_type = board.getTargetType()

    test_clock = 10000000
    if target_type == "kl25z":
        ram_start = 0x1ffff000
        ram_size = 0x4000
        rom_start = 0x00000000
        rom_size = 0x20000
    elif target_type == "kl46z":
        ram_start = 0x1fffe000
        ram_size = 0x8000
        rom_start = 0x00000000
        rom_size = 0x40000
    elif target_type == "k22f":
        ram_start = 0x1fff0000
        ram_size = 0x20000
        rom_start = 0x00000000
        rom_size = 0x80000
    elif target_type == "lpc11u24":
        ram_start = 0x10000000
        ram_size = 0x2000
        rom_start = 0x00000000
        rom_size = 0x8000
    elif target_type == "lpc1768":
        ram_start = 0x10000000
        ram_size = 0x8000
        rom_start = 0x00000000
        rom_size = 0x80000
    elif target_type == "lpc4330":
        ram_start = 0x10000000
        ram_size = 0x20000
        rom_start = 0x14000000
        rom_size = 0x100000
    elif target_type == "nrf51822":
        ram_start = 0x20000000
        ram_size = 0x4000
        rom_start = 0x00000000
        rom_size = 0x40000
        # Override clock since 10MHz is too fast
        test_clock = 1000000 
    else:
        raise Exception("The board is not supported by this test script.")

    target = board.target
    transport = board.transport
    flash = board.flash
    interface = board.interface

    transport.setClock(test_clock)

    print "\r\n\r\n------ TEST RAM READ / WRITE SPEED ------"
    test_addr = ram_start
    test_size = ram_size
    data = [randrange(1, 50) for x in range(test_size)]
    start = time()
    target.writeBlockMemoryUnaligned8(test_addr, data)
    stop = time()
    diff = stop-start
    print("Writing %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
    start = time()
    block = target.readBlockMemoryUnaligned8(test_addr, test_size)
    stop = time()
    diff = stop-start
    print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
    error = False
    for i in range(len(block)):
        if (block[i] != data[i]):
            error = True
            print "ERROR: 0x%X, 0x%X, 0x%X!!!" % ((addr + i), block[i], data[i])
    if error:
        print "TEST FAILED"
    else:
        print "TEST PASSED"

    print "\r\n\r\n------ TEST ROM READ SPEED ------"
    test_addr = rom_start
    test_size = rom_size
    start = time()
    block = target.readBlockMemoryUnaligned8(test_addr, test_size)
    stop = time()
    diff = stop-start
    print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
    print "TEST PASSED"
    
    target.reset()
