#!/usr/bin/env python

import argparse
from intelhex import IntelHex
from time import sleep, time
from struct import unpack
import sys
import subprocess

from pyOCD.interface import INTERFACE, usb_backend
from pyOCD.board import MbedBoard

import logging

VID = 0x0D28
PID = 0x0204

NVMC_READY      = 0x4001E400
NVMC_CONFIG     = 0x4001E504
NVMC_ERASEPAGE  = 0x4001E508
NVMC_ERASEALL   = 0x4001E50C
NVMC_ERASEUIR   = 0x4001E514

def flashHex(target, filename):
    '''
    flash a hex file to nRF51822
    '''
    ihex = IntelHex(filename)
    addresses = ihex.addresses()
    nbytes = len(addresses)
    addresses.sort()
    
    start = time()
    
    target.halt()
    logging.info("Erase All")
    target.writeMemory(NVMC_CONFIG, 2)
    target.writeMemory(NVMC_ERASEALL, 1)
    while target.readMemory(NVMC_READY) == 0:
        pass
       
    logging.info("Prepare to write")
    target.writeMemory(NVMC_CONFIG, 1)
    while target.readMemory(NVMC_READY) == 0:
        pass


    nbytes_align32 = nbytes & ~(32 - 1)
    for i in range(0, nbytes_align32, 32):
        if (addresses[i] + 31) == addresses[i + 31]:
            start_address = addresses[i]
            # read 32 data bytes
            bytes = ihex.tobinarray(start=start_address, size=32)
            target.writeBlockMemoryUnaligned8(start_address, bytes)
            
        else:
            # data always 4 bytes aligned
            for j in range(0, 32, 4):
                start_address = addresses[i + j]
                bytes = ihex.tobinarray(start=start_address, size=4)
                target.writeBlockMemoryUnaligned8(start_address, bytes)      
        
    for i in range(nbytes_align32, nbytes, 4):
        start_address = addresses[i]
        bytes = ihex.tobinarray(start=start_address, size=4)
        target.writeBlockMemoryUnaligned8(start_address, bytes)
        
    target.writeMemory(NVMC_CONFIG, 0)
    while target.readMemory(NVMC_READY) == 0:
        pass
        
    end = time()
    print("%f kbytes flashed in %f seconds ===> %f kbytes/s" %(nbytes/1000, end-start, nbytes/(1000*(end - start))))

def flashBin(target, filename, offset=0x14000):
    '''
    flash a binary file to nRF51822 with offset
    '''
    f = open(filename, "rb")
    start = time()
    
    target.halt()
    while target.readMemory(NVMC_READY) == 0:
        pass
       
    logging.info("Prepare to write")
    target.writeMemory(NVMC_CONFIG, 1)
    while target.readMemory(NVMC_READY) == 0:
        pass
    
    address = offset
    page_size = 1024
    nb_bytes = 0    
    try:
        bytes_read = f.read(page_size)
        while bytes_read:
            bytes_read = unpack(str(len(bytes_read)) + 'B', bytes_read)
            nb_bytes += len(bytes_read)
            
            logging.info("Erase page: 0x%X", address)
            target.writeMemory(NVMC_CONFIG, 2)
            target.writeMemory(NVMC_ERASEPAGE, address)
            while target.readMemory(NVMC_READY) == 0:
                pass

            target.writeMemory(NVMC_CONFIG, 1)
            while target.readMemory(NVMC_READY) == 0:
                pass
            
            target.writeBlockMemoryUnaligned8(address, bytes_read)
            
            # Verify
            bytes_write = target.readBlockMemoryUnaligned8(address, len(bytes_read))
            for i in range(len(bytes_write)):
                if (bytes_read[i] != bytes_write[i]):
                    logging.info("Write: error@0x%X - 0x%X | 0x%X", address, bytes_read[i], bytes_write[i])
                    raise Exception("Verify Error") 
            
            
            logging.info("Write: 0x%X - %d", address, len(bytes_read))
            
            address += len(bytes_read)
            bytes_read = f.read(page_size)
    finally:
        f.close()
        
    target.writeMemory(NVMC_CONFIG, 0)
    while target.readMemory(NVMC_READY) == 0:
        pass
        
    end = time()
    print("%f kbytes flashed in %f seconds ===> %f kbytes/s" %(nb_bytes/1000, end-start, nb_bytes/(1000*(end - start))))

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="flash nrf51822")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-i", "--ihex", help="a ihex file")
    parser.add_argument("-b", "--bin", help="a binary file")
    parser.add_argument("-o", "--offset", help="with -b option, a binary will be flashed with an offset (default: 0x14000)")
    args = parser.parse_args()
    
    if args.verbose == 2:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    
    adapter = None
    try:
        interfaces = INTERFACE[usb_backend].getAllConnectedInterface(VID, PID)
        if interfaces == None:
            print "Not find a mbed interface"
            sys.exit(1)
            
        # Use the first one
        first_interface = interfaces[0]
        adapter = MbedBoard("target_lpc1768", "flash_lpc1768", first_interface)
        adapter.init()
        target = adapter.target
        target.halt()

        if args.ihex:
            print 'flash hex file - %s to nrf51822' % args.ihex
            flashHex(target, args.ihex)
        
        offset = 0x14000
        if args.offset:
            offset = args.offset
            
        if args.bin:
            print 'flash binary file - %s to nrf51822' % args.bin
            flashBin(target, args.bin, offset)

        sleep(1)
        target.reset()
        
    finally:
        if adapter != None:
            adapter.uninit()
    
