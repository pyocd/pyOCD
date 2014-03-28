#!/usr/bin/env python

import argparse
from time import sleep, time
from struct import unpack
import sys
import subprocess

from pyOCD.interface import INTERFACE, usb_backend
from pyOCD.board import MbedBoard

import logging

logging.basicConfig(level=logging.DEBUG)

VID = 0x0D28
PID = 0x0204

NVMC_READY      = 0x4001E400
NVMC_CONFIG     = 0x4001E504
NVMC_ERASEPAGE  = 0x4001E508
NVMC_ERASEALL   = 0x4001E50C
NVMC_ERASEUIR   = 0x4001E514

FICR_CODEPAGESIZE   = 0x10000010
FICR_CODESIZE       = 0x10000014

UICR_BASE           = 0x10001000
UICR_SIZE           = 0x100
UICR_CLENR0         = 0x10001000

def getAdapter():
    '''
    Get a CMSIS DAP debug adapter
    '''
    interfaces = INTERFACE[usb_backend].getAllConnectedInterface(VID, PID)
    if interfaces == None:
        print "Not find a mbed interface"
        sys.exit(1)

    first_interface = interfaces[0]
    adapter = MbedBoard("target_lpc1768", "flash_lpc1768", first_interface)
    adapter.init()
    return adapter
    
def hex2bin(hexfile, cr0, uicr):
    subprocess.check_call(["arm-none-eabi-objcopy", "-Iihex", "-Obinary", "--remove-section", ".sec3", hexfile, cr0])
    subprocess.check_call(["arm-none-eabi-objcopy", "-Iihex", "-Obinary", "--only-section", ".sec3", hexfile, uicr])
    
def getSecNum(addr):
    n = addr >> 10;

    return n
    
def flashUICR(target, path_file):
    """
    Write User Information Configuration Registers
    """
    f = open(path_file, "rb")
    start = time()
    
    target.halt()

    logging.info("Erase UICR")
    while target.readMemory(NVMC_READY) == 0:
        pass
    target.writeMemory(NVMC_CONFIG, 2)
    target.writeMemory(NVMC_ERASEUIR, 1)
    while target.readMemory(NVMC_READY) == 0:
        pass

    logging.info("Prepare to write UICR")
    target.writeMemory(NVMC_CONFIG, 1)
    while target.readMemory(NVMC_READY) == 0:
        pass
    
    address = UICR_BASE
    size = UICR_SIZE
    nb_bytes = 0    
    try:
        bytes_read = f.read(size)
        while bytes_read:
            bytes_read = unpack(str(len(bytes_read)) + 'B', bytes_read)
            nb_bytes += len(bytes_read)
            target.writeBlockMemoryUnaligned8(address, bytes_read)
            
            logging.info("Write: 0x%X - %d", address, len(bytes_read))
            
            address += len(bytes_read)
            bytes_read = f.read(size)
    finally:
        f.close()
        
    target.writeMemory(NVMC_CONFIG, 0)
    while target.readMemory(NVMC_READY) == 0:
        pass
        
    end = time()
    logging.info("%f kbytes flashed in %f seconds ===> %f kbytes/s" %(nb_bytes/1000, end-start, nb_bytes/(1000*(end - start))))
    
    # reset to take effect
    target.reset()
    
    
    

def flashCR0(target, path_file):
    """
    Write code region 0
    """
    f = open(path_file, "rb")
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
    
    address = 0x0
    size = 1024
    nb_bytes = 0    
    try:
        bytes_read = f.read(size)
        while bytes_read:
            bytes_read = unpack(str(len(bytes_read)) + 'B', bytes_read)
            nb_bytes += len(bytes_read)
            target.writeBlockMemoryUnaligned8(address, bytes_read)
            
            # Verify
            bytes_write = target.readBlockMemoryUnaligned8(address, len(bytes_read))
            for i in range(len(bytes_write)):
                if (bytes_read[i] != bytes_write[i]):
                    logging.error("Write: error@0x%X - 0x%X | 0x%X", address, bytes_read[i], bytes_write[i])
                    raise Exception("Verify Error") 
            
            
            logging.info("Write: 0x%X - %d", address, len(bytes_read))
            
            address += len(bytes_read)
            bytes_read = f.read(size)
    finally:
        f.close()
        
    target.writeMemory(NVMC_CONFIG, 0)
    while target.readMemory(NVMC_READY) == 0:
        pass
        
    end = time()
    logging.info("%f kbytes flashed in %f seconds ===> %f kbytes/s" %(nb_bytes/1000, end-start, nb_bytes/(1000*(end - start))))


def flashCR1(flash, path_file):
    """
    Write code region 1
    """
    f = open(path_file, "rb")
    start = time()
    
    target.halt()

    while target.readMemory(NVMC_READY) == 0:
        pass
       
    logging.info("Prepare to write")
    target.writeMemory(NVMC_CONFIG, 1)
    while target.readMemory(NVMC_READY) == 0:
        pass
    
    address = 0x14000
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
    logging.info("%f kbytes flashed in %f seconds ===> %f kbytes/s" %(nb_bytes/1000, end-start, nb_bytes/(1000*(end - start))))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="flash nrf51822")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-s", "--softdevice", help="the hex file of softdevice")
    parser.add_argument("-a", "--application", help="the binary of application")
    args = parser.parse_args()
    
    adapter = getAdapter()
    target = adapter.target

    if args.softdevice:
        hex2bin(args.softdevice, "cr0.bin", "uicr.bin")
        flashCR0(target, "cr0.bin")
        flashUICR(target, "uicr.bin")
        
    if args.application:
        flashCR1(target, args.application)
        
    target.reset()
        
        
