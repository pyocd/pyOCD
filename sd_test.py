
import sys
import time
import pyOCD
from pyOCD.board.mbed_board import MbedBoard
from pyOCD.coresight.dap import DP_REG
from pyOCD.coresight.cortex_a import CortexA

sd_base = 0x30B60000

def pre_cmd(board):
    # clear interrupt flags
    board.target.write32(sd_base + 0x30, 0xffffffff)

    # read sd card status
    status = board.target.read32(sd_base + 0x24)

    print('status: %x' % status)

    print('waiting for command inhibit to be disabled')

    while ((status & 1) or (status & 2)):
        # command inhibit
        status = board.target.read32(sd_base + 0x24)

def cmd(board, index, arg):
    # clear interrupt flags
    board.target.write32(sd_base + 0x30, 0xffffffff)

    # read sd card status
    status = board.target.read32(sd_base + 0x24)

    print('status: %x' % status)

    print('waiting for command inhibit to be disabled')

    while ((status & 1) or (status & 2)):
        # command inhibit
        status = board.target.read32(sd_base + 0x24)

    print ('waiting for data line to be idle')

    while (status & 4):
        # data line active
        status = board.target.read32(sd_base + 0x24)

    # write watermark level
    wml = board.target.read32(sd_base + 0x44)
    wml &= ~0xFF
    wml |= 1
    board.target.write32(sd_base + 0x44, wml)

    # write block attr (1 block, 4 bytes)
    board.target.write32(sd_base + 0x4, (1 << 16) | 0x4)

    # disable all the interrupts
    board.target.write32(sd_base + 0x38, 0)

    # enable all interrupt status bits
    board.target.write32(sd_base + 0x34, 0x157F51FF)
    
    cmd = (index & 0x3f) << 24
    cmd |= 1 << 21
    cmd |= (1 << 19) | (1 << 20) | (1 << 17)

    board.target.write32(sd_base + 0x8, arg)
    board.target.write32(sd_base + 0xc, cmd)

def wait_response(board):
    irq_status = board.target.read32(sd_base + 0x30)
    while not(irq_status & 1):
        irq_status = board.target.read32(sd_base + 0x30)
    

    board.target.write32(sd_base + 0x30, 0xffffffff)

    print('int status = %x' % irq_status)

def send_command_simple(device, index, type, arg, response_type):
    pre_cmd(device)

    xfer_type = (index & 0x3f) << 24

    if response_type == 'R3':
        xfer_type |= 2 << 16
    elif response_type == 'R1' or response_type == 'R1b':
        xfer_type |= 2 << 16
        xfer_type |= 1 << 20
        xfer_type |= 1 << 19

        if response_type == 'R1b':
            xfer_type |= 3 << 16
    elif response_type == 'R2':
        xfer_type |= 1 << 16
        xfer_type |= 1 << 19
    
    # if type == 'infinite transfer':
    # xfer_type |= 
    
    board.target.write32(sd_base + 0x8, arg)
    board.target.write32(sd_base + 0xC, xfer_type)

    # TODO: when moving this to C, wait for the command to complete

    if response_type in ('R3', 'R1', 'R1b'):
        # read CMDRSP0
        return board.target.read32(sd_base + 0x10)
    elif response_type == 'R2':
        r0 = board.target.read32(sd_base + 0x10)
        r1 = board.target.read32(sd_base + 0x14)
        r2 = board.target.read32(sd_base + 0x18)
        r3 = board.target.read32(sd_base + 0x1c)

        return ((r3 & 0xffffff) << 96) | (r2 << 64) | (r1 << 32) | r0

def cmd1(device):
    return send_command_simple(device, 1, None, 0, 'R3')

def cmd0(device):
    return send_command_simple(device, 0, None, 0, None)

def cmd2(device):
    return send_command_simple(device, 2, None, 0, 'R2')

def cmd3(device, rca):
    return send_command_simple(device, 3, None, rca, 'R1')

def cmd7(device, rca):
    return send_command_simple(device, 7, None, rca, 'R1b')

def cmd16(device, blk_size):
    return send_command_simple(device, 16, None, blk_size, 'R1')

def cmd17(device, addr):
    return send_command_simple(device, 17, None, addr, 'R1')

if __name__ == '__main__':
    board = MbedBoard.chooseBoard()

    board.target.setAutoUnlock(False)
    board.target.setHaltOnConnect(False)

    board.init()

    board.target.halt()

    # disable interrupts
    board.target.cores[0].executeInstruction(0xF10C0080)

    # disable data cache
    for i in [0xEE111F10, 0xE3C11004, 0xF57FF04F, 0xEE011F10]:
        board.target.cores[0].executeInstruction(i)
    
    # reset ALL
    board.target.write32(sd_base + 0x2c, 1 << 24)

    status = board.target.read32(sd_base + 0x2c)

    while status & (1 << 24):
        status = board.target.read32(sd_base + 0x2c)
    
    print("SD controller reset.")

    r0 = board.target.read32(sd_base + 0x10)
    r1 = board.target.read32(sd_base + 0x14)
    r2 = board.target.read32(sd_base + 0x18)
    r3 = board.target.read32(sd_base + 0x1c)

    print(hex(((r3 & 0xffffff) << 96) | (r2 << 64) | (r1 << 32) | r0))

    board.target.write32(sd_base + 0xc4, 0)
    board.target.write32(sd_base + 0x48, 0)
    board.target.write32(sd_base + 0x68, 0)
    board.target.write32(sd_base + 0xC0, 0x20007809)
    board.target.write32(sd_base + 0x60, 0)

    vendor = board.target.read32(sd_base + 0xC0)
    # board.target.write32(sd_base + 0xC0, vendor & ~((1 << 12) | (1 << 11)))

    # board.target.write32(sd_base + 0x28, 0x00000020)

    # lets try and read a block from the sd card...

    cmd0(board)
    ocr = cmd1(board)

    # print(hex(ocr))

    cci = cmd2(board)

    print(hex(cci))

    if not (ocr & (1 << 31)):
        print('card not powered up?')

    stat = cmd3(board, 1)

    # print(hex(stat))

    stat = cmd7(board, 1 << 16)

    board.target.write32(sd_base + 0x4, 40 | (0x1 << 16))
    board.target.write32(sd_base + 0x44, 4)

    cmd16(board, 40)
    cmd17(board, 0x0)

    pres_state = board.target.read32(sd_base + 0x24)

    if not (pres_state & (1 << 11)):
        print('No read data available; trying anyway')
        print(hex(pres_state))

        data = board.target.read32(sd_base + 0x20)
        print(data)

        print('ehhh')

        while not (pres_state & (1 << 11)):
            pres_state = board.target.read32(sd_base + 0x24)

    print('read data available')

    while pres_state & (1 << 11):
        # read data availale 

        data = board.target.read32(sd_base + 0x20)
        print(data)
        pres_state = board.target.read32(sd_base + 0x24)
