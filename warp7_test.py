"""
Test running arbitrary code on the NXP i.MX7.

Because I only have two hands, and they have a stupid debugging connector...
"""
import sys
import time
import pyOCD
from pyOCD.board.mbed_board import MbedBoard
from pyOCD.coresight.dap import DP_REG
from pyOCD.coresight.cortex_a import CortexA

scratch_addr = 0x80000000 # start of DRAM
program = [
    0xe3a00000, # mov r0, #0
    0xe3a01001, # mov r1, #1
    0xe3a02002, # mov r2, #2
    0xe3a03003, # mov r3, #3
    0xe3a04004, # mov r4, #4
    0xe3a05005, # mov r5, #5
    0xe3a06006, # mov r6, #6
    0xe3a07007, # mov r7, #7
    0xe3a08008, # mov r8, #8
    0xe3a09009, # mov r9, #9
    0xe3a0a00a, # mov r10, #10
    0xe3a0b00b, # mov r11, #11
    0xe3a0c00c, # mov r12, #12
    0xe3a0d00d, # mov r13, #13
    0xe3a0e00e, # mov r14, #14
    0xe120027a  # bkpt #42
]

if __name__ == '__main__':
    board = MbedBoard.chooseBoard()

    board.target.setAutoUnlock(False)
    board.target.setHaltOnConnect(False)

    board.init()

    board.target.halt()
    addr = scratch_addr
    for val in program:
        board.target.write32(addr, val)
        addr += 4
 
    board.target.dp.write_reg(DP_REG['SELECT'], 0)

    board.target.writeCoreRegister('r0', 0x0)
    # xpsr <- r0
    board.target.cores[0].executeInstruction(0xE12CF000)

    # disable interrupts
    board.target.cores[0].executeInstruction(0xF10C0080)

    # i.MX 7 internal RAM
    addr = scratch_addr
    board.target.writeCoreRegister('r1', addr)

    # mov pc, r1
    board.target.cores[0].executeInstruction(0xE1A00000 | (15 << 12) | 1)

    # swd_restart_req
    dscr = board.target.cores[0].read32(board.target.cores[0].DEBUG_BASE + CortexA.DSCR)
    dscr &= ~0x00002000

    board.target.cores[0].write32(board.target.cores[0].DEBUG_BASE + CortexA.DSCR, dscr)

    for i in range(100):
        dscr = board.target.cores[0].read32(board.target.cores[0].DEBUG_BASE + CortexA.DSCR)

        if (dscr & 0x010001C0) == 0x01000000:
            break
        print('dscr & 0x010001c0 = %x' % (dscr & 0x010001C0))
        time.sleep(1)
    else:
        print(':\'(')
        sys.exit(1)
    
    board.target.cores[0].write32(board.target.cores[0].DEBUG_BASE + CortexA.DRCR, 0x2)

    for i in range(100):
        dscr = board.target.cores[0].read32(board.target.cores[0].DEBUG_BASE + CortexA.DSCR)

        if (dscr & 0x2) == 0x2:
            break
        print('dscr = %x' % dscr)
        time.sleep(1)
    else:
        print(':\'[')
        sys.exit(1)

    ctrl_stat = board.target.cores[0].dp.read_reg(DP_REG['CTRL_STAT'])

    if not ctrl_stat:
        print('booo 1')
    elif ctrl_stat & (0x20 | 0x80):
        print('booo 2')
    else:
        print('yay')

    # for i in range(16):
    #     reg = board.target.readCoreRegister('r%d' % i)
    #     print('r%d = %x (%d)' % (i, reg, reg))
    

    # board.target.cores[0].setBreakpoint(0x00910010)

    # board.target.resume()
    # board.target.halt()


    print('waiting for halt')
    time.sleep(5)
    # just in case
    board.target.halt()

    for i in range(16):
        reg = board.target.readCoreRegister('r%d' % i)
        print('r%d = %x (%d)' % (i, reg, reg))
