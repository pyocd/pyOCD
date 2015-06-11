#!/usr/bin/env python
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

import argparse
import logging
import os
import sys

import pyOCD
from pyOCD import __version__
from pyOCD.board import MbedBoard
from pyOCD.target import target_kinetis

# Make disasm optional.
try:
    import capstone
    isCapstoneAvailable = True
except ImportError:
    isCapstoneAvailable = False

# Command action constants.
ACTION_LIST = 1
ACTION_ERASE = 2
ACTION_UNLOCK = 3
ACTION_INFO = 4
ACTION_PROGRAM = 5
ACTION_RESET = 6
ACTION_READ = 7
ACTION_WRITE = 8
ACTION_GO = 9


def dumpHexData(data, startAddress=0, width=8):
    i = 0
    while i < len(data):
        print "%08x: " % (startAddress + i),

        while i < len(data):
            d = data[i]
            i += 1
            if width == 8:
                print "%02x" % d,
                if i % 4 == 0:
                    print "",
                if i % 16 == 0:
                    break
            elif width == 16:
                print "%04x" % d,
                if i % 8 == 0:
                    break
            elif width == 32:
                print "%08x" % d,
                if i % 4 == 0:
                    break
        print


class ToolError(Exception):
    pass


class PyOCDTool(object):
    def __init__(self):
        # logging.basicConfig(level=logging.INFO)
        pass

    def get_args(self):
        parser = argparse.ArgumentParser(description='Flash utility')
        parser.add_argument('--version', action='version', version=__version__)
        parser.add_argument("-l", "--list", action="store_const", dest='action', const=ACTION_LIST,
                            help="List available boards.")
        parser.add_argument("-e", "--erase", action="store_const", dest='action', const=ACTION_ERASE,
                            help="Erase all flash.")
        parser.add_argument("-u", "--unlock", action="store_const", dest='action', const=ACTION_UNLOCK,
                            help="Unlock device.")
        parser.add_argument("-i", "--info", action="store_const", dest='action', const=ACTION_INFO,
                            help="Print device info and status.")
        parser.add_argument("-R", "--reset", action="store_const", dest='action', const=ACTION_RESET,
                            help="Reset target device.")
        parser.add_argument("-H", "--halt", action="store_true", default=False, help="Halt core on reset.")
        parser.add_argument("-g", "--go", action="store_const", dest='action', const=ACTION_GO,
                            help="Resume execution of code.")
        parser.add_argument("-r", "--read", action="store", metavar='ADDR', help="Read and print data.")
        parser.add_argument('-n', "--len", "--length", action="store", metavar='LENGTH', default="4",
                            help="Length of data to read.")
        parser.add_argument("-w", "--write", action="store", metavar='ADDR', help="Write data to memory.")
        parser.add_argument("-W", "--width", action="store", choices=[8, 16, 32], type=int, default=8,
                            help="Word size for read and write.")
        parser.add_argument('-f', "--flash", dest="file", metavar='FILE', help="Program a binary file into flash.")
        parser.add_argument('-k', "--clock", metavar='KHZ', default=0, type=int, help="Set SWD speed in kHz.")
        parser.add_argument('-v', "--verbose", action='store_true', default=False, help="Enable verbose logging.")
        parser.add_argument('-d', "--disasm", action='store_true', default=False, help="Print disassembly.")
        parser.add_argument('-b', "--board", action='store', metavar='ID', help="Use the specified board. ")
        parser.add_argument('-t', "--target", action='store', metavar='TARGET', help="Override target.")
        parser.add_argument("data", nargs='*', help="Data to write using the --write option")
        args = parser.parse_args()

        # Set read/write actions.
        if args.read:
            args.action = ACTION_READ
            args.read = int(args.read, base=0)
            args.len = int(args.len, base=0)
        elif args.write:
            args.action = ACTION_WRITE
            args.write = int(args.write, base=0)
            args.data = [int(d, base=0) for d in args.data]

        # Default to list mode if no other action was specified.
        if args.action == None and args.file == None:
            args.action = ACTION_LIST
        elif args.file:
            args.action = ACTION_PROGRAM

        return args

    def run(self):
        board = None
        exitCode = 0

        try:
            # Read command-line arguments.
            args = self.get_args()

            if args.verbose:
                logging.basicConfig(level=logging.INFO)

            # Print a list of all connected boards.
            if args.action == ACTION_LIST:
                MbedBoard.listConnectedBoards()
                sys.exit(0)

            board = MbedBoard.chooseBoard(board_id=args.board, target_override=args.target, init_board=False)
            board.target.setAutoUnlock(False)
            try:
                board.init()
            except Exception, e:
                print "Exception:", e

            target = board.target
            transport = board.transport
            flash = board.flash

            # Set specified SWD clock.
            if args.clock > 0:
                print "Setting SWD clock to %d kHz" % args.clock
                transport.setClock(args.clock * 1000)

            # Handle reset action first
            if args.action == ACTION_RESET:
                print "Resetting target"
                target.reset()
                sys.exit(0)

            # Handle a device with flash security enabled.
            didErase = False
            if target.isLocked() and args.action != ACTION_UNLOCK:
                print "Target is locked, cannot complete operation. Use --unlock to mass erase and unlock."

            # Handle actions.
            if args.action == ACTION_INFO:
                print "Unique ID: %s" % board.getUniqueID()
                print "Core ID:   0x%08x" % target.readIDCode()
                if isinstance(target, pyOCD.target.target_kinetis.Kinetis):
                    print "MDM-AP Control: 0x%08x" % transport.readAP(target_kinetis.MDM_CTRL)
                    print "MDM-AP Status:  0x%08x" % transport.readAP(target_kinetis.MDM_STATUS)
                status = target.getState()
                if status == pyOCD.target.cortex_m.TARGET_HALTED:
                    print "Core status:    Halted"
                    self.dumpRegisters(target)
                elif status == pyOCD.target.cortex_m.TARGET_RUNNING:
                    print "Core status:    Running"
            elif args.action == ACTION_READ:
                if args.width == 8:
                    data = target.readBlockMemoryUnaligned8(args.read, args.len)
                elif args.width == 16:
                    if args.read & 0x1:
                        raise ToolError("read address 0x%08x is not 16-bit aligned" % args.read)

                    byteData = target.readBlockMemoryUnaligned8(args.read, args.len * 2)
                    i = 0
                    data = []
                    while i < len(byteData):
                        data.append(byteData[i] | (byteData[i + 1] << 8))
                        i += 2
                elif args.width == 32:
                    if args.read & 0x3:
                        raise ToolError("read address 0x%08x is not 32-bit aligned" % args.read)

                    data = target.readBlockMemoryAligned32(args.read, args.len / 4)

                # Either print disasm or hex dump of output
                if args.disasm:
                    if args.width == 8:
                        code = bytearray(data)
                    elif args.width == 16:
                        code = bytearray(byteData)
                    elif args.width == 32:
                        byteData = []
                        for v in data:
                            byteData.extend([(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff])
                        code = bytearray(byteData)

                    self.disasm(str(code), args.read)
                else:
                    dumpHexData(data, args.read, width=args.width)
            elif args.action == ACTION_WRITE:
                if args.width == 8:
                    target.writeBlockMemoryUnaligned8(args.write, args.data)
                elif args.width == 16:
                    if args.write & 0x1:
                        raise ToolError("write address 0x%08x is not 16-bit aligned" % args.write)

                    print "16-bit writes are currently not supported"
                elif args.width == 32:
                    if args.write & 0x3:
                        raise ToolError("write address 0x%08x is not 32-bit aligned" % args.write)

                    target.writeBlockMemoryAligned32(args.write, args.data)
            elif args.action == ACTION_PROGRAM:
                if not os.path.exists(args.file):
                    raise ToolError("%s does not exist!" % args.file)

                print "Programming %s into flash..." % args.file
                flash.flashBinary(args.file)
            elif args.action == ACTION_ERASE:
                # TODO: change to be a complete chip erase that doesn't write FSEC to 0xfe.
                if not didErase:
                    target.massErase()
            elif args.action == ACTION_UNLOCK:
                # Currently the same as erase.
                if not didErase:
                    target.massErase()
            elif args.action == ACTION_GO:
                target.resume()

        except ToolError, e:
            print "Error:", e
            exitCode = 1
        finally:
            if board != None:
                # Pass false to prevent target resume.
                board.uninit(False)

        return exitCode

    def dumpRegisters(self, target):
        regs = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc']

        for reg in regs:
            regValue = target.readCoreRegister(reg)
            print "%s: 0x%08x" % (reg, regValue)

    def disasm(self, code, startAddr):
        if not isCapstoneAvailable:
            print "Warning: Disassembly is not available because the Capstone library is not installed"
            return

        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

        addrLine = 0
        text = ''
        for i in md.disasm(code, startAddr):
            hexBytes = ''
            for b in i.bytes:
                hexBytes += '%02x' % b

            def spacing(s, w):
                return ' ' * (w - len(s))

            text += "0x%08x:  %s%s%s%s%s\n" % (
            i.address, hexBytes, spacing(hexBytes, 10), i.mnemonic, spacing(i.mnemonic, 8), i.op_str)

        print text


def main():
    sys.exit(PyOCDTool().run())


if __name__ == '__main__':
    main()
