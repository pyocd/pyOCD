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
import sys
import logging

import os
import pyOCD
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
ACTION_RESET = 6
ACTION_READ = 7
ACTION_WRITE = 8
ACTION_GO = 9
ACTION_HALT = 10
ACTION_DISASM = 11

LEVELS={'debug':logging.DEBUG,
        'info':logging.INFO,
        'warning':logging.WARNING,
        'error':logging.ERROR,
        'critical':logging.CRITICAL
        }

USAGE = """
The --read and --disasm command take an optional byte count using the --length
option. The length defaults to 4 bytes if not specified. The --center option will
shift the disassembly so that the specified address is centered in the output.
--read and --write will make use of the --width option in different ways. --read
uses the width only when printing the hex dump. For --write, the width determines
the word size of the data positional arguments. For if -W32 is specified, the data
arguments are each a 32-bit word, and the total number of bytes written will be the
number of data arguments times 4.
"""

def dumpHexData(data, startAddress=0, width=8):
    i = 0
    while i < len(data):
        print "%08x: " % (startAddress + i),

        while i < len(data):
            d = data[i]
            i += 1
            if width==8:
                print "%02x" % d,
                if i % 4 == 0:
                    print "",
                if i % 16 == 0:
                    break
            elif width==16:
                print "%04x" % d,
                if i % 8 == 0:
                    break
            elif width==32:
                print "%08x" % d,
                if i % 4 == 0:
                    break
        print

class ToolError(Exception):
    pass

class PyOCDTool(object):
    def __init__(self):
        self.board = None
        self.exitCode = 0
        self.action_handlers = {
                ACTION_LIST : self.handle_list,
                ACTION_ERASE : self.handle_erase,
                ACTION_UNLOCK : self.handle_unlock,
                ACTION_INFO : self.handle_info,
                ACTION_RESET : self.handle_reset,
                ACTION_READ : self.handle_read,
                ACTION_WRITE : self.handle_write,
                ACTION_GO : self.handle_go,
                ACTION_HALT : self.handle_halt,
                ACTION_DISASM : self.handle_disasm
            }

    def get_args(self):
        debug_levels = LEVELS.keys()

        parser = argparse.ArgumentParser(description='Target inspection utility', epilog=USAGE)
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
        parser.add_argument("-H", "--halt", action="store_true", help="Halt core. Can be used alone or with --reset.")
        parser.add_argument("-g", "--go", action="store_const", dest='action', const=ACTION_GO, help="Resume execution of code.")
        parser.add_argument('-D', "--disasm", action='store', metavar='ADDR', help="Disassemble code at address.")
        parser.add_argument("-C", "--center", action="store_true", help="Center the disassembly around the provided address.")
        parser.add_argument("-r", "--read", action="store", metavar='ADDR', help="Read and print data.")
        parser.add_argument('-n', "--len", "--length", action="store", metavar='LENGTH', default="4", help="Number of bytes to read or disassemble. (Default 4.)")
        parser.add_argument("-w", "--write", action="store", metavar='ADDR', help="Write data to memory.")
        parser.add_argument("-W", "--width", action="store", choices=[8, 16, 32], type=int, default=8, help="Word size for read and write. (Default 8.)")
        parser.add_argument('-k', "--clock", metavar='KHZ', default=0, type=int, help="Set SWD speed in kHz.")
        parser.add_argument('-b', "--board", action='store', metavar='ID', help="Use the specified board. ")
        parser.add_argument('-t', "--target", action='store', metavar='TARGET', help="Override target.")
        parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='warning', help="Set the level of system logging output. Supported choices are: "+", ".join(debug_levels), metavar="LEVEL")
        parser.add_argument("data", nargs='*', help="Data to write using the --write option")
        return parser.parse_args()

    def determine_action(self, args):
        # Determine action.
        if args.read:
            args.action = ACTION_READ
        elif args.write:
            args.action = ACTION_WRITE
        elif args.disasm:
            args.action = ACTION_DISASM
        elif args.halt and not args.action:
            args.action = ACTION_HALT

        # Default to list mode if no other action was specified.
        if args.action == None:
            args.action = ACTION_LIST

        return args

    def configure_logging(self):
        level = LEVELS.get(self.args.debug_level, logging.WARNING)
        logging.basicConfig(level=level)

    def run(self):
        try:
            # Read command-line arguments.
            args = self.get_args()
            self.args = self.determine_action(args)

            # Set logging level
            self.configure_logging()

            # Print a list of all connected boards.
            if self.args.action == ACTION_LIST:
                self.handle_list()
                sys.exit(0)

            self.board = MbedBoard.chooseBoard(board_id=self.args.board, target_override=self.args.target, init_board=False)
            self.board.target.setAutoUnlock(False)
            self.board.target.setHaltOnConnect(False)
            try:
                self.board.init()
            except Exception, e:
                print "Exception while initing board:", e

            self.target = self.board.target
            self.transport = self.board.transport
            self.flash = self.board.flash

            # Set specified SWD clock.
            if self.args.clock > 0:
                print "Setting SWD clock to %d kHz" % self.args.clock
                self.transport.setClock(self.args.clock * 1000)

            # Handle reset action first
            if self.args.action == ACTION_RESET:
                self.handle_reset()
                sys.exit(0)

            # Halt if requested.
            if self.args.halt:
                self.target.halt()

                status = self.target.getState()
                if status != pyOCD.target.cortex_m.TARGET_HALTED:
                    print "Failed to halt device"
                else:
                    print "Successfully halted device"

            # Handle a device with flash security enabled.
            self.didErase = False
            if self.target.isLocked() and self.args.action != ACTION_UNLOCK:
                print "Target is locked, cannot complete operation. Use --unlock to mass erase and unlock."

            # Invoke action handler.
            self.action_handlers[self.args.action]()

        except pyOCD.transport.transport.TransferError:
            print "Error: transfer failed"
            self.exitCode = 2
        except ToolError, e:
            print "Error:", e
            self.exitCode = 1
        finally:
            if self.board != None:
                # Pass false to prevent target resume.
                self.board.uninit(False)

        return self.exitCode

    def handle_list(self):
        MbedBoard.listConnectedBoards()

    def handle_info(self):
        print "Target:         %s" % self.target.part_number
        print "CPU type:       %s" % pyOCD.target.cortex_m.CORE_TYPE_NAME[self.target.core_type]
        print "Unique ID:      %s" % self.board.getUniqueID()
        print "Core ID:        0x%08x" % self.target.readIDCode()
        if isinstance(self.target, pyOCD.target.target_kinetis.Kinetis):
            print "MDM-AP Control: 0x%08x" % self.transport.readAP(target_kinetis.MDM_CTRL)
            print "MDM-AP Status:  0x%08x" % self.transport.readAP(target_kinetis.MDM_STATUS)
        status = self.target.getState()
        if status == pyOCD.target.cortex_m.TARGET_HALTED:
            print "Core status:    Halted"
            self.dump_registers()
        elif status == pyOCD.target.cortex_m.TARGET_RUNNING:
            print "Core status:    Running"

    def handle_reset(self):
        print "Resetting target"
        if self.args.halt:
            self.target.resetStopOnReset()

            status = self.target.getState()
            if status != pyOCD.target.cortex_m.TARGET_HALTED:
                print "Failed to halt device on reset"
            else:
                print "Successfully halted device on reset"
        else:
            self.target.reset()

    def handle_disasm(self):
        addr = self.convert_value(self.args.disasm)
        count = self.convert_value(self.args.len)

        # Since we're disassembling, make sure the Thumb bit is cleared.
        addr &= ~1

        if self.args.center:
            addr -= count // 2

        if self.args.width == 8:
            data = self.target.readBlockMemoryUnaligned8(addr, count)
            byteData = data
        elif self.args.width == 16:
            byteData = self.target.readBlockMemoryUnaligned8(addr, count)
            data = pyOCD.utility.conversion.byte2half(byteData)
        elif self.args.width == 32:
            byteData = self.target.readBlockMemoryUnaligned8(addr, count)
            data = pyOCD.utility.conversion.byte2word(byteData)

        # Print disasm of data.
        self.disasm(str(bytearray(byteData)), addr)

    def handle_read(self):
        addr = self.convert_value(self.args.read)
        count = self.convert_value(self.args.len)

        if self.args.width == 8:
            data = self.target.readBlockMemoryUnaligned8(addr, count)
            byteData = data
        elif self.args.width == 16:
            byteData = self.target.readBlockMemoryUnaligned8(addr, count)
            data = pyOCD.utility.conversion.byte2half(byteData)
        elif self.args.width == 32:
            byteData = self.target.readBlockMemoryUnaligned8(addr, count)
            data = pyOCD.utility.conversion.byte2word(byteData)

        # Print hex dump of output.
        dumpHexData(data, addr, width=self.args.width)

    def handle_write(self):
        addr = self.convert_value(self.args.write)
        data = [self.convert_value(d) for d in self.args.data]

        if self.args.width == 8:
            pass
        elif self.args.width == 16:
            data = pyOCD.utility.conversion.half2byte(data)
        elif self.args.width == 32:
            data = pyOCD.utility.conversion.word2byte(data)

        self.target.writeBlockMemoryUnaligned8(addr, data)

    def handle_erase(self):
        # TODO: change to be a complete chip erase that doesn't write FSEC to 0xfe.
        if not self.didErase:
            self.target.massErase()

    def handle_unlock(self):
        # Currently the same as erase.
        if not self.didErase:
            self.target.massErase()

    def handle_go(self):
        self.target.resume()
        status = self.target.getState()
        if status == pyOCD.target.cortex_m.TARGET_RUNNING:
            print "Successfully resumed device"
        else:
            print "Failed to resume device"

    def handle_halt(self):
        pass

    ## @brief Convert an argument to a 32-bit integer.
    #
    # Handles the usual decimal, binary, and hex numbers with the appropriate prefix.
    # Also recognizes register names and address dereferencing. Dereferencing using the
    # ARM assembler syntax. To dereference, put the value in brackets, i.e. '[r0]' or
    # '[0x1040]'. You can also use put an offset in the brackets after a comma, such as
    # '[r3,8]'. The offset can be positive or negative, and any supported base.
    def convert_value(self, arg):
        arg = arg.lower()
        deref = (arg[0] == '[')
        if deref:
            arg = arg[1:-1]
            offset = 0
            if ',' in arg:
                arg, offset = arg.split(',')
                arg = arg.strip()
                offset = int(offset.strip(), base=0)

        if arg in pyOCD.target.cortex_m.CORE_REGISTER:
#             arg = arg[1:]
#             if arg not in pyOCD.target.cortex_m.CORE_REGISTER:
#                 raise ToolError("Unknown register name '%s'" % arg)
            value = self.target.readCoreRegister(arg)
            print "%s = 0x%08x" % (arg, value)
        else:
            value = int(arg, base=0)

        if deref:
            value = pyOCD.utility.conversion.byte2word(self.target.readBlockMemoryUnaligned8(value + offset, 4))[0]
            print "[%s,%d] = 0x%08x" % (arg, offset, value)

        return value

    def dump_registers(self):
        # Registers organized into columns for display.
        regs = ['r0', 'r6', 'r12',
                'r1', 'r7', 'sp',
                'r2', 'r8', 'lr',
                'r3', 'r9', 'pc',
                'r4', 'r10', 'xpsr',
                'r5', 'r11', 'primask']

        for i, reg in enumerate(regs):
            regValue = self.target.readCoreRegister(reg)
            print "{:>8} {:#010x} ".format(reg + ':', regValue),
            if i % 3 == 2:
                print

    def print_memory_map(self):
        print "Region          Start         End           Blocksize"
        for region in self.target.getMemoryMap():
            print "{:<15} {:#010x}    {:#010x}    {}".format(region.name, region.start, region.end, region.blocksize if region.isFlash else '-')

    def disasm(self, code, startAddr):
        if not isCapstoneAvailable:
            print "Warning: Disassembly is not available because the Capstone library is not installed"
            return

        pc = self.target.readCoreRegister('pc') & ~1
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

        addrLine = 0
        text = ''
        for i in md.disasm(code, startAddr):
            hexBytes = ''
            for b in i.bytes:
                hexBytes += '%02x' % b
            pc_marker = '*' if (pc==i.address) else ' '
            text += "{addr:#010x}:{pc_marker} {bytes:<10}{mnemonic:<8}{args}\n".format(addr=i.address, pc_marker=pc_marker, bytes=hexBytes, mnemonic=i.mnemonic, args=i.op_str)

        print text


def main():
    sys.exit(PyOCDTool().run())


if __name__ == '__main__':
    main()
