#!/usr/bin/env python
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

from __future__ import print_function
import argparse
import os
import sys
import logging
import itertools
from struct import unpack

try:
    from intelhex import IntelHex
    intelhex_available = True
except ImportError:
    intelhex_available = False

from .. import __version__
from .. import target
from ..board.mbed_board import MbedBoard
from ..pyDAPAccess import DAPAccess
from ..utility.progress import print_progress

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

board = None

supported_formats = ['bin', 'hex']
supported_targets = list(target.TARGET.keys())
supported_targets.remove('cortex_m')  # No generic programming

debug_levels = list(LEVELS.keys())

def int_base_0(x):
    return int(x, base=0)

epi = """--chip_erase and --sector_erase can be used alone as individual commands, or they
can be used in conjunction with flashing a binary or hex file. For the former, only the erase option
will be performed. With a file, the erase options specify whether to erase the entire chip before
flashing the file, or just to erase only those sectors occupied by the file. For a standalone
sector erase, the --address and --count options are used to specify the start address of the
sector to erase and the number of sectors to erase.
"""

# Keep args in snyc with gdb_server.py when possible
parser = argparse.ArgumentParser(description='Flash utility', epilog=epi)
parser.add_argument("file", nargs='?', default=None, help="File to program")
parser.add_argument("format", nargs='?', choices=supported_formats, default=None, help="File format. Default is to use the file extension (.bin or .hex)")
parser.add_argument('--version', action='version', version=__version__)
# reserved: "-p", "--port"
# reserved: "-c", "--cmd-port"
parser.add_argument("-b", "--board", dest="board_id", default=None,
                    help="Connect to board by board ID. Use -l to list all connected boards. Only a unique part of the board ID needs to be provided.")
parser.add_argument("-l", "--list", action="store_true", dest="list_all", default=False,
                    help="List all connected boards.")
parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='info',
                    help="Set the level of system logging output. Supported choices are: " + ", ".join(debug_levels),
                    metavar="LEVEL")
parser.add_argument("-t", "--target", dest="target_override", choices=supported_targets, default=None,
                    help="Override target to debug.  Supported targets are: " + ", ".join(supported_targets),
                    metavar="TARGET")
# reserved: "-n", "--nobreak"
# reserved: "-r", "--reset-break"
# reserved: "-s", "--step-int"
parser.add_argument("-f", "--frequency", dest="frequency", default=1000000, type=int,
                    help="Set the SWD clock frequency in Hz.")
# reserved: "-o", "--persist"
# reserved: "-k", "--soft-bkpt-as-hard"
group = parser.add_mutually_exclusive_group()
group.add_argument("-ce", "--chip_erase", action="store_true", help="Use chip erase when programming.")
group.add_argument("-se", "--sector_erase", action="store_true", help="Use sector erase when programming.")
parser.add_argument("-u", "--unlock", action="store_true", default=False, help="Unlock the device.")
parser.add_argument("-a", "--address", default=None, type=int_base_0,
                    help="Address. Used for the sector address with sector erase, and for the address where to flash a binary.")
parser.add_argument("-n", "--count", default=1, type=int_base_0,
                    help="Number of sectors to erase. Only applies to sector erase. Default is 1.")
parser.add_argument("-s", "--skip", default=0, type=int_base_0,
                    help="Skip programming the first N bytes.  This can only be used with binary files")
parser.add_argument("-hp", "--hide_progress", action="store_true", help="Don't display programming progress.")
parser.add_argument("-fp", "--fast_program", action="store_true",
                    help="Use only the CRC of each page to determine if it already has the same data.")
parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
parser.add_argument("--mass-erase", action="store_true", help="Mass erase the target device.")

# Notes
# -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked

def setup_logging(args):
    # Set logging level
    level = LEVELS.get(args.debug_level, logging.NOTSET)
    logging.basicConfig(level=level)


def ranges(i):
    for a, b in itertools.groupby(enumerate(i), lambda x: x[1] - x[0]):
        b = list(b)
        yield b[0][1], b[-1][1]


def main():
    args = parser.parse_args()
    setup_logging(args)
    DAPAccess.set_args(args.daparg)

    # Sanity checks before attaching to board
    if args.format == 'hex' and not intelhex_available:
        print("Unable to program hex file")
        print("Module 'intelhex' must be installed first")
        exit()

    if args.list_all:
        MbedBoard.listConnectedBoards()
    else:
        board_selected = MbedBoard.chooseBoard(board_id=args.board_id, target_override=args.target_override,
                                               frequency=args.frequency, blocking=False)
        if board_selected is None:
            print("Error: There is no board connected.")
            sys.exit(1)
        with board_selected as board:
            flash = board.flash
            link = board.link

            progress = print_progress()
            if args.hide_progress:
                progress = None

            has_file = args.file is not None

            chip_erase = None
            if args.chip_erase:
                chip_erase = True
            elif args.sector_erase:
                chip_erase = False

            if args.mass_erase:
                print("Mass erasing device...")
                if board.target.massErase():
                    print("Successfully erased.")
                else:
                    print("Failed.")
                return

            if not has_file:
                if chip_erase:
                    print("Erasing chip...")
                    flash.init()
                    flash.eraseAll()
                    print("Done")
                elif args.sector_erase and args.address is not None:
                    flash.init()
                    page_addr = args.address
                    for i in range(args.count):
                        page_info = flash.getPageInfo(page_addr)
                        if not page_info:
                            break
                        # Align page address on first time through.
                        if i == 0:
                            delta = page_addr % page_info.size
                            if delta:
                                print("Warning: sector address 0x%08x is unaligned" % page_addr)
                                page_addr -= delta
                        print("Erasing sector 0x%08x" % page_addr)
                        flash.erasePage(page_addr)
                        page_addr += page_info.size
                else:
                    print("No operation performed")
                return

            # If no format provided, use the file's extension.
            if not args.format:
                args.format = os.path.splitext(args.file)[1][1:]

            # Binary file format
            if args.format == 'bin':
                # If no address is specified use the start of rom
                if args.address is None:
                    args.address = board.flash.getFlashInfo().rom_start

                with open(args.file, "rb") as f:
                    f.seek(args.skip, 0)
                    data = f.read()
                args.address += args.skip
                data = unpack(str(len(data)) + 'B', data)
                flash.flashBlock(args.address, data, chip_erase=chip_erase, progress_cb=progress,
                                 fast_verify=args.fast_program)

            # Intel hex file format
            elif args.format == 'hex':
                hex = IntelHex(args.file)
                addresses = hex.addresses()
                addresses.sort()

                flash_builder = flash.getFlashBuilder()

                data_list = list(ranges(addresses))
                for start, end in data_list:
                    size = end - start + 1
                    data = list(hex.tobinarray(start=start, size=size))
                    flash_builder.addData(start, data)
                flash_builder.program(chip_erase=chip_erase, progress_cb=progress, fast_verify=args.fast_program)

            else:
                print("Unknown file format '%s'" % args.format)

if __name__ == '__main__':
    main()
