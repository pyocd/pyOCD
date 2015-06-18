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

import argparse
import sys
import logging
import itertools
from struct import unpack

try:
    from intelhex import IntelHex
    intelhex_available = True
except ImportError:
    intelhex_available = False

import pyOCD
from pyOCD import __version__
from pyOCD.board import MbedBoard

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

interface = None
board = None

supported_formats = ['bin', 'hex']
supported_targets = pyOCD.target.TARGET.keys()
supported_targets.remove('cortex_m')  # No generic programming

debug_levels = LEVELS.keys()

# Keep args in snyc with gdb_server.py when possible
parser = argparse.ArgumentParser(description='Flash utility')
parser.add_argument('--version', action='version', version=__version__)
parser.add_argument("file", help="File to program")
parser.add_argument("format", choices=supported_formats, help="File format")
# reserved: "-p", "--port"
# reserved: "-c", "--cmd-port"
parser.add_argument("-b", "--board", dest="board_id", default=None,
                    help="Connect to board by board id.  Use -l to list all connected boards.")
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
parser.add_argument("-a", "--address", default=None,
                    help="Address to flash binary.  This can only be used with binary files")
parser.add_argument("-s", "--skip", default=0, type=int,
                    help="Skip programming the first N bytes.  This can only be used with binary files")
parser.add_argument("-hp", "--hide_progress", action="store_true", help="Don't display programming progress.")
parser.add_argument("-fp", "--fast_program", action="store_true",
                    help="Use only the CRC of each page to determine if it already has the same data.")

# Notes
# -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked

def setup_logging(args):
    # Set logging level
    level = LEVELS.get(args.debug_level, logging.NOTSET)
    logging.basicConfig(level=level)


def ranges(i):
    for a, b in itertools.groupby(enumerate(i), lambda (x, y): y - x):
        b = list(b)
        yield b[0][1], b[-1][1]


def print_progress(progress):
    # Reset state on 0.0
    if progress == 0.0:
        print_progress.done = False

    # print progress bar
    if not print_progress.done:
        sys.stdout.write('\r')
        i = int(progress * 20.0)
        sys.stdout.write("[%-20s] %3d%%" % ('=' * i, round(progress * 100)))
        sys.stdout.flush()

    # Finish on 1.0
    if progress >= 1.0:
        if not print_progress.done:
            print_progress.done = True
            sys.stdout.write("\n")


def main():
    args = parser.parse_args()
    setup_logging(args)

    # Sanity checks before attaching to board
    if args.format == 'hex' and not intelhex_available:
        print("Unable to program hex file")
        print("Module 'intelhex' must be installed first")
        exit()

    if args.list_all:
        MbedBoard.listConnectedBoards()
    else:
        board_selected = MbedBoard.chooseBoard(board_id=args.board_id, target_override=args.target_override,
                                               frequency=args.frequency)
        with board_selected as board:
            flash = board.flash
            transport = board.transport

            # Boost speed with deferred transfers
            transport.setDeferredTransfer(True)

            progress = print_progress
            if args.hide_progress:
                progress = None

            chip_erase = None
            if args.chip_erase:
                chip_erase = True
            elif args.sector_erase:
                chip_erase = False

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
            if args.format == 'hex':
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


if __name__ == '__main__':
    main()
