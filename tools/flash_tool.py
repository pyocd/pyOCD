#!/usr/bin/env python
"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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

import argparse, os, sys, logging, itertools
from struct import unpack

try:
    from intelhex import IntelHex
    intelhex_available = True
except:
    intelhex_available = False

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard

LEVELS={'debug':logging.DEBUG,
        'info':logging.INFO,
        'warning':logging.WARNING,
        'error':logging.ERROR,
        'critical':logging.CRITICAL
        }

interface = None
board = None

supported_formats = ['bin', 'hex']
supported_targets = pyOCD.target.TARGET.keys()
supported_targets.remove('cortex_m')    # No generic programming

parser = argparse.ArgumentParser(description='Flash utility')
parser.add_argument("file", help="File to program")
parser.add_argument("format", choices=supported_formats, help="File format")
group = parser.add_mutually_exclusive_group()
group.add_argument("-ce", "--chip_erase", action="store_true",help="erase flash before write")
group.add_argument("-se", "--sector_erase", action="store_true",help="only erase sectors")
parser.add_argument("-u", "--unlock", action="store_true", default=False, help="Unlock device.")
parser.add_argument("-a", "--address", default = None, help="Address to flash binary.  This can only be used with binary files")
parser.add_argument("-s", "--skip", default = 0, type=int, help="Skip programming the first N bytes.  This can only be used with binary files")
parser.add_argument("-id", "--board_id", default = None, help="connect to board by board id, use -l to list all connected boards")
parser.add_argument("-l", "--list", action="store_true", help="list all connected boards")
parser.add_argument("-d", "--debug", default = 'info', help = "Set the level of system logging output, the available value for DEBUG_LEVEL: debug, info, warning, error, critical" )
parser.add_argument("-t", "--target", choices=supported_targets, default = None, help = "Override target to debug.  Supported targets are: "+', '.join(supported_targets), metavar='' )
parser.add_argument("-f", "--frequency", default = 1000000, type=int, help = "SWD clock frequency in Hz." )
parser.add_argument("-p", "--hide_progress", action="store_true", help = "Don't display programming progress." )
args = parser.parse_args()

# Notes
# -Currently "--unlock" does nothing since kinetis parts will automatically get unlocked

# Set logging level
level = LEVELS.get(args.debug, logging.NOTSET)
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
        i = int(progress*20.0)
        sys.stdout.write("[%-20s] %3d%%" % ('='*i, round(progress * 100)))

    # Finish on 1.0
    if progress >= 1.0:
        if not print_progress.done:
            print_progress.done = True
            sys.stdout.write("\n")

# Sanity checks before attaching to board
if args.format == 'hex' and not intelhex_available:
    print("Unable to program hex file")
    print("Module 'intelhex' must be installed first")
    exit()


if args.list:
    MbedBoard.listConnectedBoards()
else:
    board_selected = MbedBoard.chooseBoard(board_id = args.board_id, target_override = args.target, frequency = args.frequency)
    with board_selected as board:
        flash = board.flash

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
            flash.flashBlock(args.address, data, chip_erase=chip_erase, progress_cb=progress)

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
            flash_builder.program(chip_erase=chip_erase, progress_cb=progress)
