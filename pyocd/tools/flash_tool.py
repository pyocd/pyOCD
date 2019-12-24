#!/usr/bin/env python
# pyOCD debugger
# Copyright (c) 2006-2018 Arm Limited
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
from ..core.helpers import ConnectHelper
from ..probe.pydapaccess import DAPAccess
from ..utility.progress import print_progress
from ..utility.cmdline import convert_session_options
from ..debug.elf.elf import (ELFBinaryFile, SH_FLAGS)
from ..flash.file_programmer import FileProgrammer
from ..flash.eraser import FlashEraser

LOG = logging.getLogger(__name__)

LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

# pylint: disable=invalid-name
board = None

supported_formats = ['bin', 'hex', 'elf']

DEBUG_LEVELS = list(LEVELS.keys())

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
parser.add_argument("format", nargs='?', choices=supported_formats, default=None, help="File format. Default is to use the file extension (.bin, .hex, .elf, .afx)")
parser.add_argument('--version', action='version', version=__version__)
# reserved: "-p", "--port"
# reserved: "-c", "--cmd-port"
parser.add_argument('--config', metavar="PATH", default=None, help="Use a YAML config file.")
parser.add_argument("--no-config", action="store_true", default=None, help="Do not use a configuration file.")
parser.add_argument("--pack", metavar="PATH", help="Path to a CMSIS Device Family Pack")
parser.add_argument("-b", "--board", dest="board_id", default=None,
                    help="Connect to board by board ID. Use -l to list all connected boards. Only a unique part of the board ID needs to be provided.")
parser.add_argument("-l", "--list", action="store_true", dest="list_all", default=False,
                    help="List all connected boards.")
parser.add_argument("-d", "--debug", dest="debug_level", choices=DEBUG_LEVELS, default='info',
                    help="Set the level of system logging output. Supported choices are: " + ", ".join(DEBUG_LEVELS),
                    metavar="LEVEL")
parser.add_argument("-t", "--target", dest="target_override", default=None,
                    help="Override target to debug.",
                    metavar="TARGET")
# reserved: "-n", "--nobreak"
# reserved: "-r", "--reset-break"
# reserved: "-s", "--step-int"
parser.add_argument("-f", "--frequency", dest="frequency", default=None, type=int,
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
parser.add_argument("-hp", "--hide_progress", action="store_true", default=None, help="Don't display programming progress.")
parser.add_argument("-fp", "--fast_program", action="store_true", default=None,
                    help="Use only the CRC of each page to determine if it already has the same data.")
parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
parser.add_argument("--mass-erase", action="store_true", help="Mass erase the target device.")
parser.add_argument("-O", "--option", metavar="OPTION", action="append", help="Set session option of form 'OPTION=VALUE'.")
parser.add_argument("--no-deprecation-warning", action="store_true", help="Do not warn about pyocd-flashtool being deprecated.")
# pylint: enable=invalid-name

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

    if not args.no_deprecation_warning:
        LOG.warning("pyocd-flashtool is deprecated; please use the new combined pyocd tool.")
        
    # Sanity checks before attaching to board
    if args.format == 'hex' and not intelhex_available:
        print("Unable to program hex file")
        print("Module 'intelhex' must be installed first")
        exit()

    if args.list_all:
        ConnectHelper.list_connected_probes()
    else:
        session = ConnectHelper.session_with_chosen_probe(
                            config_file=args.config,
                            no_config=args.no_config,
                            pack=args.pack,
                            unique_id=args.board_id,
                            target_override=args.target_override,
                            frequency=args.frequency,
                            blocking=False,
                            hide_progress=args.hide_progress,
                            **convert_session_options(args.option))
        if session is None:
            print("Error: There is no debug probe connected.")
            sys.exit(1)
        with session:
            has_file = args.file is not None

            if args.mass_erase:
                print("Mass erasing device...")
                if session.target.mass_erase():
                    print("Successfully erased.")
                else:
                    print("Failed.")
                return

            if not has_file:
                if args.chip_erase:
                    FlashEraser(session, FlashEraser.Mode.CHIP).erase()
                elif args.sector_erase and args.address is not None:
                    page_addr = args.address
                    
                    region = session.target.memory_map.get_region_for_address(page_addr)
                    if not region.is_flash:
                        print("Error: address 0x%08x is not in flash" % page_addr)
                        return
                    
                    flash = region.flash
                    flash.init(flash.Operation.ERASE)
                    
                    for i in range(args.count):
                        page_info = flash.get_page_info(page_addr)
                        if not page_info:
                            print("Warning: stopped erasing early; hit end of flash region at 0x%08x" % region.end)
                            break
                        # Align page address on first time through.
                        if i == 0:
                            delta = page_addr % page_info.size
                            if delta:
                                print("Warning: sector address 0x%08x is unaligned" % page_addr)
                                page_addr -= delta
                        print("Erasing sector 0x%08x" % page_addr)
                        flash.erase_sector(page_addr)
                        page_addr += page_info.size

                    flash.cleanup()
                else:
                    print("No operation performed")
                return

            # Convert arguments for FileProgrammer.
            if args.chip_erase:
                chip_erase = "chip"
            elif args.sector_erase:
                chip_erase = "sector"
            else:
                chip_erase = "auto"
            
            # Program the file into flash.
            programmer = FileProgrammer(session, chip_erase=chip_erase, trust_crc=args.fast_program)
            programmer.program(args.file,
                                file_format=args.format,
                                base_address=args.address,
                                skip=args.skip)

if __name__ == '__main__':
    main()
