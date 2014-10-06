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

import logging
import traceback
import pyOCD.board.mbed_board

from pyOCD.gdbserver import GDBServer
from pyOCD.board import MbedBoard
from optparse import OptionParser
from optparse import OptionGroup

LEVELS={'debug':logging.DEBUG,
        'info':logging.INFO,
        'warning':logging.WARNING,
        'error':logging.ERROR,
        'critical':logging.CRITICAL 
        }

print "Welcome to the PyOCD GDB Server Beta Version " 
supported_list = ''
for (k,v) in pyOCD.board.mbed_board.TARGET_TYPE.items():
    supported_list += v + ' '

parser = OptionParser()
group = OptionGroup(parser, "Supported Mbed Platform",supported_list )
parser.add_option_group(group)
parser.add_option("-p", "--port", dest = "port_number", default = 3333, help = "Write the port number that GDB server will open")
parser.add_option("-c", "--cmd-port", dest = "cmd_port", default = 4444, help = "Command port number. pyOCD doesn't open command port but it's required to be compatible with OpenOCD and Eclipse.")
parser.add_option("-b", "--board", dest = "board_id", default = None, help = "Write the board id you want to connect")
parser.add_option("-l", "--list", action = "store_true", dest = "list_all", default = False, help = "List all the connected board")
parser.add_option("-d", "--debug", dest = "debug_level", default = 'info', help = "Set the level of system logging output, the available value for DEBUG_LEVEL: debug, info, warning, error, critical" )
parser.add_option("-t", "--target", dest = "target_override", default = None, help = "Override target to debug" )
parser.add_option("-n", "--nobreak", dest = "no_break_at_hardfault", action="count", help = "Disable breakpoint at hardfault handler. Required for nrf51 chip with SoftDevice based application." )
parser.add_option("-o", "--protect", dest = "flash_protect_offset", default = False, help = "Protect N (hexidecimal) first bytes of flash (for example SoftDevice on nrf51 chip). " )
(option, args) = parser.parse_args()
if (option.flash_protect_offset):
    option.flash_protect_offset = int(option.flash_protect_offset, 16)

gdb = None
level = LEVELS.get(option.debug_level, logging.NOTSET)
logging.basicConfig(level=level)
if option.list_all == True:
    MbedBoard.listConnectedBoards()
else:
    try:
        board_selected = MbedBoard.chooseBoard(board_id = option.board_id, target_override = option.target_override)
        if board_selected != None:
            try:
                gdb = GDBServer(board_selected, int(option.port_number), {'flash_protect_offset' : option.flash_protect_offset, 'no_break_at_hardfault' : option.no_break_at_hardfault})
                while gdb.isAlive():
                    gdb.join(timeout = 0.5)
            except ValueError:
                logging.error("Port number error!")
    except KeyboardInterrupt:
        if gdb != None:
            gdb.stop()
    except Exception as e:
        print "uncaught exception: %s" % e
        traceback.print_exc()
        if gdb != None:
            gdb.stop()
