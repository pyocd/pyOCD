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

import argparse, os, sys
from time import sleep
from random import randrange
import math

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard

interface = None
board = None

fcf = [0xff] * 12
fcf += [0xfe, 0xff, 0xff, 0xff]

import logging

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(description='A CMSIS-DAP python debugger')
args = parser.parse_args()

try:

    board = MbedBoard.chooseBoard()
    target_type = board.getTargetType()

    target = board.target
    transport = board.transport
    flash = board.flash
    interface = board.interface

    print "\r\n\r\n------ GET Unique ID ------"
    print "Unique ID: %s" % board.getUniqueID()

    print "Permanently unlocking chip..."
    print "Writing FCF = %s" % repr(fcf)
    flash.init()
    flash.eraseAll()
    flash.programPage(0x400, fcf)

#     target.reset()

finally:
    if board != None:
        board.uninit()
