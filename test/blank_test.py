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
from __future__ import print_function
import os, sys
from time import sleep
from random import randrange
import math

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
import logging

logging.basicConfig(level=logging.INFO)

print("\n\n------ Test attaching to locked board ------")
for i in range(0, 10):
    with MbedBoard.chooseBoard() as board:
        # Erase and then reset - This locks Kinetis devices
        board.flash.init()
        board.flash.eraseAll()
        board.target.reset()

print("\n\n------ Testing Attaching to board ------")
for i in range(0, 100):
    with MbedBoard.chooseBoard() as board:
        board.target.halt()
        sleep(0.01)
        board.target.resume()
        sleep(0.01)

print("\n\n------ Flashing new code ------")
with MbedBoard.chooseBoard() as board:
    binary_file = os.path.join(parentdir, 'binaries', board.getTestBinary())
    board.flash.flashBinary(binary_file)

print("\n\n------ Testing Attaching to regular board ------")
for i in range(0, 10):
    with MbedBoard.chooseBoard() as board:
        board.target.resetStopOnReset()
        board.target.halt()
        sleep(0.2)
        board.target.resume()
        sleep(0.2)
