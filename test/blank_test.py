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
import logging

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

from pyocd.core.helpers import ConnectHelper
from pyocd.flash.loader import FileProgrammer
from test_util import get_session_options

logging.basicConfig(level=logging.INFO)

print("\n\n------ Test attaching to locked board ------")
for i in range(0, 10):
    with ConnectHelper.session_with_chosen_probe(**get_session_options()) as session:
        board = session.board
        # Erase and then reset - This locks Kinetis devices
        board.flash.init()
        board.flash.erase_all()
        board.target.reset()

print("\n\n------ Testing Attaching to board ------")
for i in range(0, 100):
    with ConnectHelper.session_with_chosen_probe(**get_session_options()) as session:
        board = session.board
        board.target.halt()
        sleep(0.01)
        board.target.resume()
        sleep(0.01)

print("\n\n------ Flashing new code ------")
with ConnectHelper.session_with_chosen_probe(**get_session_options()) as session:
    board = session.board
    binary_file = os.path.join(parentdir, 'binaries', board.test_binary)
    FileProgrammer(session).program(binary_file)

print("\n\n------ Testing Attaching to regular board ------")
for i in range(0, 10):
    with ConnectHelper.session_with_chosen_probe(**get_session_options()) as session:
        board = session.board
        board.target.reset_stop_on_reset()
        board.target.halt()
        sleep(0.2)
        board.target.resume()
        sleep(0.2)
