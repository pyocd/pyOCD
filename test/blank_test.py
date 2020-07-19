#!/usr/bin/env python
# pyOCD debugger
# Copyright (c) 2006-2020 Arm Limited
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

import os
import sys
from time import sleep
from random import randrange
import math
import logging

from pyocd.core.helpers import ConnectHelper
from pyocd.flash.file_programmer import FileProgrammer
from test_util import (
    get_session_options,
    get_test_binary_path,
    )

logging.basicConfig(level=logging.WARNING)

print("\n\n------ Test attaching to locked board ------")
for i in range(0, 10):
    with ConnectHelper.session_with_chosen_probe(**get_session_options()) as session:
        board = session.board
        flash = session.target.memory_map.get_boot_memory().flash
        # Erase and then reset - This locks Kinetis devices
        flash.init(flash.Operation.ERASE)
        flash.erase_all()
        flash.cleanup()
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
    binary_file = get_test_binary_path(board.test_binary)
    FileProgrammer(session).program(binary_file)

print("\n\n------ Testing Attaching to regular board ------")
for i in range(0, 10):
    with ConnectHelper.session_with_chosen_probe(**get_session_options()) as session:
        board = session.board
        board.target.reset_and_halt()
        board.target.halt()
        sleep(0.2)
        board.target.resume()
        sleep(0.2)
