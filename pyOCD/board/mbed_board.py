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
import sys, os
import logging, array
from time import sleep
import colorama
import six
from .board import Board
from ..pyDAPAccess import DAPAccess
from .board_ids import BOARD_ID_TO_INFO

mbed_vid = 0x0d28
mbed_pid = 0x0204

# Init colorama here since this is currently the only module that uses it.
colorama.init()

class MbedBoard(Board):
    """
    This class inherits from Board and is specific to mbed boards.
    Particularly, this class allows you to dynamically determine
    the type of all boards connected based on the id board
    """
    def __init__(self, link, target=None, frequency=1000000):
        """
        Init the board
        """
        self.native_target = None
        self.test_binary = None
        unique_id = link.get_unique_id()
        board_id = unique_id[0:4]
        self.name = "Unknown Board"
        if board_id in BOARD_ID_TO_INFO:
            board_info = BOARD_ID_TO_INFO[board_id]
            self.name = board_info.name
            self.native_target = board_info.target
            self.test_binary = board_info.binary

        # Unless overridden use the native target
        if target is None:
            target = self.native_target

        if target is None:
            logging.warning("Unsupported board found %s", board_id)
            target = "cortex_m"

        super(MbedBoard, self).__init__(target, link, frequency)
        self.unique_id = unique_id
        self.target_type = target

    def getUniqueID(self):
        """
        Return the unique id of the board
        """
        return self.unique_id

    def getTargetType(self):
        """
        Return the type of the board
        """
        return self.target_type

    def getTestBinary(self):
        """
        Return name of test binary file
        """
        return self.test_binary

    def getBoardName(self):
        """
        Return board name
        """
        return self.name

    def getInfo(self):
        """
        Return info on the board
        """
        return self.name + " [" + self.target_type + "]"

    @staticmethod
    def listConnectedBoards(dap_class=DAPAccess):
        """
        List the connected board info
        """
        all_mbeds = MbedBoard.getAllConnectedBoards(dap_class, close=True,
                                                    blocking=False)
        if len(all_mbeds) > 0:
            print(colorama.Fore.BLUE + "## => Board Name | Unique ID")
            print("-- -- ----------------------")
            for index, mbed in enumerate(sorted(all_mbeds, key=lambda x:x.getInfo())):
                print(colorama.Fore.GREEN + "%2d => %s | %s" % (
                    index, mbed.getInfo(),
                    colorama.Fore.CYAN + mbed.unique_id) + colorama.Style.RESET_ALL)
        else:
            print("No available boards are connected")

    @staticmethod
    def getAllConnectedBoards(dap_class=DAPAccess, close=False, blocking=True,
                              target_override=None, frequency=1000000):
        """
        Return an array of all mbed boards connected
        """

        mbed_list = []
        while True:

            connected_daps = dap_class.get_connected_devices()
            for dap_access in connected_daps:
                new_mbed = MbedBoard(dap_access, target_override, frequency)
                mbed_list.append(new_mbed)

            #TODO - handle exception on open
            if not close:
                for dap_access in connected_daps:
                    dap_access.open()

            if not blocking:
                break
            elif len(mbed_list) > 0:
                break
            else:
                sleep(0.01)
            assert len(mbed_list) == 0

        return mbed_list

    @staticmethod
    def chooseBoard(dap_class=DAPAccess, blocking=True, return_first=False,
                    board_id=None, target_override=None, frequency=1000000,
                    init_board=True):
        """
        Allow you to select a board among all boards connected
        """
        all_mbeds = MbedBoard.getAllConnectedBoards(dap_class, True, blocking,
                                                    target_override, frequency)

        # If a board ID is specified remove all other boards
        if board_id != None:
            board_id = board_id.lower()
            new_mbed_list = []
            for mbed in all_mbeds:
                if board_id in mbed.unique_id.lower():
                    new_mbed_list.append(mbed)
            if len(new_mbed_list) > 1:
                print(colorama.Fore.RED + "More than one board matches board ID '%s'" % board_id + colorama.Style.RESET_ALL)
                all_mbeds = sorted(all_mbeds, key=lambda x:x.getInfo())
                for mbed in all_mbeds:
                    head, sep, tail = mbed.unique_id.lower().rpartition(board_id)
                    highlightedId = head + colorama.Fore.RED + sep + colorama.Style.RESET_ALL + tail
                    print("%s | %s" % (
                        mbed.getInfo(),
                        highlightedId))
                return None
            all_mbeds = new_mbed_list

        # Return if no boards are connected
        if all_mbeds == None or len(all_mbeds) <= 0:
            if board_id is None:
                print("No connected boards")
            else:
                print("Board %s is not connected" % board_id)
            return None # No boards to close so it is safe to return

        # Select first board
        if return_first:
            all_mbeds = all_mbeds[0:1]

        # Ask user to select boards if there is more than 1 left
        if len(all_mbeds) > 1:
            all_mbeds = sorted(all_mbeds, key=lambda x:x.getInfo())
            print(colorama.Fore.BLUE + "## => Board Name | Unique ID")
            print("-- -- ----------------------")
            for index, mbed in enumerate(all_mbeds):
                print(colorama.Fore.GREEN + "%2d => %s | %s" % (
                    index, mbed.getInfo(),
                    colorama.Fore.CYAN + mbed.unique_id))
            print(colorama.Fore.RED + " q => Quit")
            while True:
                print(colorama.Style.RESET_ALL)
                print("Enter the number of the board to connect:")
                line = six.moves.input("> ")
                valid = False
                if line.strip().lower() == 'q':
                    return None
                try:
                    ch = int(line)
                    valid = 0 <= ch < len(all_mbeds)
                except ValueError:
                    pass
                if not valid:
                    print(colorama.Fore.YELLOW + "Invalid choice: %s\n" % line)
                    for index, mbed in enumerate(all_mbeds):
                        print(colorama.Fore.GREEN + "%d => %s" % (index, mbed.getInfo()))
                    print(colorama.Fore.RED + "q => Exit")
                else:
                    break
            all_mbeds = all_mbeds[ch:ch + 1]

        assert len(all_mbeds) == 1
        mbed = all_mbeds[0]
        mbed.link.open()
        if init_board:
            try:
                mbed.init()
            except:
                mbed.link.close()
                raise
        return mbed
