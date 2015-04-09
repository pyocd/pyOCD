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

import sys, os
import logging, array

from time import sleep
from board import Board
from pyOCD.interface import INTERFACE, usb_backend

BOARD_ID_TO_TARGET = {
                "0200": "kl25z",
                "0210": "kl05z",
                "0220": "kl46z",
                "0230": "k20d50m",
                "0231": "k22f",
                "0240": "k64f",
                "0250": "kl02z",
                "0260": "kl26z",
                "1010": "lpc1768",
                "9004": "lpc1768",
                "1040": "lpc11u24",
                "1050": "lpc800",
                "1070": "nrf51822",
                "9009": "nrf51822",
                "9012": "nrf51822",
                "1080": "stm32f103rc",
                "1090": "stm32f051",
                "1600": "lpc4330",
                "1605": "lpc4330",
                "0400": "maxwsnenv",
                "0405": "max32600mbed",
              }

mbed_vid = 0x0d28
mbed_pid = 0x0204

class MbedBoard(Board):
    """
    This class inherits from Board and is specific to mbed boards.
    Particularly, this class allows you to dynamically determine
    the type of all boards connected based on the id board
    """
    def __init__(self, interface, board_id, unique_id, target = None, transport = "cmsis_dap", frequency = 1000000):
        """
        Init the board
        """
        # Set the native target if there is one
        self.native_target = None
        if board_id in BOARD_ID_TO_TARGET:
            self.native_target = BOARD_ID_TO_TARGET[board_id]

        # Unless overridden use the native target
        if target is None:
            target = self.native_target

        if target is None:
            raise Exception("Unknown board target")

        super(MbedBoard, self).__init__(target, target, interface, transport, frequency)
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
    
    def getInfo(self):
        """
        Return info on the board
        """
        return Board.getInfo(self) + " [" + self.target_type + "]"
    
    @staticmethod
    def listConnectedBoards(transport = "cmsis_dap"):
        """
        List the connected board info
        """
        all_mbeds = MbedBoard.getAllConnectedBoards(close = True, blocking = False)
        index = 0
        if len(all_mbeds) > 0:
            for mbed in all_mbeds:
                print("%d => %s boardId => %s" % (index, mbed.getInfo().encode('ascii', 'ignore'), mbed.unique_id))
                index += 1
        else:
            print("No available boards are connected")
        
    @staticmethod
    def getAllConnectedBoards(transport = "cmsis_dap", close = False, blocking = True, 
                                target_override = None, frequency = 1000000):
        """
        Return an array of all mbed boards connected
        """
        first = True
        while True:
            while True:
                if not first:
                    # Don't eat up all the cpu if an unsupported board is connected.
                    # Sleep before getting connected interfaces.  This way if a keyboard
                    # exception comes in there will be no resources to close
                    sleep(0.2)
            
                all_mbeds = INTERFACE[usb_backend].getAllConnectedInterface(mbed_vid, mbed_pid)
                if all_mbeds == None:
                    all_mbeds = []
                
                if not blocking:
                    # No blocking so break from loop
                    break
                
                if len(all_mbeds) > 0:
                    # A board has been found so break from loop
                    break

                if (first == True):
                    logging.info("Waiting for a USB device connected")
                    first = False
                
            mbed_boards = []
            for mbed in all_mbeds:
                try:
                    mbed.write([0x80])
                    u_id_ = mbed.read()
                    board_id = array.array('B', [i for i in u_id_[2:6]]).tostring()
                    unique_id = array.array('B', [i for i in u_id_[2:2+u_id_[1]]]).tostring()
                    if board_id not in BOARD_ID_TO_TARGET:
                        logging.info("Unsupported board found: %s" % board_id)
                        if target_override is None:
                            # TODO - if no board can be determined treat this as a generic cortex-m device
                            logging.info("Target could not be determined.  Specify target manually to use board")
                            mbed.close()
                            continue

                    new_mbed = MbedBoard(mbed, board_id, unique_id, target_override, transport, frequency)
                    logging.info("new board id detected: %s", unique_id)
                    mbed_boards.append(new_mbed)
                    if close:
                        mbed.close()
                except:
                    #TODO - close all boards when an exception occurs
                    mbed.close()
                    raise
            
            if len(mbed_boards) > 0 or not blocking:
                return mbed_boards
            
            if (first == True):
                logging.info("Waiting for a USB device connected")
                first = False
    
    @staticmethod
    def chooseBoard(transport = "cmsis_dap", blocking = True, return_first = False, board_id = None, target_override = None, frequency = 1000000):
        """
        Allow you to select a board among all boards connected
        """
        all_mbeds = MbedBoard.getAllConnectedBoards(transport, False, blocking, target_override, frequency)
        
        # If a board ID is specified close all other boards
        if board_id != None:
            new_mbed_list = []
            for mbed in all_mbeds:
                if mbed.unique_id == (board_id):    
                    new_mbed_list.append(mbed)
                else:
                    mbed.interface.close()
            assert len(new_mbed_list) <= 1
            all_mbeds = new_mbed_list

        # Return if no boards are connected
        if all_mbeds == None or len(all_mbeds)  <= 0:
            if board_id is None:
                print("No connected boards")
            else:
                print("Board %s is not connected" % board_id)
            return None # No boards to close so it is safe to return
            
        # Select first board and close others if True
        if return_first:
            for i in range(1, len(all_mbeds)):
                all_mbeds[i].interface.close()
            all_mbeds = all_mbeds[0:1]
        
        # Ask use to select boards if there is more than 1 left
        if len(all_mbeds) > 1:
            index = 0
            print "id => usbinfo | boardname"
            for mbed in all_mbeds:
                print "%d => %s" % (index, mbed.getInfo().encode('ascii', 'ignore'))
                index += 1
            while True:
                print "input id num to choice your board want to connect"
                line = sys.stdin.readline()
                valid = False
                try:
                    ch = int(line)
                    valid = 0 <= ch < len(all_mbeds)
                except ValueError:
                    pass
                if not valid:
                    logging.info("BAD CHOICE: %s", line)
                    index = 0
                    for mbed in all_mbeds:
                        print "%d => %s" % ( index, mbed.getInfo())
                        index += 1
                else:
                    break
            # close all others mbed connected
            for mbed in all_mbeds:
                if mbed != all_mbeds[ch]:
                    mbed.interface.close()
            all_mbeds = all_mbeds[ch:ch+1]
            
        assert len(all_mbeds) == 1
        mbed = all_mbeds[0]
        try:
            mbed.init()
        except:
            mbed.interface.close()
            raise
        return mbed

    def getPacketCount(self):
        """
        Return the number of commands the remote device's buffer can hold.
        """
        return self.transport.info('PACKET_COUNT')
