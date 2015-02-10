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

TARGET_TYPE = {
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
              }

mbed_vid = 0x0d28
mbed_pid = 0x0204

class MbedBoard(Board):
    """
    This class inherits from Board and is specific to mbed boards.
    Particularly, this class allows you to dynamically determine
    the type of all boards connected based on the id board
    """
    def __init__(self, target, flash, interface, transport = "cmsis_dap", frequency = 1000000):
        """
        Init the board
        """
        super(MbedBoard, self).__init__(target, flash, interface, transport, frequency)
        self.unique_id = ""
        self.target_type = ""
    
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
        all_mbeds = INTERFACE[usb_backend].getAllConnectedInterface(mbed_vid, mbed_pid)
        index = 0
        if (all_mbeds != []) & (all_mbeds != None):
            for mbed in all_mbeds:
                mbed.write([0x80])
                u_id_ = mbed.read()
                try:
                    target_type = array.array('B', [i for i in u_id_[2:6]]).tostring()
                    if (target_type not in TARGET_TYPE):
                        logging.info("Unsupported target found: %s" % target_type)
                        continue
                    else:
                        target_type = TARGET_TYPE[target_type]
                    new_mbed = MbedBoard("target_" + target_type, "flash_" + target_type, mbed, transport)
                    new_mbed.target_type = target_type
                    new_mbed.unique_id = array.array('B', [i for i in u_id_[2:2+u_id_[1]]]).tostring()
                    logging.info("new board id detected: %s", new_mbed.unique_id)
                    print "%d => %s boardId => %s" % (index, new_mbed.getInfo().encode('ascii', 'ignore'), new_mbed.unique_id)
                    mbed.close()
                    index += 1
                except:
                    mbed.close()
                    raise
        else:
            print "No available boards is connected"
        
    @staticmethod
    def getAllConnectedBoards(transport = "cmsis_dap", close = False, blocking = True, 
                                target_override = None, frequency = 1000000):
        """
        Return an array of all mbed boards connected
        """
        first = True
        while True:
            while True:
                all_mbeds = INTERFACE[usb_backend].getAllConnectedInterface(mbed_vid, mbed_pid)
                if all_mbeds != None or not blocking:
                    break
                if (first == True):
                    logging.info("Waiting for a USB device connected")
                    first = False
                sleep(0.2)
                
            mbed_boards = []
            for mbed in all_mbeds:
                try:
                    mbed.write([0x80])
                    u_id_ = mbed.read()
                    if target_override:
                        target_type = target_override
                    else:
                        target_type = array.array('B', [i for i in u_id_[2:6]]).tostring()
                        if (target_type not in TARGET_TYPE):
                            logging.info("Unsupported target found: %s" % target_type)
                            continue
                        else:
                            target_type = TARGET_TYPE[target_type]
                        
                    new_mbed = MbedBoard("target_" + target_type, "flash_" + target_type, mbed, transport, frequency)
                    new_mbed.target_type = target_type
                    new_mbed.unique_id = array.array('B', [i for i in u_id_[2:2+u_id_[1]]]).tostring()
                    logging.info("new board id detected: %s", new_mbed.unique_id)
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
        
        if all_mbeds == None:
            return None
        
        index = 0
        print "id => usbinfo | boardname"
        for mbed in all_mbeds:
            print "%d => %s" % (index, mbed.getInfo().encode('ascii', 'ignore'))
            index += 1
        
        if len(all_mbeds) == 1:
            if board_id != None:
                if all_mbeds[0].unique_id == (board_id):
                    all_mbeds[0].init()
                    return all_mbeds[0]
                else:
                    print "The board you want to connect isn't the board now connected"
                    return None
            else:
                try:
                    all_mbeds[0].init()
                except:
                    all_mbeds[0].interface.close()
                    raise
                return all_mbeds[0]
        
        try:
            ch = 0
            if board_id != None:
                for mbed in all_mbeds:
                    if mbed.unique_id == (board_id):
                        mbed.init()
                        return mbed
                    else:
                        mbed.interface.close()
                print "The board you want to connect isn't the boards now connected"
                return None
            elif not return_first:
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
                if mbed != all_mbeds[int(ch)]:
                    mbed.interface.close()
        
            all_mbeds[int(ch)].init()
            return all_mbeds[int(ch)]
        except:
            for mbed in all_mbeds:
                mbed.interface.close()
            raise
