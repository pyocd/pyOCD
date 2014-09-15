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

from interface import Interface
import logging, os

try:
    import hid
except:
    if os.name == "posix" and os.uname()[0] == 'Darwin':
        logging.error("cython-hidapi is required on a Mac OS X Machine")
    isAvailable = False
else:
    isAvailable = True

class HidApiUSB(Interface):
    """
    This class provides basic functions to access
    a USB HID device using cython-hidapi:
        - write/read an endpoint
    """
    vid = 0
    pid = 0

    isAvailable = isAvailable

    def __init__(self):
        # Vendor page and usage_id = 2
        self.device = None

    def open(self):
        pass

    @staticmethod
    def getAllConnectedInterface(vid, pid):
        """
        returns all the connected devices which matches HidApiUSB.vid/HidApiUSB.pid.
        returns an array of HidApiUSB (Interface) objects
        """

        devices = hid.enumerate(vid, pid)

        if not devices:
            logging.debug("No Mbed device connected")
            return

        boards = []

        for deviceInfo in devices:
            try:
                dev = hid.device(vendor_id=vid, product_id=pid, path = deviceInfo['path'])
            except IOError:
                logging.debug("Failed to open Mbed device")
                return

            # Create the USB interface object for this device.
            new_board = HidApiUSB()
            new_board.vendor_name = deviceInfo['manufacturer_string']
            new_board.product_name = deviceInfo['product_string']
            new_board.vid = deviceInfo['vendor_id']
            new_board.pid = deviceInfo['product_id']
            new_board.device = dev
            try:
                dev.open(vid, pid)
            except AttributeError:
                pass

            boards.append(new_board)

        return boards

    def write(self, data):
        """
        write data on the OUT endpoint associated to the HID interface
        """
        for _ in range(64 - len(data)):
            data.append(0)
        #logging.debug("send: %s", data)
        self.device.write([0] + data)
        return


    def read(self, timeout = -1):
        """
        read data on the IN endpoint associated to the HID interface
        """
        return self.device.read(64)

    def close(self):
        """
        close the interface
        """
        logging.debug("closing interface")
        self.device.close()
