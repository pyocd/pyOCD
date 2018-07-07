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

from .interface import Interface
import logging, os, collections
from time import time
from ..dap_access_api import DAPAccessIntf

OPEN_TIMEOUT_S = 60.0

try:
    import pywinusb.hid as hid
except:
    if os.name == "nt":
        logging.error("PyWinUSB is required on a Windows Machine")
    isAvailable = False
else:
    isAvailable = True

class PyWinUSB(Interface):
    """
    This class provides basic functions to access
    a USB HID device using pywinusb:
        - write/read an endpoint
    """
    vid = 0
    pid = 0

    isAvailable = isAvailable

    def __init__(self):
        super(PyWinUSB, self).__init__()
        # Vendor page and usage_id = 2
        self.report = []
        # deque used here instead of synchronized Queue
        # since read speeds are ~10-30% faster and are
        # comprable to a based list implmentation.
        self.rcv_data = collections.deque()
        self.device = None
        self.packet_size = 64

    # handler called when a report is received
    def rx_handler(self, data):
        #logging.debug("rcv: %s", data[1:])
        self.rcv_data.append(data[1:])

    def open(self):
        self.device.set_raw_data_handler(self.rx_handler)

        # Attempt to open the device.
        # Note - this operation must be retried since
        # other instances of pyOCD listing board can prevent
        # opening this device with exclusive access.
        start = time()
        while True:

            # Attempt to open the device
            try:
                self.device.open(shared=False)
                break
            except hid.HIDError:
                pass

            # Attempt to open the device in shared mode to make
            # sure it is still there
            try:
                self.device.open(shared=True)
                self.device.close()
            except hid.HIDError:
                # If the device could not be opened in read only mode
                # Then it either has been disconnected or is in use
                # by another thread/process
                raise DAPAccessIntf.DeviceError("Unable to open device")

            if time() - start > OPEN_TIMEOUT_S:
                # If this timeout has elapsed then another process
                # has locked this device in shared mode. This should
                # not happen.
                assert False
                break


    @staticmethod
    def getAllConnectedInterface():
        """
        returns all the connected CMSIS-DAP devices
        """
        all_devices = hid.find_all_hid_devices()

        # find devices with good vid/pid
        all_mbed_devices = []
        for d in all_devices:
            if (d.product_name.find("CMSIS-DAP") >= 0):
                all_mbed_devices.append(d)

        boards = []
        for dev in all_mbed_devices:
            try:
                dev.open(shared=True)
                report = dev.find_output_reports()
                if len(report) != 1:
                    dev.close()
                    continue
                new_board = PyWinUSB()
                new_board.report = report[0]
                new_board.vendor_name = dev.vendor_name
                new_board.product_name = dev.product_name
                new_board.serial_number = dev.serial_number
                new_board.vid = dev.vendor_id
                new_board.pid = dev.product_id
                new_board.device = dev
                dev.close()
                boards.append(new_board)
            except Exception as e:
                if (str(e) != "Failure to get HID pre parsed data"):
                    logging.error("Receiving Exception: %s", e)
                dev.close()

        return boards

    def write(self, data):
        """
        write data on the OUT endpoint associated to the HID interface
        """
        for _ in range(self.packet_size - len(data)):
            data.append(0)
        #logging.debug("send: %s", data)
        self.report.send([0] + data)
        return


    def read(self, timeout=20.0):
        """
        read data on the IN endpoint associated to the HID interface
        """
        start = time()
        while len(self.rcv_data) == 0:
            if time() - start > timeout:
                # Read operations should typically take ~1-2ms.
                # If this exception occurs, then it could indicate
                # a problem in one of the following areas:
                # 1. Bad usb driver causing either a dropped read or write
                # 2. CMSIS-DAP firmware problem cause a dropped read or write
                # 3. CMSIS-DAP is performing a long operation or is being
                #    halted in a debugger
                raise Exception("Read timed out")
        return self.rcv_data.popleft()

    def setPacketCount(self, count):
        # No interface level restrictions on count
        self.packet_count = count

    def setPacketSize(self, size):
        self.packet_size = size

    def getSerialNumber(self):
        return self.serial_number

    def close(self):
        """
        close the interface
        """
        logging.debug("closing interface")
        self.device.close()
