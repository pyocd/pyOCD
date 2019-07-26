# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
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

from .interface import Interface
from .common import filter_device_by_usage_page
from ..dap_access_api import DAPAccessIntf
from ....utility.timeout import Timeout
import logging
import os
import collections
from time import time, sleep
import six

OPEN_TIMEOUT_S = 60.0

LOG = logging.getLogger(__name__)

try:
    import pywinusb.hid as hid
except:
    if os.name == "nt":
        LOG.error("PyWinUSB is required on a Windows Machine")
    IS_AVAILABLE = False
else:
    IS_AVAILABLE = True

class PyWinUSB(Interface):
    """! @brief CMSIS-DAP USB interface class using pyWinUSB for the backend.
    """

    isAvailable = IS_AVAILABLE

    def __init__(self):
        super(PyWinUSB, self).__init__()
        # Vendor page and usage_id = 2
        self.report = None
        # deque used here instead of synchronized Queue
        # since read speeds are ~10-30% faster and are
        # comprable to a based list implmentation.
        self.rcv_data = collections.deque()
        self.device = None

    # handler called when a report is received
    def rx_handler(self, data):
#         LOG.debug("rcv<(%d) %s" % (len(data), ' '.join(['%02x' % i for i in data])))
        self.rcv_data.append(data[1:])

    def open(self):
        self.device.set_raw_data_handler(self.rx_handler)

        # Attempt to open the device.
        # Note - this operation must be retried since
        # other instances of pyOCD listing board can prevent
        # opening this device with exclusive access.
        with Timeout(OPEN_TIMEOUT_S) as t_o:
            while t_o.check():
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
                except hid.HIDError as exc:
                    # If the device could not be opened in read only mode
                    # Then it either has been disconnected or is in use
                    # by another thread/process
                    raise six.raise_from(DAPAccessIntf.DeviceError("Unable to open device"), exc)

            else:
                # If this timeout has elapsed then another process
                # has locked this device in shared mode. This should
                # not happen.
                assert False

    @staticmethod
    def get_all_connected_interfaces():
        """! @brief Returns all the connected CMSIS-DAP devices
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

                # Perform device-specific filtering.
                if filter_device_by_usage_page(dev.vendor_id, dev.product_id, dev.hid_caps.usage_page):
                    dev.close()
                    continue

                report = dev.find_output_reports()
                if len(report) != 1:
                    dev.close()
                    continue
                new_board = PyWinUSB()
                new_board.report = report[0]
                new_board.packet_size = len(new_board.report.get_raw_data()) - 1
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
                    LOG.error("Receiving Exception: %s", e)
                dev.close()

        return boards

    def write(self, data):
        """! @brief Write data on the OUT endpoint associated to the HID interface
        """
        data.extend([0] * (self.packet_size - len(data)))
#         LOG.debug("snd>(%d) %s" % (len(data), ' '.join(['%02x' % i for i in data])))
        self.report.send([0] + data)

    def read(self, timeout=20.0):
        """! @brief Read data on the IN endpoint associated to the HID interface
        """
        with Timeout(timeout) as t_o:
            while t_o.check():
                if len(self.rcv_data):
                    break
                sleep(0)
            else:
                # Read operations should typically take ~1-2ms.
                # If this exception occurs, then it could indicate
                # a problem in one of the following areas:
                # 1. Bad usb driver causing either a dropped read or write
                # 2. CMSIS-DAP firmware problem cause a dropped read or write
                # 3. CMSIS-DAP is performing a long operation or is being
                #    halted in a debugger
                raise DAPAccessIntf.DeviceError("Read timed out")
        return self.rcv_data.popleft()

    def set_packet_count(self, count):
        # No interface level restrictions on count
        self.packet_count = count

    def set_packet_size(self, size):
        self.packet_size = size

    def get_serial_number(self):
        return self.serial_number

    def close(self):
        """! @brief Close the interface
        """
        LOG.debug("closing interface")
        self.device.close()
