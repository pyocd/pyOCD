# pyOCD debugger
# Copyright (c) 2006-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import collections
import logging
import platform
import six
import threading

from .interface import Interface
from .common import (
    filter_device_by_usage_page,
    generate_device_unique_id,
    )
from ..dap_access_api import DAPAccessIntf
from ....utility.compatibility import to_str_safe
from ....utility.timeout import Timeout

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

try:
    import hid
except ImportError:
    IS_AVAILABLE = False
else:
    IS_AVAILABLE = True

# OS flags.
_IS_DARWIN = (platform.system() == 'Darwin')
_IS_WINDOWS = (platform.system() == 'Windows')

class HidApiUSB(Interface):
    """@brief CMSIS-DAP USB interface class using hidapi backend."""

    isAvailable = IS_AVAILABLE

    HIDAPI_MAX_PACKET_COUNT = 30

    def __init__(self):
        super().__init__()
        # Vendor page and usage_id = 2
        self.device = None
        self.device_info = None
        self.thread = None
        self.read_sem = threading.Semaphore(0)
        self.closed_event = threading.Event()
        self.received_data = collections.deque()

    def set_packet_count(self, count):
        # hidapi for macos has an arbitrary limit on the number of packets it will queue for reading.
        # Even though we have a read thread, it doesn't hurt to limit the packet count since the limit
        # is fairly high.
        if _IS_DARWIN:
            count = min(count, self.HIDAPI_MAX_PACKET_COUNT)
        self.packet_count = count

    def open(self):
        try:
            self.device.open_path(self.device_info['path'])
        except IOError as exc:
            raise DAPAccessIntf.DeviceError("Unable to open device: " + str(exc)) from exc

        # Windows does not use the receive thread because it causes packet corruption for some reason.
        if not _IS_WINDOWS:
            # Make certain the closed event is clear.
            self.closed_event.clear()

            # Start RX thread
            self.thread = threading.Thread(target=self.rx_task)
            self.thread.daemon = True
            self.thread.start()

    def rx_task(self):
        try:
            while not self.closed_event.is_set():
                self.read_sem.acquire()
                if not self.closed_event.is_set():
                    read_data = self.device.read(self.packet_size)

                    if TRACE.isEnabledFor(logging.DEBUG):
                        # Strip off trailing zero bytes to reduce clutter.
                        TRACE.debug("  USB IN < (%d) %s", len(read_data), ' '.join([f'{i:02x}' for i in bytes(read_data).rstrip(b'\x00')]))

                    self.received_data.append(read_data)
        finally:
            # Set last element of rcv_data to None on exit
            self.received_data.append(None)

    @staticmethod
    def get_all_connected_interfaces():
        """@brief Returns all the connected devices with CMSIS-DAP in the name.

        returns an array of HidApiUSB (Interface) objects
        """

        devices = hid.enumerate()

        boards = []

        for deviceInfo in devices:
            product_name = to_str_safe(deviceInfo['product_string'])
            if ("CMSIS-DAP" not in product_name):
                # Check the device path as a backup. Even though we can't get the interface name from
                # hidapi, it may appear in the path. At least, it does on macOS.
                device_path = to_str_safe(deviceInfo['path'])
                if "CMSIS-DAP" not in device_path:
                    # Skip non cmsis-dap devices
                    continue

            vid = deviceInfo['vendor_id']
            pid = deviceInfo['product_id']

            # Perform device-specific filtering.
            if filter_device_by_usage_page(vid, pid, deviceInfo['usage_page']):
                continue

            try:
                dev = hid.device(vendor_id=vid, product_id=pid, path=deviceInfo['path'])
            except IOError as exc:
                LOG.debug("Failed to open USB device: %s", exc)
                continue

            # Create the USB interface object for this device.
            new_board = HidApiUSB()
            new_board.vid = vid
            new_board.pid = pid
            new_board.vendor_name = deviceInfo['manufacturer_string'] or f"{vid:#06x}"
            new_board.product_name = deviceInfo['product_string'] or f"{pid:#06x}"
            new_board.serial_number = deviceInfo['serial_number'] \
                    or generate_device_unique_id(vid, pid, six.ensure_str(deviceInfo['path']))
            new_board.device_info = deviceInfo
            new_board.device = dev
            boards.append(new_board)

        return boards

    def write(self, data):
        """@brief Write data on the OUT endpoint associated to the HID interface"""
        if TRACE.isEnabledFor(logging.DEBUG):
            TRACE.debug("  USB OUT> (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))
        data.extend([0] * (self.packet_size - len(data)))
        if not _IS_WINDOWS:
            self.read_sem.release()
        self.device.write([0] + data)

    def read(self, timeout=Interface.DEFAULT_READ_TIMEOUT):
        """@brief Read data on the IN endpoint associated to the HID interface"""
        # Windows doesn't use the read thread, so read directly.
        if _IS_WINDOWS:
            read_data = self.device.read(self.packet_size)

            if TRACE.isEnabledFor(logging.DEBUG):
                # Strip off trailing zero bytes to reduce clutter.
                TRACE.debug("  USB IN < (%d) %s", len(read_data), ' '.join([f'{i:02x}' for i in bytes(read_data).rstrip(b'\x00')]))

            return read_data

        # Other OSes use the read thread, so we check for and pull data from the queue.
        # Spin for a while if there's not data available yet. 100 µs sleep between checks.
        with Timeout(timeout, sleeptime=0.0001) as t_o:
            while t_o.check():
                if len(self.received_data) != 0:
                    break
            else:
                raise DAPAccessIntf.DeviceError(f"Timeout reading from device {self.serial_number}")

        if self.received_data[0] is None:
            raise DAPAccessIntf.DeviceError(f"Device {self.serial_number} read thread exited")

        # Trace when the higher layer actually gets a packet previously read.
        if TRACE.isEnabledFor(logging.DEBUG):
            # Strip off trailing zero bytes to reduce clutter.
            TRACE.debug("  USB RD < (%d) %s", len(self.received_data[0]),
                    ' '.join([f'{i:02x}' for i in bytes(self.received_data[0]).rstrip(b'\x00')]))

        return self.received_data.popleft()

    def close(self):
        """@brief Close the interface"""
        assert not self.closed_event.is_set()

        LOG.debug("closing interface")
        if not _IS_WINDOWS:
            self.closed_event.set()
            self.read_sem.release()
            self.thread.join()
            self.thread = None
        self.device.close()
