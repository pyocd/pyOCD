# pyOCD debugger
# Copyright (c) 2006-2020,2025 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
# Copyright (c) 2022 Harper Weigle
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

import logging
import platform
import six
import threading
import queue
from typing import Optional

from .interface import Interface
from .common import (
    USB_CLASS_HID,
    filter_device_by_usage_page,
    generate_device_unique_id,
    is_known_cmsis_dap_vid_pid,
    )
from ..dap_access_api import DAPAccessIntf
from .pyusb_backend import MatchCmsisDapv1Interface
from ....utility.compatibility import to_str_safe
from ....utility.timeout import Timeout

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

try:
    import hid
    import usb.util
    try:
        from libusb_package import find as usb_find
    except ImportError:
        from usb.core import find as usb_find
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

    def __init__(self, dev, info: dict):
        super().__init__()
        # Vendor page and usage_id = 2
        self.vid = info['vendor_id']
        self.pid = info['product_id']
        self.vendor_name = info['manufacturer_string'] or f"{self.vid:#06x}"
        self.product_name = info['product_string'] or f"{self.pid:#06x}"
        self.serial_number = info['serial_number'] \
                or generate_device_unique_id(self.vid, self.pid, six.ensure_str(info['path']))
        self.device_info = info
        self.device = dev
        self.closed = True
        self.thread = None
        self.read_sem = threading.Semaphore(0)
        self.closed_event = threading.Event()
        self.received_data: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self._read_thread_did_exit: bool = False
        self._read_thread_exception: Optional[Exception] = None
        self.report_in_size = None
        self.report_out_size = None

    def set_packet_count(self, count):
        # hidapi for macos has an arbitrary limit on the number of packets it will queue for reading.
        # Even though we have a read thread, it doesn't hurt to limit the packet count since the limit
        # is fairly high.
        if _IS_DARWIN:
            count = min(count, self.HIDAPI_MAX_PACKET_COUNT)
        self.packet_count = count

    def open(self):

        # Use pyUSB to get HID Interrupt EP wMaxPacketSize, since hidapi is not reliable

        # Get device handle.
        # If multiple identical (same PID & VID) probes without serial number are connected,
        # assume they share the same wMaxPacketSize.

        usb_serial = self.device_info['serial_number']

        kwargs = {'idVendor': self.vid, 'idProduct': self.pid}
        if usb_serial:  # only pass a real USB serial
            kwargs['serial_number'] = usb_serial

        probe_id = usb_serial or f"VID={self.vid:#06x}:PID={self.pid:#06x}"

        dev = usb_find(**kwargs)
        if dev is None:
            raise DAPAccessIntf.DeviceError(f"Probe {probe_id} not found")

        # Get active config
        config = dev.get_active_configuration()

        # Get count of HID interfaces and create the matcher object
        hid_interface_count = len(list(usb.util.find_descriptor(config, find_all=True, bInterfaceClass=USB_CLASS_HID)))
        matcher = MatchCmsisDapv1Interface(hid_interface_count)

        # Get CMSIS-DAPv1 interface
        interface = usb.util.find_descriptor(config, custom_match=matcher)
        if interface is None:
            raise DAPAccessIntf.DeviceError(f"Probe {probe_id} has no CMSIS-DAPv1 interface")

        # Set report sizes, assuming HID report size matches endpoint wMaxPacketSize.
        for endpoint in interface:
            if usb.util.endpoint_type(endpoint.bmAttributes) == usb.util.ENDPOINT_TYPE_INTR:
                if endpoint.bEndpointAddress & usb.util.ENDPOINT_IN:
                    self.report_in_size = endpoint.wMaxPacketSize
                else:
                    self.report_out_size = endpoint.wMaxPacketSize

        if self.report_in_size is None:
            raise DAPAccessIntf.DeviceError(
                f"Could not determine packet sizes for probe {probe_id}")

        if self.report_out_size is None:
            # No interrupt OUT endpoint. Out reports will be sent via control transfer.
            # Assuming out report size matches in report size.
            self.report_out_size = self.report_in_size

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

        self.closed = False

    def rx_task(self):
        try:
            while not self.closed_event.is_set():
                self.read_sem.acquire()
                if not self.closed_event.is_set():
                    read_data = bytes(self.device.read(self.report_in_size))

                    # This trace log is commented out to reduce clutter, but left in to leave available
                    # when debugging rx_task issues.
                    # if TRACE.isEnabledFor(logging.DEBUG):
                    #     # Strip off trailing zero bytes to reduce clutter.
                    #     TRACE.debug("  USB RD < (%d) %s", len(read_data),
                    #                 ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

                    self.received_data.put(read_data)
        except Exception as err:
            TRACE.debug("rx_task exception: %s", err)
            self._read_thread_exception = err
        finally:
            self._swo_thread_did_exit = True

    @staticmethod
    def get_all_connected_interfaces():
        """@brief Returns all the connected devices with CMSIS-DAP in the name.

        returns an array of HidApiUSB (Interface) objects
        """

        devices = hid.enumerate()

        boards = []

        for deviceInfo in devices:
            product_name = to_str_safe(deviceInfo['product_string'])
            known_cmsis_dap = is_known_cmsis_dap_vid_pid(deviceInfo['vendor_id'], deviceInfo['product_id'])
            if ("CMSIS-DAP" not in product_name) and (not known_cmsis_dap):
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
            new_board = HidApiUSB(dev, deviceInfo)
            boards.append(new_board)

        return boards

    def write(self, data):
        """@brief Write data on the OUT endpoint associated to the HID interface"""
        if TRACE.isEnabledFor(logging.DEBUG):
            TRACE.debug("  USB OUT> (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))
        data.extend([0] * (self.report_out_size - len(data)))
        if not _IS_WINDOWS:
            self.read_sem.release()
        self.device.write([0] + data)

    def read(self):
        """@brief Read data on the IN endpoint associated to the HID interface"""
        # Windows doesn't use the read thread, so read directly.
        if _IS_WINDOWS:
            read_data = bytes(self.device.read(self.report_in_size))

            if TRACE.isEnabledFor(logging.DEBUG):
                # Strip off trailing zero bytes to reduce clutter.
                TRACE.debug("  USB IN < (%d) %s", len(read_data),
                            ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

            return read_data

        # Check for terminated read thread.
        if self.closed:
            return b''
        elif self._read_thread_did_exit:
            raise DAPAccessIntf.DeviceError("Probe %s read thread exited unexpectedly" % self.serial_number) from self._read_thread_exception

        try:
            read_data = self.received_data.get(True, self.DEFAULT_USB_TIMEOUT_S)
        except queue.Empty:
            raise DAPAccessIntf.DeviceError(f"Timeout reading from probe {self.serial_number}") from None

        # Trace when the higher layer actually gets a packet previously read.
        if TRACE.isEnabledFor(logging.DEBUG):
            # Strip off trailing zero bytes to reduce clutter.
            TRACE.debug("  USB RD < (%d) %s", len(read_data),
                    ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

        return read_data

    def close(self):
        """@brief Close the interface"""
        assert not self.closed_event.is_set()

        LOG.debug("closing interface")
        self.closed = True
        if not _IS_WINDOWS:
            self.closed_event.set()
            self.read_sem.release()
            assert self.thread
            self.thread.join()
            self.thread = None

            # Clear closed event, recreate read sem and received data deque so they
            # are cleared and ready if we're re-opened.
            self.closed_event.clear()
            self.read_sem = threading.Semaphore(0)
            self.received_data = queue.SimpleQueue()
            self._read_thread_did_exit = False
            self._read_thread_exception = None
        self.device.close()

    def set_packet_size(self, size):
        # Custom logic for HID backend
        if size > min(self.report_in_size, self.report_out_size):
            raise DAPAccessIntf.DeviceError(
                f"DAP_Info Packet Size {size} exceeds endpoint wMaxPacketSize {min(self.report_in_size, self.report_out_size)}"
            )
        else:
            self.packet_size = size
