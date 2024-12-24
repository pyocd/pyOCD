# pyOCD debugger
# Copyright (c) 2006-2021 Arm Limited
# Copyright (c) 2020 Patrick Huesmann
# Copyright (c) 2021 mentha
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
import threading
import platform
import errno
import queue
from typing import Optional

from .interface import Interface
from .common import (
    USB_CLASS_HID,
    filter_device_by_class,
    is_known_device_string,
    is_known_cmsis_dap_vid_pid,
    generate_device_unique_id,
    )
from ..dap_access_api import DAPAccessIntf
from ....utility.timeout import Timeout

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

try:
    import libusb_package
    import usb.core
    import usb.util
except ImportError:
    IS_AVAILABLE = False
else:
    IS_AVAILABLE = True

class PyUSB(Interface):
    """@brief CMSIS-DAP USB interface class using pyusb for the backend."""

    isAvailable = IS_AVAILABLE

    did_show_no_libusb_warning = False

    def __init__(self, dev):
        super().__init__()
        self.vid = dev.idVendor
        self.pid = dev.idProduct
        self.product_name = dev.product or f"{dev.idProduct:#06x}"
        self.vendor_name = dev.manufacturer or f"{dev.idVendor:#06x}"
        self.serial_number = dev.serial_number \
                or generate_device_unique_id(dev.idProduct, dev.idVendor, dev.bus, dev.address)
        self.ep_out = None
        self.ep_in = None
        self.dev = None
        self.intf_number = None
        self.kernel_driver_was_attached = False
        self.closed = True
        self.thread = None
        self.rx_stop_event = threading.Event()
        self.rcv_data: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self.read_sem = threading.Semaphore(0)
        self._read_thread_did_exit: bool = False
        self._read_thread_exception: Optional[Exception] = None

    def open(self):
        assert self.closed is True

        # Get device handle
        dev = libusb_package.find(custom_match=FindDap(self.serial_number))
        if dev is None:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} not found")

        # get active config
        config = dev.get_active_configuration()

        # Get count of HID interfaces and create the matcher object
        hid_interface_count = len(list(usb.util.find_descriptor(config, find_all=True, bInterfaceClass=USB_CLASS_HID)))
        matcher = MatchCmsisDapv1Interface(hid_interface_count)

        # Get CMSIS-DAPv1 interface
        interface = usb.util.find_descriptor(config, custom_match=matcher)
        if interface is None:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} has no CMSIS-DAPv1 interface")
        interface_number = interface.bInterfaceNumber

        # Find endpoints
        ep_in, ep_out = None, None
        for endpoint in interface:
            if endpoint.bEndpointAddress & usb.util.ENDPOINT_IN:
                ep_in = endpoint
            else:
                ep_out = endpoint

        # Detach kernel driver
        self.kernel_driver_was_attached = False
        try:
            if dev.is_kernel_driver_active(interface_number):
                LOG.debug("Detaching Kernel Driver of Interface %d from USB device (VID=%04x PID=%04x).", interface_number, dev.idVendor, dev.idProduct)
                dev.detach_kernel_driver(interface_number)
                self.kernel_driver_was_attached = True
        except usb.core.USBError as e:
            LOG.warning("USB Kernel Driver Detach Failed ([%s] %s). Attached driver may interfere with pyOCD operations.", e.errno, e.strerror)
        except NotImplementedError as e:
            # Some implementations don't don't have kernel attach/detach
            LOG.debug("Probe %s: USB kernel driver detaching is not supported. Attached HID driver may interfere with pyOCD operations.", self.serial_number)

        # Explicitly claim the interface
        try:
            usb.util.claim_interface(dev, interface_number)
        except usb.core.USBError as exc:
            raise DAPAccessIntf.DeviceError(f"Unable to claim interface for probe {self.serial_number}") from exc

        # Update all class variables if we made it here
        self.ep_out = ep_out
        self.ep_in = ep_in
        self.dev = dev
        self.intf_number = interface_number

        # Start RX thread as the last step
        self.closed = False
        self.start_rx()

    def start_rx(self):
        # Flush the RX buffers by reading until timeout exception
        try:
            while True:
                self.ep_in.read(self.ep_in.wMaxPacketSize, 1)
        except usb.core.USBError:
            # USB timeout expected
            pass

        # Start RX thread
        thread_name = f"CMSIS-DAPv1 receive ({self.serial_number})"
        self.thread = threading.Thread(target=self.rx_task, name=thread_name)
        self.thread.daemon = True
        self.thread.start()

    def rx_task(self):
        try:
            while not self.rx_stop_event.is_set():
                self.read_sem.acquire()
                if not self.rx_stop_event.is_set():
                    read_data = self.ep_in.read(self.ep_in.wMaxPacketSize,
                            timeout=self.DEFAULT_USB_TIMEOUT_MS).tobytes()

                    # This trace log is commented out to reduce clutter, but left in to leave available
                    # when debugging rx_task issues.
                    # if TRACE.isEnabledFor(logging.DEBUG):
                    #     # Strip off trailing zero bytes to reduce clutter.
                    #     TRACE.debug("  USB IN < (%d) %s", len(read_data),
                    #                 ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

                    self.rcv_data.put(read_data)
        except Exception as err:
            TRACE.debug("rx_task exception: %s", err)
            self._read_thread_exception = err
        finally:
            self._swo_thread_did_exit = True

    @staticmethod
    def get_all_connected_interfaces():
        """@brief Returns all the connected CMSIS-DAP devices.

        returns an array of PyUSB (Interface) objects
        """
        # find all cmsis-dap devices
        try:
            all_devices = libusb_package.find(find_all=True, custom_match=FindDap())
        except usb.core.NoBackendError:
            if not PyUSB.did_show_no_libusb_warning:
                LOG.warning("CMSIS-DAPv1 probes may not be detected because no libusb library was found.")
                PyUSB.did_show_no_libusb_warning = True
            return []

        # iterate on all devices found
        boards = [PyUSB(board) for board in all_devices]

        return boards

    def write(self, data):
        """@brief Write data on the OUT endpoint associated to the HID interface"""

        report_size = self.packet_size
        if self.ep_out:
            report_size = self.ep_out.wMaxPacketSize

        # Trace output data before padding.
        if TRACE.isEnabledFor(logging.DEBUG):
            TRACE.debug("  USB OUT> (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))

        data.extend([0] * (report_size - len(data)))

        self.read_sem.release()

        if not self.ep_out:
            bmRequestType = 0x21       # Host to device request of type Class of Recipient Interface
            bmRequest = 0x09           # Set_REPORT (HID class-specific request for transferring data over EP0)
            wValue = 0x200             # Issuing an OUT report
            wIndex = self.intf_number  # interface number for HID
            self.dev.ctrl_transfer(bmRequestType, bmRequest, wValue, wIndex, data,
                    timeout=self.DEFAULT_USB_TIMEOUT_MS)
        else:
            self.ep_out.write(data, timeout=self.DEFAULT_USB_TIMEOUT_MS)

    def read(self):
        """@brief Read data on the IN endpoint associated to the HID interface"""
        if self.closed:
            return b''
        elif self._read_thread_did_exit:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} read thread exited unexpectedly") \
                from self._read_thread_exception

        try:
            data = self.rcv_data.get(True, self.DEFAULT_USB_TIMEOUT_S)
        except queue.Empty:
            raise DAPAccessIntf.DeviceError(f"Timeout reading from probe {self.serial_number}") from None

        # Trace when the higher layer actually gets a packet previously read.
        if TRACE.isEnabledFor(logging.DEBUG):
            # Strip off trailing zero bytes to reduce clutter.
            TRACE.debug("  USB RD < (%d) %s", len(data),
                    ' '.join([f'{i:02x}' for i in bytes(data).rstrip(b'\x00')]))

        return data

    def close(self):
        """@brief Close the interface"""
        assert self.closed is False

        LOG.debug("closing interface")
        self.closed = True
        self.rx_stop_event.set()
        self.read_sem.release()
        self.thread.join()
        self.rx_stop_event.clear() # Reset the stop event.
        self.rcv_data = queue.SimpleQueue() # Recreate queue to ensure it's empty.
        usb.util.release_interface(self.dev, self.intf_number)
        if self.kernel_driver_was_attached:
            try:
                self.dev.attach_kernel_driver(self.intf_number)
            except Exception as exception:
                LOG.warning('Exception attaching kernel driver: %s',
                                str(exception))
        usb.util.dispose_resources(self.dev)
        self.ep_out = None
        self.ep_in = None
        self.dev = None
        self.intf_number = None
        self.kernel_driver_was_attached = False
        self.thread = None
        self._read_thread_did_exit = False
        self._read_thread_exception = None

class MatchCmsisDapv1Interface:
    """@brief Match class for finding CMSIS-DAPv1 interface.

    This match class performs several tests on the provided USB interface descriptor, to
    determine whether it is a CMSIS-DAPv1 interface. These requirements must be met by the
    interface:

    1. If there is more than one HID interface on the device, the interface must have an interface
        name string containing "CMSIS-DAP".
    2. bInterfaceClass must be 0x03 (HID).
    3. bInterfaceSubClass must be 0.
    4. Must have interrupt in endpoint, with an optional interrupt out endpoint, in that order.
    """

    def __init__(self, hid_interface_count):
        """@brief Constructor."""
        self._hid_count = hid_interface_count

    def __call__(self, interface):
        """@brief Return True if this is a CMSIS-DAPv1 interface."""
        try:
            if self._hid_count > 1:
                interface_name = usb.util.get_string(interface.device, interface.iInterface)

                # This tells us whether the interface is CMSIS-DAP, but not whether it's v1 or v2.
                if (interface_name is None) or ("CMSIS-DAP" not in interface_name):
                    return False

            # Now check the interface class to distinguish v1 from v2.
            if (interface.bInterfaceClass != USB_CLASS_HID) \
                or (interface.bInterfaceSubClass != 0):
                return False

            # Must have either 1 or 2 endpoints.
            if interface.bNumEndpoints not in (1, 2):
                return False

            endpoint_attrs = [
                (usb.util.endpoint_direction(ep.bEndpointAddress),
                 usb.util.endpoint_type(ep.bmAttributes))
                 for ep in interface
            ]

            # Possible combinations of endpoints
            ENDPOINT_ATTRS_ALLOWED = [
                # One interrupt endpoint IN
                [(usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_INTR)],
                # Two interrupt endpoints, first one IN, second one OUT
                [(usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_INTR),
                 (usb.util.ENDPOINT_OUT, usb.util.ENDPOINT_TYPE_INTR)],
                # Two interrupt endpoints, first one OUT, second one IN
                [(usb.util.ENDPOINT_OUT, usb.util.ENDPOINT_TYPE_INTR),
                 (usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_INTR)],
            ]
            if endpoint_attrs not in ENDPOINT_ATTRS_ALLOWED:
                return False

            # All checks passed, this is a CMSIS-DAPv2 interface!
            return True

        except (UnicodeDecodeError, IndexError):
            # UnicodeDecodeError exception can be raised if the device has a corrupted interface name.
            # Certain versions of STLinkV2 are known to have this problem. If we can't read the
            # interface name, there's no way to tell if it's a CMSIS-DAPv2 interface.
            #
            # IndexError can be raised if an endpoint is missing.
            return False

class FindDap:
    """@brief CMSIS-DAP match class to be used with usb.core.find"""

    def __init__(self, serial=None):
        """@brief Create a new FindDap object with an optional serial number"""
        self._serial = serial

    def __call__(self, dev):
        """@brief Return True if this is a DAP device, False otherwise"""
        # Check if the device class is a valid one for CMSIS-DAP.
        if filter_device_by_class(dev.idVendor, dev.idProduct, dev.bDeviceClass):
            return False

        known_cmsis_dap = is_known_cmsis_dap_vid_pid(dev.idVendor, dev.idProduct)
        try:
            # First attempt to get the active config. This produces a more direct error
            # when you don't have device permissions on Linux
            config = dev.get_active_configuration()

            # Now read the product name string.
            device_string = dev.product
            if ((device_string is None) or (not is_known_device_string(device_string))) and (not known_cmsis_dap):
                return False

            # Get count of HID interfaces.
            hid_interface_count = len(list(usb.util.find_descriptor(config, find_all=True, bInterfaceClass=USB_CLASS_HID)))

            # Find the CMSIS-DAPv1 interface.
            matcher = MatchCmsisDapv1Interface(hid_interface_count)
            cmsis_dap_interface = usb.util.find_descriptor(config, custom_match=matcher)
        except usb.core.USBError as error:
            if error.errno == errno.EACCES and platform.system() == "Linux":
                msg = ("%s while trying to interrogate a USB device "
                   "(VID=%04x PID=%04x). This can probably be remedied with a udev rule. "
                   "See <https://github.com/pyocd/pyOCD/tree/master/udev> for help." %
                   (error, dev.idVendor, dev.idProduct))
                # If we recognize this device as one that should be CMSIS-DAP, we can raise
                # the level of the log message since it's almost certainly a permissions issue.
                if known_cmsis_dap:
                    LOG.warning(msg)
                else:
                    LOG.debug(msg)
            else:
                LOG.debug("Error accessing USB device (VID=%04x PID=%04x): %s",
                    dev.idVendor, dev.idProduct, error)
            return False
        except (IndexError, NotImplementedError, ValueError, UnicodeDecodeError) as error:
            LOG.debug("Error accessing USB device (VID=%04x PID=%04x): %s", dev.idVendor, dev.idProduct, error)
            return False

        if cmsis_dap_interface is None:
            return False
        if self._serial is not None:
            if dev.serial_number is None:
                if self._serial == "":
                    return True
                if self._serial == generate_device_unique_id(dev.idProduct, dev.idVendor, dev.bus, dev.address):
                    return True
            if self._serial != dev.serial_number:
                return False
        return True
