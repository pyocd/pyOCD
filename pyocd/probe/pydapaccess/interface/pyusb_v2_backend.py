# pyOCD debugger
# Copyright (c) 2019-2021 Arm Limited
# Copyright (c) 2021 mentha
# Copyright (c) 2021-2023 Chris Reed
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
import errno
import platform
import queue
from typing import List, Optional

from .interface import Interface
from .common import (
    USB_CLASS_VENDOR_SPECIFIC,
    filter_device_by_class,
    is_known_cmsis_dap_vid_pid,
    check_ep,
    generate_device_unique_id,
    )
from ..dap_access_api import DAPAccessIntf
from ... import common
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

class PyUSBv2(Interface):
    """@brief CMSIS-DAPv2 interface using pyUSB."""

    isAvailable = IS_AVAILABLE

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
        self.ep_swo = None
        self.dev = None
        self.intf_number = None
        self.kernel_driver_was_attached = False
        self.closed = True
        self.thread = None
        self.rx_stop_event = threading.Event()
        self.swo_thread = None
        self.swo_stop_event = threading.Event()
        self.rcv_data: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self.swo_data: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self.read_sem = threading.Semaphore(0)
        self.packet_size = 512
        self.is_swo_running = False
        self._read_thread_did_exit: bool = False
        self._read_thread_exception: Optional[Exception] = None
        self._swo_thread_did_exit: bool = False
        self._swo_thread_exception: Optional[Exception] = None

    @property
    def has_swo_ep(self):
        return self.ep_swo is not None

    @property
    def is_bulk(self):
        """@brief Whether the interface uses CMSIS-DAP v2 bulk endpoints."""
        return True

    def open(self):
        assert self.closed is True

        # Get device handle
        dev = libusb_package.find(custom_match=HasCmsisDapv2Interface(self.serial_number))
        if dev is None:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} not found")

        # get active config
        config = dev.get_active_configuration()

        # Get CMSIS-DAPv2 interface
        interface = usb.util.find_descriptor(config, custom_match=_match_cmsis_dap_v2_interface)
        if interface is None:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} has no CMSIS-DAPv2 interface")
        interface_number = interface.bInterfaceNumber

        # Find endpoints. CMSIS-DAPv2 endpoints are in a fixed order.
        try:
            ep_out = interface.endpoints()[0]
            ep_in = interface.endpoints()[1]
            ep_swo = interface.endpoints()[2] if len(interface.endpoints()) > 2 else None
        except IndexError:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} is missing expected endpoints")

        # Explicitly claim the interface
        try:
            usb.util.claim_interface(dev, interface_number)
        except usb.core.USBError as exc:
            raise DAPAccessIntf.DeviceError(f"Unable to claim interface for probe {self.serial_number}") from exc

        # Update all class variables if we made it here
        self.ep_out = ep_out
        self.ep_in = ep_in
        self.ep_swo = ep_swo
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
        thread_name = "CMSIS-DAPv2 receive (%s)" % self.serial_number
        self.thread = threading.Thread(target=self.rx_task, name=thread_name)
        self.thread.daemon = True
        self.thread.start()

    def start_swo(self):
        thread_name = "SWO receive (%s)" % self.serial_number
        self.swo_thread = threading.Thread(target=self.swo_rx_task, name=thread_name)
        self.swo_thread.daemon = True
        self.swo_thread.start()
        self.is_swo_running = True

    def stop_swo(self):
        self.swo_stop_event.set()
        self.swo_thread.join()
        self.swo_stop_event.clear()
        self.swo_thread = None
        self.is_swo_running = False
        self._swo_thread_did_exit = False

    def rx_task(self):
        try:
            while not self.rx_stop_event.is_set():
                self.read_sem.acquire()
                if not self.rx_stop_event.is_set():
                    read_data = self.ep_in.read(self.packet_size,
                                                timeout=self.DEFAULT_USB_TIMEOUT_MS).tobytes()

                    # This trace log is commented out to reduce clutter, but left in to leave available
                    # when debugging rx_task issues.
                    # if TRACE.isEnabledFor(logging.DEBUG):
                    #     TRACE.debug("  USB IN < (%d) %s", len(read_data),
                    #                 ' '.join([f'{i:02x}' for i in read_data]))

                    self.rcv_data.put(read_data)
        except Exception as err:
            TRACE.debug("rx_task exception: %s", err)
            self._read_thread_exception = err
        finally:
            self._swo_thread_did_exit = True

    def swo_rx_task(self):
        try:
            while not self.swo_stop_event.is_set():
                try:
                    data = self.ep_swo.read(self.ep_swo.wMaxPacketSize,
                            timeout=self.DEFAULT_USB_TIMEOUT_MS).tobytes()
                    self.swo_data.put(data)
                except usb.core.USBError:
                    pass
        except Exception as err:
            self._swo_thread_exception = err
        finally:
            # Set last element of swo_data to None on exit
            self._swo_thread_did_exit = True

    @staticmethod
    def get_all_connected_interfaces():
        """@brief Returns all the connected devices with a CMSIS-DAPv2 interface."""
        # find all cmsis-dap devices
        try:
            all_devices = libusb_package.find(find_all=True, custom_match=HasCmsisDapv2Interface())
        except usb.core.NoBackendError:
            common.show_no_libusb_warning()
            return []

        # iterate on all devices found
        boards = [PyUSBv2(board) for board in all_devices]
        return boards

    def write(self, data):
        """@brief Write data on the OUT endpoint."""

        if self.ep_out:
            if (len(data) > 0) and (len(data) < self.packet_size) and (len(data) % self.ep_out.wMaxPacketSize == 0):
                data.append(0)

        if TRACE.isEnabledFor(logging.DEBUG):
            TRACE.debug("  USB OUT> (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))

        self.read_sem.release()

        self.ep_out.write(data, timeout=self.DEFAULT_USB_TIMEOUT_MS)

    def read(self):
        """@brief Read data on the IN endpoint."""
        if self.closed:
            return b''
        elif self._read_thread_did_exit:
            raise DAPAccessIntf.DeviceError("Probe %s read thread exited unexpectedly" % self.serial_number) from self._read_thread_exception

        try:
            data = self.rcv_data.get(True, self.DEFAULT_USB_TIMEOUT_S)
        except queue.Empty:
            raise DAPAccessIntf.DeviceError(f"Timeout reading from probe {self.serial_number}") from None

        # Trace when the higher layer actually gets a packet previously read.
        if TRACE.isEnabledFor(logging.DEBUG):
            TRACE.debug("  USB RD < (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))

        return data

    def read_swo(self):
        # Accumulate all available SWO data.
        data = bytearray()
        if not self.is_swo_running:
            return data
        elif self._swo_thread_did_exit:
            raise DAPAccessIntf.DeviceError(f"Probe {self.serial_number} read thread exited unexpectedly") \
                from self._read_thread_exception

        while True:
            try:
                data += self.swo_data.get(block=False)
            except queue.Empty:
                break

        return data

    def close(self):
        """@brief Close the USB interface."""
        assert self.closed is False

        if self.is_swo_running:
            self.stop_swo()
        self.closed = True
        self.rx_stop_event.set()
        self.read_sem.release()
        self.thread.join()
        self.rx_stop_event.clear() # Reset the stop event.
        self.rcv_data = queue.SimpleQueue() # Recreate queue to ensure it's empty.
        self.swo_data = queue.SimpleQueue()
        usb.util.release_interface(self.dev, self.intf_number)
        usb.util.dispose_resources(self.dev)
        self.ep_out = None
        self.ep_in = None
        self.ep_swo = None
        self.dev = None
        self.intf_number = None
        self.thread = None
        self._read_thread_did_exit = False
        self._read_thread_exception = None

def _match_cmsis_dap_v2_interface(interface):
    """@brief Returns true for a CMSIS-DAP v2 interface.

    This match function performs several tests on the provided USB interface descriptor, to
    determine whether it is a CMSIS-DAPv2 interface. These requirements must be met by the
    interface:

    1. Have an interface name string containing "CMSIS-DAP".
    2. bInterfaceClass must be 0xff.
    3. bInterfaceSubClass must be 0.
    4. Must have bulk out and bulk in endpoints, with an optional extra bulk in endpoint, in
        that order.
    """
    try:
        interface_name = usb.util.get_string(interface.device, interface.iInterface)

        # This tells us whether the interface is CMSIS-DAP, but not whether it's v1 or v2.
        if (interface_name is None) or ("CMSIS-DAP" not in interface_name):
            return False

        # Now check the interface class to distinguish v1 from v2.
        if (interface.bInterfaceClass != USB_CLASS_VENDOR_SPECIFIC) \
            or (interface.bInterfaceSubClass != 0):
            return False

        # Must have either 2 or 3 endpoints.
        if interface.bNumEndpoints not in (2, 3):
            return False

        # Endpoint 0 must be bulk out.
        if not check_ep(interface, 0, usb.util.ENDPOINT_OUT, usb.util.ENDPOINT_TYPE_BULK):
            return False

        # Endpoint 1 must be bulk in.
        if not check_ep(interface, 1, usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_BULK):
            return False

        # Endpoint 2 is optional. If present it must be bulk in.
        if (interface.bNumEndpoints == 3) \
            and not check_ep(interface, 2, usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_BULK):
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

class HasCmsisDapv2Interface:
    """@brief CMSIS-DAPv2 match class to be used with usb.core.find"""

    def __init__(self, serial=None):
        """@brief Create a new FindDap object with an optional serial number"""
        self._serial = serial

    def __call__(self, dev):
        """@brief Return True if this is a CMSIS-DAPv2 device, False otherwise"""
        # Check if the device class is a valid one for CMSIS-DAP.
        if filter_device_by_class(dev.idVendor, dev.idProduct, dev.bDeviceClass):
            return False

        try:
            config = dev.get_active_configuration()
            cmsis_dap_interface = usb.util.find_descriptor(config, custom_match=_match_cmsis_dap_v2_interface)
        except usb.core.USBError as error:
            # Produce a more helpful error message if we get a permissions error on Linux.
            if error.errno == errno.EACCES and platform.system() == "Linux" \
                and common.should_show_libusb_device_error((dev.idVendor, dev.idProduct)):
                msg = ("%s while trying to interrogate a USB device "
                   "(VID=%04x PID=%04x). This can probably be remedied with a udev rule. "
                   "See <https://github.com/pyocd/pyOCD/tree/master/udev> for help." %
                   (error, dev.idVendor, dev.idProduct))
                # If we recognize this device as one that should be CMSIS-DAP, we can raise
                # the level of the log message since it's almost certainly a permissions issue.
                if is_known_cmsis_dap_vid_pid(dev.idVendor, dev.idProduct):
                    LOG.warning(msg)
                else:
                    LOG.debug(msg)
            return False
        except (IndexError, NotImplementedError, ValueError, UnicodeDecodeError) as error:
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
