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
from .common import (USB_CLASS_HID, filter_device_by_class, is_known_cmsis_dap_vid_pid, check_ep)
from ..dap_access_api import DAPAccessIntf
import logging
import os
import threading
import six
from time import sleep
import platform
import errno

LOG = logging.getLogger(__name__)

try:
    import usb.core
    import usb.util
except:
    if os.name == "posix" and not os.uname()[0] == 'Darwin':
        LOG.error("PyUSB is required on a Linux Machine")
    IS_AVAILABLE = False
else:
    IS_AVAILABLE = True

class PyUSB(Interface):
    """! @brief CMSIS-DAP USB interface class using pyusb for the backend.
    """

    isAvailable = IS_AVAILABLE

    def __init__(self):
        super(PyUSB, self).__init__()
        self.ep_out = None
        self.ep_in = None
        self.dev = None
        self.intf_number = None
        self.serial_number = None
        self.kernel_driver_was_attached = False
        self.closed = True
        self.thread = None
        self.rcv_data = []
        self.read_sem = threading.Semaphore(0)
        self.packet_size = 64

    def open(self):
        assert self.closed is True

        # Get device handle
        dev = usb.core.find(custom_match=FindDap(self.serial_number))
        if dev is None:
            raise DAPAccessIntf.DeviceError("Device %s not found" % self.serial_number)

        # get active config
        config = dev.get_active_configuration()

        # Get CMSIS-DAPv1 interface
        interface = usb.util.find_descriptor(config, custom_match=_match_cmsis_dap_v1_interface)
        if interface is None:
            raise DAPAccessIntf.DeviceError("Device %s has no CMSIS-DAPv1 interface" %
                                            self.serial_number)
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
                dev.detach_kernel_driver(interface_number)
                self.kernel_driver_was_attached = True
        except NotImplementedError as e:
            # Some implementations don't don't have kernel attach/detach
            pass

        # Explicitly claim the interface
        try:
            usb.util.claim_interface(dev, interface_number)
        except usb.core.USBError as exc:
            raise six.raise_from(DAPAccessIntf.DeviceError("Unable to open device"), exc)

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
        self.thread = threading.Thread(target=self.rx_task)
        self.thread.daemon = True
        self.thread.start()

    def rx_task(self):
        try:
            while not self.closed:
                self.read_sem.acquire()
                if not self.closed:
                    self.rcv_data.append(self.ep_in.read(self.ep_in.wMaxPacketSize, 10 * 1000))
        finally:
            # Set last element of rcv_data to None on exit
            self.rcv_data.append(None)

    @staticmethod
    def get_all_connected_interfaces():
        """! @brief Returns all the connected CMSIS-DAP devices.

        returns an array of PyUSB (Interface) objects
        """
        # find all cmsis-dap devices
        all_devices = usb.core.find(find_all=True, custom_match=FindDap())

        # iterate on all devices found
        boards = []
        for board in all_devices:
            new_board = PyUSB()
            new_board.vid = board.idVendor
            new_board.pid = board.idProduct
            new_board.product_name = board.product
            new_board.vendor_name = board.manufacturer
            new_board.serial_number = board.serial_number
            boards.append(new_board)

        return boards

    def write(self, data):
        """! @brief Write data on the OUT endpoint associated to the HID interface
        """

        report_size = self.packet_size
        if self.ep_out:
            report_size = self.ep_out.wMaxPacketSize

        for _ in range(report_size - len(data)):
            data.append(0)

        self.read_sem.release()

        if not self.ep_out:
            bmRequestType = 0x21              #Host to device request of type Class of Recipient Interface
            bmRequest = 0x09              #Set_REPORT (HID class-specific request for transferring data over EP0)
            wValue = 0x200             #Issuing an OUT report
            wIndex = self.intf_number  #mBed Board interface number for HID
            self.dev.ctrl_transfer(bmRequestType, bmRequest, wValue, wIndex, data)
            return

        self.ep_out.write(data)

    def read(self):
        """! @brief Read data on the IN endpoint associated to the HID interface
        """
        while len(self.rcv_data) == 0:
            sleep(0)

        if self.rcv_data[0] is None:
            raise DAPAccessIntf.DeviceError("Device %s read thread exited" %
                                            self.serial_number)
        return self.rcv_data.pop(0)

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
        assert self.closed is False

        LOG.debug("closing interface")
        self.closed = True
        self.read_sem.release()
        self.thread.join()
        assert self.rcv_data[-1] is None
        self.rcv_data = []
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

def _match_cmsis_dap_v1_interface(interface):
    """! @brief Returns true for a CMSIS-DAPv1 interface.
    
    This match function performs several tests on the provided USB interface descriptor, to
    determine whether it is a CMSIS-DAPv1 interface. These requirements must be met by the
    interface:
    
    1. Have an interface name string containing "CMSIS-DAP".
    2. bInterfaceClass must be 0x03 (HID).
    3. bInterfaceSubClass must be 0.
    4. Must have interrupt in endpoint, with an optional interrupt out endpoint, in that order.
    """
    try:
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
        
        # Endpoint 0 must be interrupt in.
        if not check_ep(interface, 0, usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_INTR):
            return False
        
        # Endpoint 1 is optional. If present it must be interrupt out.
        if (interface.bNumEndpoints == 2) \
            and not check_ep(interface, 1, usb.util.ENDPOINT_OUT, usb.util.ENDPOINT_TYPE_INTR):
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

class FindDap(object):
    """! @brief CMSIS-DAP match class to be used with usb.core.find"""

    def __init__(self, serial=None):
        """! @brief Create a new FindDap object with an optional serial number"""
        self._serial = serial

    def __call__(self, dev):
        """! @brief Return True if this is a DAP device, False otherwise"""
        # Check if the device class is a valid one for CMSIS-DAP.
        if filter_device_by_class(dev.idVendor, dev.idProduct, dev.bDeviceClass):
            return False
        
        try:
            # First attempt to get the active config. This produces a more direct error
            # when you don't have device permissions on Linux
            config = dev.get_active_configuration()
            
            # Now read the product name string.
            device_string = dev.product
            if (device_string is None) or ("CMSIS-DAP" not in device_string):
                return False
            
            cmsis_dap_interface = usb.util.find_descriptor(config, custom_match=_match_cmsis_dap_v1_interface)
        except usb.core.USBError as error:
            if error.errno == errno.EACCES and platform.system() == "Linux":
                msg = ("%s while trying to interrogate a USB device "
                   "(VID=%04x PID=%04x). This can probably be remedied with a udev rule. "
                   "See <https://github.com/mbedmicro/pyOCD/tree/master/udev> for help." %
                   (error, dev.idVendor, dev.idProduct))
                # If we recognize this device as one that should be CMSIS-DAP, we can raise
                # the level of the log message since it's almost certainly a permissions issue.
                if is_known_cmsis_dap_vid_pid(dev.idVendor, dev.idProduct):
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
            if self._serial != dev.serial_number:
                return False
        return True
