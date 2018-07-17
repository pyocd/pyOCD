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
import logging, os, threading
from ..dap_access_api import DAPAccessIntf

try:
    import usb.core
    import usb.util
except:
    if os.name == "posix" and not os.uname()[0] == 'Darwin':
        logging.error("PyUSB is required on a Linux Machine")
    isAvailable = False
else:
    isAvailable = True


class PyUSB(Interface):
    """
    This class provides basic functions to access
    a USB HID device using pyusb:
        - write/read an endpoint
    """

    isAvailable = isAvailable

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
            raise DAPAccessIntf.DeviceError("Device %s not found" %
                                            self.serial_number)

        # get active config
        config = dev.get_active_configuration()

        # Get hid interface
        interface = None
        interface_number = None
        for interface in config:
            if interface.bInterfaceClass == 0x03:
                interface_number = interface.bInterfaceNumber
                break
        if interface_number is None or interface is None:
            raise DAPAccessIntf.DeviceError("Device %s has no hid interface" %
                                            self.serial_number)

        # Find endpoints
        ep_in, ep_out = None, None
        for endpoint in interface:
            if endpoint.bEndpointAddress & 0x80:
                ep_in = endpoint
            else:
                ep_out = endpoint

        # If there is no EP for OUT then we can use CTRL EP.
        # The IN EP is required
        if not ep_in:
            raise DAPAccessIntf.DeviceError("Unable to open device -"
                                            " no endpoints")

        # Detach kernel driver
        kernel_driver_was_attached = False
        try:
            if dev.is_kernel_driver_active(interface_number):
                dev.detach_kernel_driver(interface_number)
                kernel_driver_was_attached = True
        except NotImplementedError as e:
            # Some implementations don't don't have kernel attach/detach
            logging.debug('Exception detaching kernel driver: %s' %
                          str(e))

        # Explicitly claim the interface
        try:
            usb.util.claim_interface(dev, interface_number)
        except usb.core.USBError:
            raise DAPAccessIntf.DeviceError("Unable to open device")

        # Update all class variables if we made it here
        self.ep_out = ep_out
        self.ep_in = ep_in
        self.dev = dev
        self.intf_number = interface_number
        self.kernel_driver_was_attached = kernel_driver_was_attached

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
    def getAllConnectedInterface():
        """
        returns all the connected devices which matches PyUSB.vid/PyUSB.pid.
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
        """
        write data on the OUT endpoint associated to the HID interface
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
            #raise ValueError('EP_OUT endpoint is NULL')

        self.ep_out.write(data)
        #logging.debug('sent: %s', data)
        return


    def read(self):
        """
        read data on the IN endpoint associated to the HID interface
        """
        while len(self.rcv_data) == 0:
            pass
        if self.rcv_data[0] is None:
            raise DAPAccessIntf.DeviceError("Device %s read thread exited" %
                                            self.serial_number)
        return self.rcv_data.pop(0)

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
        assert self.closed is False

        logging.debug("closing interface")
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
                logging.warning('Exception attaching kernel driver: %s',
                                str(exception))
        usb.util.dispose_resources(self.dev)
        self.ep_out = None
        self.ep_in = None
        self.dev = None
        self.intf_number = None
        self.kernel_driver_was_attached = False
        self.thread = None


class FindDap(object):
    """CMSIS-DAP match class to be used with usb.core.find"""

    def __init__(self, serial=None):
        """Create a new FindDap object with an optional serial number"""
        self._serial = serial

    def __call__(self, dev):
        """Return True if this is a DAP device, False otherwise"""
        try:
            device_string = dev.product
        except ValueError as error:
            # Permission denied error gets reported as ValueError (langid)
            logging.debug(("ValueError \"{}\" while trying to access dev.product "
                           "for idManufacturer=0x{:04x} idProduct=0x{:04x}. "
                           "This is probably a permission issue.").format(error, dev.idVendor, dev.idProduct))
            return False
        except usb.core.USBError as error:
            logging.warning("Exception getting product string: %s", error)
            return False
        except IndexError as error:
            logging.warning("Internal pyusb error: %s", error)
            return False
        if device_string is None:
            return False
        if device_string.find("CMSIS-DAP") < 0:
            return False
        if self._serial is not None:
            if self._serial != dev.serial_number:
                return False
        return True
