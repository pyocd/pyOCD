# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

from __future__ import absolute_import
from . import STLinkException
import usb.core
import usb.util
import logging
import six
import threading
from collections import namedtuple

# Set to True to enable debug logs of USB data transfers.
LOG_USB_DATA = False

log = logging.getLogger('stlink.usb')

STLinkInfo = namedtuple('STLinkInfo', 'version_name out_ep in_ep swv_ep')

##
# @brief Provides low-level USB enumeration and transfers for STLinkV2/3 devices.
class STLinkUSBInterface(object):
    ## Command packet size.
    CMD_SIZE = 16
    
    ## ST's USB vendor ID
    USB_VID = 0x0483

    ## Map of USB PID to firmware version name and device endpoints.
    USB_PID_EP_MAP = {
        # PID              Version  OUT     IN      SWV
        0x3748: STLinkInfo('V2',    0x02,   0x81,   0x83),
        0x374b: STLinkInfo('V2-1',  0x01,   0x81,   0x82),
        0x374a: STLinkInfo('V2-1',  0x01,   0x81,   0x82),  # Audio
        0x3742: STLinkInfo('V2-1',  0x01,   0x81,   0x82),  # No MSD
        0x374e: STLinkInfo('V3',    0x01,   0x81,   0x82),
        0x374f: STLinkInfo('V3',    0x01,   0x81,   0x82),  # Bridge
        0x3753: STLinkInfo('V3',    0x01,   0x81,   0x82),  # 2VCP
        }
    
    ## STLink devices only have one USB interface.
    DEBUG_INTERFACE_NUMBER = 0

    @classmethod
    def _usb_match(cls, dev):
        try:
            # Check VID/PID.
            isSTLink = (dev.idVendor == cls.USB_VID) and (dev.idProduct in cls.USB_PID_EP_MAP)
            
            # Try accessing the product name, which will cause a permission error on Linux. Better
            # to error out here than later when building the device description.
            if isSTLink:
                dev.product
            
            return isSTLink
        except ValueError as error:
            # Permission denied error gets reported as ValueError (The device has no langid).
            log.debug("ValueError \"%s\" while trying to access STLink USB device fields (VID=%04x PID=%04x). "
                        "This is probably a permission issue.", error, dev.idVendor, dev.idProduct)
            return False
        except usb.core.USBError as error:
            log.warning("Exception getting device info (VID=%04x PID=%04x): %s", dev.idVendor, dev.idProduct, error)
            return False
        except IndexError as error:
            log.warning("Internal pyusb error (VID=%04x PID=%04x): %s", dev.idVendor, dev.idProduct, error)
            return False
        except NotImplementedError as error:
            log.warning("Received USB unimplemented error (VID=%04x PID=%04x)", dev.idVendor, dev.idProduct)
            return False

    @classmethod
    def get_all_connected_devices(cls):
        try:
            devices = usb.core.find(find_all=True, custom_match=cls._usb_match)
        except usb.core.NoBackendError:
            # Print a warning if pyusb cannot find a backend, and return no probes.
            log.warning("STLink probes are not supported because no libusb library was found.")
            return []
        
        intfList = []
        for dev in devices:
            intf = cls(dev)
            intfList.append(intf)
        
        return intfList

    def __init__(self, dev):
        self._dev = dev
        assert dev.idVendor == self.USB_VID
        self._info = self.USB_PID_EP_MAP[dev.idProduct]
        self._ep_out = None
        self._ep_in = None
        self._ep_swv = None
        self._max_packet_size = 64
        self._closed = True
    
    def open(self):
        assert self._closed
        
        # Debug interface is always interface 0, alt setting 0.
        config = self._dev.get_active_configuration()
        interface = config[(self.DEBUG_INTERFACE_NUMBER, 0)]
        
        # Look up endpoint objects.
        for endpoint in interface:
            if endpoint.bEndpointAddress == self._info.out_ep:
                self._ep_out = endpoint
            elif endpoint.bEndpointAddress == self._info.in_ep:
                self._ep_in = endpoint
            elif endpoint.bEndpointAddress == self._info.swv_ep:
                self._ep_swv = endpoint
        
        if not self._ep_out:
            raise STLinkException("Unable to find OUT endpoint")
        if not self._ep_in:
            raise STLinkException("Unable to find IN endpoint")

        self._max_packet_size = self._ep_in.wMaxPacketSize
        
        # Claim this interface to prevent other processes from accessing it.
        usb.util.claim_interface(self._dev, 0)
        
        self._flush_rx()
        self._closed = False
    
    def close(self):
        assert not self._closed
        self._closed = True
        usb.util.release_interface(self._dev, self.DEBUG_INTERFACE_NUMBER)
        usb.util.dispose_resources(self._dev)
        self._ep_out = None
        self._ep_in = None

    @property
    def serial_number(self):
        return self._dev.serial_number

    @property
    def vendor_name(self):
        return self._dev.manufacturer

    @property
    def product_name(self):
        return self._dev.product

    @property
    def version_name(self):
        return self._info.version_name

    @property
    def max_packet_size(self):
        return self._max_packet_size

    def _flush_rx(self):
        # Flush the RX buffers by reading until timeout exception
        try:
            while True:
                self._ep_in.read(self._max_packet_size, 1)
        except usb.core.USBError:
            # USB timeout expected
            pass

    def _read(self, size, timeout=1000):
        # Minimum read size is the maximum packet size.
        read_size = max(size, self._max_packet_size)
        data = self._ep_in.read(read_size, timeout)
        return bytearray(data)[:size]

    def transfer(self, cmd, writeData=None, readSize=None, timeout=1000):
        # Pad command to required 16 bytes.
        assert len(cmd) <= self.CMD_SIZE
        paddedCmd = bytearray(self.CMD_SIZE)
        paddedCmd[0:len(cmd)] = cmd
        
        try:
            # Command phase.
            if LOG_USB_DATA:
                log.debug("  USB CMD> %s" % ' '.join(['%02x' % i for i in paddedCmd]))
            count = self._ep_out.write(paddedCmd, timeout)
            assert count == len(paddedCmd)
            
            # Optional data out phase.
            if writeData is not None:
                if LOG_USB_DATA:
                    log.debug("  USB OUT> %s" % ' '.join(['%02x' % i for i in writeData]))
                count = self._ep_out.write(writeData, timeout)
                assert count == len(writeData)
            
            # Optional data in phase.
            if readSize is not None:
                if LOG_USB_DATA:
                    log.debug("  USB IN < (%d bytes)" % readSize)
                data = self._read(readSize)
                if LOG_USB_DATA:
                    log.debug("  USB IN < %s" % ' '.join(['%02x' % i for i in data]))
                return data
        except usb.core.USBError as exc:
            six.raise_from(STLinkException("USB Error: %s" % exc), exc)
        return None

    def read_swv(self, size, timeout=1000):
        return self._ep_swv.read(size, timeout)
    
    def __repr__(self):
        return "<{} @ {:#x} vid={:#06x} pid={:#06x} sn={} version={}>".format(
            self.__class__.__name__, id(self),
            self._dev.idVendor, self._dev.idProduct, self.serial_number,
            self.version)
