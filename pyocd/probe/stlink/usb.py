# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

import libusb_package
import usb.core
import usb.util
import logging
from typing import NamedTuple
import platform
import errno
from binascii import hexlify

from ...core import exceptions
from .. import common

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class STLinkInfo(NamedTuple):
    """@brief STLink USB interface numbers and version name."""
    version_name: str
    out_ep: int
    in_ep: int
    swv_ep: int

class STLinkUSBInterface:
    """@brief Provides low-level USB enumeration and transfers for STLinkV2/3 devices."""

    ## Command packet size.
    CMD_SIZE = 16

    ## ST's USB vendor ID
    USB_VID = 0x0483

    ## Map of USB PID to firmware version name and device endpoints.
    #
    # Other PIDs:
    # - 0x3744: STLink V1
    # - 0x374d: STLink V3 DFU
    USB_PID_EP_MAP = {
        # PID              Version  OUT     IN      SWV
        0x3748: STLinkInfo('V2',    0x02,   0x81,   0x83),
        0x374a: STLinkInfo('V2-1',  0x01,   0x81,   0x82),  # Audio
        0x374b: STLinkInfo('V2-1',  0x01,   0x81,   0x82),
        0x374e: STLinkInfo('V3',    0x01,   0x81,   0x82),
        0x374f: STLinkInfo('V3',    0x01,   0x81,   0x82),  # Bridge
        0x3752: STLinkInfo('V2-1',  0x01,   0x81,   0x82),  # No MSD
        0x3753: STLinkInfo('V3',    0x01,   0x81,   0x82),  # 2VCP, No MSD
        0x3754: STLinkInfo('V3',    0x01,   0x81,   0x82),  # No MSD
        0x3755: STLinkInfo('V3',    0x01,   0x81,   0x82),
        0x3757: STLinkInfo('V3',    0x01,   0x81,   0x82),
        }

    ## STLink devices only have one USB interface.
    DEBUG_INTERFACE_NUMBER = 0

    @classmethod
    def _usb_match(cls, dev):
        try:
            # Check VID/PID.
            isSTLink = (dev.idVendor == cls.USB_VID) and (dev.idProduct in cls.USB_PID_EP_MAP)

            # Try accessing the current config, which will cause a permission error on Linux. Better
            # to error out here than later when building the device description. For Windows we
            # don't need to worry about device permissions, but reading descriptors requires special
            # handling due to the libusb bug described in __init__().
            if isSTLink and platform.system() != "Windows":
                dev.get_active_configuration()

            return isSTLink
        except usb.core.USBError as error:
            if error.errno == errno.EACCES and platform.system() == "Linux" \
                and common.should_show_libusb_device_error((dev.idVendor, dev.idProduct)):
                # We've already checked that this is an STLink device by VID/PID, so we
                # can use a warning log level to let the user know it's almost certainly
                # a permissions issue.
                LOG.warning("%s while trying to get the STLink USB device configuration "
                   "(VID=%04x PID=%04x). This can probably be remedied with a udev rule. "
                   "See <https://github.com/pyocd/pyOCD/tree/master/udev> for help.",
                   error, dev.idVendor, dev.idProduct)
            return False
        except (IndexError, NotImplementedError, ValueError) as error:
            return False

    @classmethod
    def get_all_connected_devices(cls):
        try:
            devices = libusb_package.find(find_all=True, custom_match=cls._usb_match)
        except usb.core.NoBackendError:
            common.show_no_libusb_warning()
            return []

        assert devices is not None
        intfList = []
        for dev in devices:
            try:
                intf = cls(dev)
                intfList.append(intf)
            except (ValueError, usb.core.USBError, IndexError, NotImplementedError) as error:
                # Ignore errors that can be raised by libusb, just don't add the device to the list.
                pass

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

        # Open the device temporarily to read the descriptor strings. The Windows libusb
        # (version 1.0.22 at the time of this writing) appears to have a bug where it can fail to
        # properly close a device automatically opened for reading descriptors. The bug manifests
        # as every other call to get_all_connected_devices() returning no available probes,
        # caused by a getting a permissions error ("The device has no langid" ValueError) when
        # attempting to read descriptor strings. If we manually call dispose_resources() after
        # reading the strings, everything is ok. This workaround doesn't cause any issues with
        # Linux or macOS.
        try:
            if len(self._dev.serial_number) == 12:  # Workaround for unprintable characters in the ST-Link V2 probes
                self._serial_number = hexlify(self._dev.serial_number.encode('utf-16-le')[::2])\
                    .decode('utf-8', 'replace').upper()
            else:
                self._serial_number = self._dev.serial_number
            self._vendor_name = self._dev.manufacturer
            self._product_name = self._dev.product
        finally:
            usb.util.dispose_resources(self._dev)

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
            raise exceptions.ProbeError("Unable to find OUT endpoint")
        if not self._ep_in:
            raise exceptions.ProbeError("Unable to find IN endpoint")

        self._max_packet_size = self._ep_in.wMaxPacketSize

        # Claim this interface to prevent other processes from accessing it.
        usb.util.claim_interface(self._dev, self.DEBUG_INTERFACE_NUMBER)

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
    def is_open(self) -> bool:
        return not self._closed

    @property
    def serial_number(self):
        return self._serial_number

    @property
    def vendor_name(self):
        return self._vendor_name

    @property
    def product_name(self):
        return self._product_name

    @property
    def version_name(self):
        return self._info.version_name

    @property
    def max_packet_size(self):
        return self._max_packet_size

    def _flush_rx(self):
        assert self._ep_in

        # Flush the RX buffers by reading until timeout exception
        try:
            while True:
                self._ep_in.read(self._max_packet_size, 1)
        except usb.core.USBError:
            # USB timeout expected
            pass

    def _read(self, size, timeout=1000):
        assert self._ep_in

        # Minimum read size is the maximum packet size.
        read_size = max(size, self._max_packet_size)
        data = self._ep_in.read(read_size, timeout)
        return bytearray(data)[:size]

    def transfer(self, cmd, writeData=None, readSize=None, timeout=1000):
        assert self._ep_out

        # Pad command to required 16 bytes.
        assert len(cmd) <= self.CMD_SIZE
        paddedCmd = bytearray(self.CMD_SIZE)
        paddedCmd[0:len(cmd)] = cmd

        try:
            # Command phase.
            if TRACE.isEnabledFor(logging.DEBUG):
                TRACE.debug("  USB CMD> (%d) %s", len(paddedCmd), ' '.join([f'{i:02x}' for i in paddedCmd]))
            count = self._ep_out.write(paddedCmd, timeout)
            assert count == len(paddedCmd)

            # Optional data out phase.
            if writeData is not None:
                if TRACE.isEnabledFor(logging.DEBUG):
                    TRACE.debug("  USB OUT> (%d) %s", len(writeData), ' '.join([f'{i:02x}' for i in writeData]))
                count = self._ep_out.write(writeData, timeout)
                assert count == len(writeData)

            # Optional data in phase.
            if readSize is not None:
                if TRACE.isEnabledFor(logging.DEBUG):
                    TRACE.debug("  USB IN < (req %d bytes)", readSize)
                data = self._read(readSize)
                if TRACE.isEnabledFor(logging.DEBUG):
                    TRACE.debug("  USB IN < (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))

                # Verify we got all requested data.
                if len(data) < readSize:
                    raise exceptions.ProbeError("received incomplete command response from STLink "
                            f"(got {len(data)}, expected {readSize}")

                return data
        except usb.core.USBError as exc:
            raise exceptions.ProbeError("USB Error: %s" % exc) from exc
        return None

    def read_swv(self, size, timeout=1000):
        assert self._ep_swv
        return bytearray(self._ep_swv.read(size, timeout))

    def __repr__(self):
        return "<{} @ {:#x} vid={:#06x} pid={:#06x} sn={} version={}>".format(
            self.__class__.__name__, id(self),
            self._dev.idVendor, self._dev.idProduct, self.serial_number,
            self.version_name)
