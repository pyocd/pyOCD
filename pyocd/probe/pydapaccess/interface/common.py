# pyOCD debugger
# Copyright (c) 2019-2021 Arm Limited
# Copyright (c) 2021 mentha
# Copyright (c) 2021 Chris Reed
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

import usb.util
from hashlib import sha1
from base64 import b32encode
from typing import (List, Tuple, Union, TYPE_CHECKING)

if TYPE_CHECKING:
    from usb.core import Interface

# USB class codes.
USB_CLASS_COMPOSITE = 0x00
USB_CLASS_COMMUNICATIONS = 0x02
USB_CLASS_HID = 0x03
USB_CLASS_MISCELLANEOUS = 0xef
USB_CLASS_VENDOR_SPECIFIC = 0xff

CMSIS_DAP_USB_CLASSES = [
    USB_CLASS_COMPOSITE,
    USB_CLASS_MISCELLANEOUS,
    ]

CMSIS_DAP_HID_USAGE_PAGE = 0xff00

VidPidPair = Tuple[int, int]

# USB vendor IDs.
ARM_VID = 0x0d28
ATMEL_VID = 0x03eb
CYPRESS_VID = 0x04b4
KEIL_VID = 0xc251
NXP_VID = 0x1fc9
VEGA_VID = 0x30cc

# USB VID/PID pairs.
ARM_DAPLINK_ID: VidPidPair = (ARM_VID, 0x0204) # Arm DAPLink firmware
NXP_LPCLINK2_ID: VidPidPair = (NXP_VID, 0x0090) # NXP LPC-LinkII
NXP_MCULINK_ID: VidPidPair = (NXP_VID, 0x0143) # NXP MCU-Link

## List of VID/PID pairs for known CMSIS-DAP USB devices.
#
# Microchip IDs from https://ww1.microchip.com/downloads/en/DeviceDoc/50002630A.pdf.
KNOWN_CMSIS_DAP_IDS: List[VidPidPair] = [
    ARM_DAPLINK_ID,
    (ATMEL_VID, 0x2111), # Microchip EDBG
    (ATMEL_VID, 0x2140), # Microchip JTAGICE3 (firmware version 3 or later)
    (ATMEL_VID, 0x2141), # Microchip Atmel-ICE
    (ATMEL_VID, 0x2144), # Microchip Power Debugger
    (ATMEL_VID, 0x2145), # Microchip mEDBG
    (ATMEL_VID, 0x216c), # Microchip EDBGC
    (ATMEL_VID, 0x2175), # Microchip nEDBG
    (CYPRESS_VID, 0xf138), # Cypress KitProg1, KitProg2 in CMSIS-DAP mode
    (CYPRESS_VID, 0xf148), # Cypress KitProg1, KitProg2 in CMSIS-DAP mode
    (CYPRESS_VID, 0xf151), # Cypress MiniProg4 bulk
    (CYPRESS_VID, 0xf152), # Cypress MiniProg4 HID
    (CYPRESS_VID, 0xf154), # Cypress KitProg3 HID
    (CYPRESS_VID, 0xf155), # Cypress KitProg3 bulk
    (CYPRESS_VID, 0xf166), # Cypress KitProg3 bulk with 2x UART
    (KEIL_VID, 0x2750), # Keil ULINKplus
    (VEGA_VID, 0x9527), # Vega VT-LinkII
    NXP_LPCLINK2_ID,
    NXP_MCULINK_ID,
    (0x1a86, 0x8011),  # WCH-Link
    (0x2a86, 0x8011),  # WCH-Link clone
    ]

## List of substrings to look for in product and interface name strings.
#
# These strings identify a CMSIS-DAP compatible device. According to the specification,
# "CMSIS-DAP" is required. But some low cost probes have misspelled or outright wrong
# or missing strings.
KNOWN_DEVICE_STRINGS: List[str] = (
    "CMSIS-DAP",
    "CMSIS_DAP",
    "WCH-Link",
    )

## List of VID/PID pairs for CMSIS-DAP probes that have multiple HID interfaces that must be
# filtered by usage page. Currently these are only NXP probes.
CMSIS_DAP_IDS_TO_FILTER_BY_USAGE_PAGE: List[VidPidPair] = [
    NXP_LPCLINK2_ID,
    NXP_MCULINK_ID,
    ]

def is_known_cmsis_dap_vid_pid(vid: int, pid: int) -> bool:
    """@brief Test whether a VID/PID pair belong to a known CMSIS-DAP device."""
    return (vid, pid) in KNOWN_CMSIS_DAP_IDS

def is_known_device_string(device_string: str) -> bool:
    return any(s in device_string for s in KNOWN_DEVICE_STRINGS)

def filter_device_by_class(vid: int, pid: int, device_class: int) -> bool:
    """@brief Test whether the device should be ignored by comparing bDeviceClass.

    This function checks the device's bDeviceClass to determine whether it is likely to be
    a CMSIS-DAP device. It uses the vid and pid for device-specific quirks.

    @retval True Skip the device.
    @retval False The device is valid.
    """
    # Check valid classes for CMSIS-DAP firmware.
    if device_class in CMSIS_DAP_USB_CLASSES:
        return False
    # Old "Mbed CMSIS-DAP" firmware has an incorrect bDeviceClass.
    if ((vid, pid) == ARM_DAPLINK_ID) and (device_class == USB_CLASS_COMMUNICATIONS):
        return False
    # Any other class indicates the device is not CMSIS-DAP.
    return True

def filter_device_by_usage_page(vid: int, pid: int, usage_page: int) -> bool:
    """@brief Test whether the device should be ignored by comparing the HID usage page.

    This function performs device-specific tests to determine whether the device is a CMSIS-DAP
    interface. The only current test is for the NXP LPC-Link2, which has extra HID interfaces with
    usage pages other than 0xff00. No generic tests are done regardless of VID/PID, because it is
    not clear whether all CMSIS-DAP devices have the usage page set to the same value.

    @retval True Skip the device.
    @retval False The device is valid.
    """
    return ((vid, pid) in CMSIS_DAP_IDS_TO_FILTER_BY_USAGE_PAGE) \
        and (usage_page != CMSIS_DAP_HID_USAGE_PAGE)

def check_ep(interface: "Interface", ep_index: int, ep_dir: int, ep_type: int) -> bool:
    """@brief Tests an endpoint type and direction."""
    ep = interface[ep_index]
    return ((usb.util.endpoint_direction(ep.bEndpointAddress) == ep_dir) # type:ignore
        and (usb.util.endpoint_type(ep.bmAttributes) == ep_type)) # type:ignore

def generate_device_unique_id(vid: int, pid: int, *locations: Union[int, str]) -> str:
    """@brief Generate a semi-stable unique ID from USB device properties.

    This function is intended to be used in cases where a device does not provide a serial number
    string. pyocd still needs a valid unique ID so the device can be selected from amongst multiple
    connected devices. The algorithm used here generates an ID that is stable for a given device as
    long as it is connected to the same USB port.

    @param vid Vendor ID.
    @param pid Product ID.
    @param locations Additional parameters are expected to be int or string values that represent
        parts of the bus location to which the device is connected. At least one location parameter
        must be provided.
    @return Unique ID string generated from parameeters.
    """
    s = f"{vid:4x},{pid:4x}," + ",".join(str(locations))
    return b32encode(sha1(s.encode()).digest()).decode('ascii')

