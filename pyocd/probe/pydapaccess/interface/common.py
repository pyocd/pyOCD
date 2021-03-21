# pyOCD debugger
# Copyright (c) 2019-2021 Arm Limited
# Copyright (c) 2021 mentha
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

import usb.util
from hashlib import sha1
from base64 import b32encode
from typing import (List, Union)

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

# Known USB VID/PID pairs.
ARM_DAPLINK_ID = (0x0d28, 0x0204) # Arm DAPLink firmware
ATMEL_ICE_ID = (0x03eb, 0x2141) # Atmel-ICE
CYPRESS_KITPROG1_2_ID = (0x04b4, 0xf138) # Cypress KitProg1, KitProg2 in CMSIS-DAP mode
CYPRESS_MINIPROG4_BULK_ID = (0x04b4, 0xf151) # Cypress MiniProg4 bulk
CYPRESS_MINIPROG4_HID_ID = (0x04b4, 0xf152) # Cypress MiniProg4 HID
CYPRESS_KITPROG3_HID_ID = (0x04b4, 0xf154) # Cypress KitProg3 HID
CYPRESS_KITPROG3_BULKD_ID = (0x04b4, 0xf155) # Cypress KitProg3 bulk
CYPRESS_KITPROG3_BULK_2_UART_ID = (0x04b4, 0xf166) # Cypress KitProg3 bulk with 2x UART
KEIL_ULINKPLUS_ID = (0xc251, 0x2750) # Keil ULINKplus
NXP_LPCLINK2_ID = (0x1fc9, 0x0090) # NXP LPC-LinkII
NXP_MCULINK_ID = (0x1fc9, 0x0143) # NXP MCU-Link

## List of VID/PID pairs for known CMSIS-DAP USB devices.
KNOWN_CMSIS_DAP_IDS = [
    ARM_DAPLINK_ID,
    ATMEL_ICE_ID,
    CYPRESS_KITPROG1_2_ID,
    CYPRESS_MINIPROG4_BULK_ID,
    CYPRESS_MINIPROG4_HID_ID,
    CYPRESS_KITPROG3_HID_ID,
    CYPRESS_KITPROG3_BULKD_ID,
    CYPRESS_KITPROG3_BULK_2_UART_ID,
    KEIL_ULINKPLUS_ID,
    NXP_LPCLINK2_ID,
    NXP_MCULINK_ID,
    ]

## List of VID/PID pairs for CMSIS-DAP probes that have multiple HID interfaces that must be
# filtered by usage page. Currently these are only NXP probes.
CMSIS_DAP_IDS_TO_FILTER_BY_USAGE_PAGE = [
    NXP_LPCLINK2_ID,
    NXP_MCULINK_ID,
    ]

def is_known_cmsis_dap_vid_pid(vid, pid):
    """! @brief Test whether a VID/PID pair belong to a known CMSIS-DAP device."""
    return (vid, pid) in KNOWN_CMSIS_DAP_IDS

def filter_device_by_class(vid, pid, device_class):
    """! @brief Test whether the device should be ignored by comparing bDeviceClass.
    
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

def filter_device_by_usage_page(vid, pid, usage_page):
    """! @brief Test whether the device should be ignored by comparing the HID usage page.
    
    This function performs device-specific tests to determine whether the device is a CMSIS-DAP
    interface. The only current test is for the NXP LPC-Link2, which has extra HID interfaces with
    usage pages other than 0xff00. No generic tests are done regardless of VID/PID, because it is
    not clear whether all CMSIS-DAP devices have the usage page set to the same value.
    
    @retval True Skip the device.
    @retval False The device is valid.
    """
    return ((vid, pid) in CMSIS_DAP_IDS_TO_FILTER_BY_USAGE_PAGE) \
        and (usage_page != CMSIS_DAP_HID_USAGE_PAGE)

def check_ep(interface, ep_index, ep_dir, ep_type):
    """! @brief Tests an endpoint type and direction."""
    ep = interface[ep_index]
    return (usb.util.endpoint_direction(ep.bEndpointAddress) == ep_dir) \
        and (usb.util.endpoint_type(ep.bmAttributes) == ep_type)

def generate_device_unique_id(vid: int, pid: int, *locations: List[Union[int, str]]) -> str:
    """! @brief Generate a semi-stable unique ID from USB device properties.
    
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

