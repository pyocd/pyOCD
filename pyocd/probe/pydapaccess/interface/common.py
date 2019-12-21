# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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

# Various known USB VID/PID values.
ARM_DAPLINK_ID = (0x0d28, 0x0204)
KEIL_ULINKPLUS_ID = (0xc251, 0x2750)
NXP_LPCLINK2_ID = (0x1fc9, 0x0090)

## List of VID/PID pairs for known CMSIS-DAP USB devices.
KNOWN_CMSIS_DAP_IDS = [
    ARM_DAPLINK_ID,
    KEIL_ULINKPLUS_ID,
    NXP_LPCLINK2_ID,
    ]

def is_known_cmsis_dap_vid_pid(vid, pid):
    """! @brief Test whether a VID/PID pair belong to a known CMSIS-DAP device."""
    return (vid, pid) in KNOWN_CMSIS_DAP_IDS

def filter_device_by_class(vid, pid, device_class):
    """! @brief Test whether the device should be ignored by comparing bDeviceClass.
    
    This function checks the device's bDeviceClass to determine whether the it is likely to be
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
    return ((vid, pid) == NXP_LPCLINK2_ID) \
        and (usage_page != CMSIS_DAP_HID_USAGE_PAGE)

def check_ep(interface, ep_index, ep_dir, ep_type):
    """! @brief Tests an endpoint type and direction."""
    ep = interface[ep_index]
    return (usb.util.endpoint_direction(ep.bEndpointAddress) == ep_dir) \
        and (usb.util.endpoint_type(ep.bmAttributes) == ep_type)
