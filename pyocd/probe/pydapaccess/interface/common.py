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

USB_CLASS_COMPOSITE = 0x00
USB_CLASS_MISCELLANEOUS = 0xef

CMSIS_DAP_USB_CLASSES = [
    USB_CLASS_COMPOSITE,
    USB_CLASS_MISCELLANEOUS,
    ]

NXP_VID = 0x1fc9
NXP_LPCLINK2_PID = 0x0090

CMSIS_DAP_HID_USAGE_PAGE = 0xff00

def filter_device(vid, pid, usage_page):
    """! @brief Test whether the device should be ignored.
    
    This function performs device-specific tests to determine whether the device is
    a CMSIS-DAP interface. An example is the NXP LPC-Link2, which has extra HID interfaces
    with usage pages other than 0xff00.
    
    @retval True Skip the device.
    @retval False The device is valid.
    """
    return (vid == NXP_VID) and (pid == NXP_LPCLINK2_PID) \
        and (usage_page != CMSIS_DAP_HID_USAGE_PAGE)

