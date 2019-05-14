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

import os
import logging
from ..dap_access_api import DAPAccessIntf
from .hidapi_backend import HidApiUSB
from .pyusb_backend import PyUSB
from .pyusb_v2_backend import PyUSBv2
from .pywinusb_backend import PyWinUSB

LOG = logging.getLogger(__name__)

INTERFACE = {
             'hidapiusb': HidApiUSB,
             'pyusb': PyUSB,
             'pyusb_v2': PyUSBv2,
             'pywinusb': PyWinUSB,
            }

# Allow user to override backend with an environment variable.
USB_BACKEND = os.getenv('PYOCD_USB_BACKEND', "") # pylint: disable=invalid-name

# Check validity of backend env var.
if USB_BACKEND and ((USB_BACKEND not in INTERFACE) or (not INTERFACE[USB_BACKEND].isAvailable)):
    LOG.error("Invalid USB backend specified in PYOCD_USB_BACKEND: " + USB_BACKEND)
    USB_BACKEND = ""

# Select backend based on OS and availability.
if not USB_BACKEND:
    if os.name == "nt":
        # Prefer hidapi over pyWinUSB for Windows, since pyWinUSB has known bug(s)
        if HidApiUSB.isAvailable:
            USB_BACKEND = "hidapiusb"
        elif PyWinUSB.isAvailable:
            USB_BACKEND = "pywinusb"
        else:
            raise DAPAccessIntf.DeviceError("No USB backend found")
    elif os.name == "posix":
        # Select hidapi for OS X and pyUSB for Linux.
        if os.uname()[0] == 'Darwin':
            USB_BACKEND = "hidapiusb"
        else:
            USB_BACKEND = "pyusb"
    else:
        raise DAPAccessIntf.DeviceError("No USB backend found")

USB_BACKEND_V2 = "pyusb_v2"
