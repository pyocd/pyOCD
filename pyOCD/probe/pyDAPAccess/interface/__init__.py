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

import os
import logging
from .hidapi_backend import HidApiUSB
from .pyusb_backend import PyUSB
from .pywinusb_backend import PyWinUSB
from .ws_backend import WebSocketInterface

INTERFACE = {
             'hidapiusb': HidApiUSB,
             'pyusb': PyUSB,
             'pywinusb': PyWinUSB,
             'ws': WebSocketInterface
            }

# Allow user to override backend with an environment variable.
usb_backend = os.getenv('PYOCD_USB_BACKEND', "")

ws_backend = "ws"

# Check validity of backend env var.
if usb_backend and ((usb_backend not in INTERFACE) or (not INTERFACE[usb_backend].isAvailable)):
    logging.error("Invalid USB backend specified in PYOCD_USB_BACKEND: " + usb_backend)
    usb_backend = ""

# Select backend based on OS and availability.
if not usb_backend:
    if os.name == "nt":
        # Prefer hidapi over pyWinUSB for Windows, since pyWinUSB has known bug(s)
        if HidApiUSB.isAvailable:
            usb_backend = "hidapiusb"
        elif PyWinUSB.isAvailable:
            usb_backend = "pywinusb"
        else:
            raise Exception("No USB backend found")
    elif os.name == "posix":
        # Select hidapi for OS X and pyUSB for Linux.
        if os.uname()[0] == 'Darwin':
            usb_backend = "hidapiusb"
        else:
            usb_backend = "pyusb"
    else:
        raise Exception("No USB backend found")

