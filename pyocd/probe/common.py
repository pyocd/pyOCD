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

import logging

LOG = logging.getLogger(__name__)

## Whether the warning about no libusb was printed already.
#
# Used to prevent warning spewage if repeatedly scanning for probes, such as when ConnectHelper
# is used in blocking mode and no probes are connected.
did_show_no_libusb_warning = False

## Set of VID/PID tuples for which libusb errors have been reported.
#
# Used to prevent spewing lots of errors for the same devices when repeatedly scanning for probes.
libusb_error_device_set = set()

def show_no_libusb_warning():
    """! @brief Logs a warning about missing libusb library only the first time it is called."""
    global did_show_no_libusb_warning
    if not did_show_no_libusb_warning:
        LOG.warning("STLink, CMSIS-DAPv2 and PicoProbe probes are not supported because no libusb library was found.")
        did_show_no_libusb_warning = True

def should_show_libusb_device_error(vidpid):
    """! @brief Returns whether a debug warning should be shown for the given VID/PID pair.

    The first time a given VID/PID is passed to this function, the result will be True. Any
    subsequent times, False will be returned for the same VID/PID pair.

    @param vidpi A bi-tuple of USB VID and PID, in that order.
    """
    should_log = vidpid not in libusb_error_device_set
    libusb_error_device_set.add(vidpid)
    return should_log
