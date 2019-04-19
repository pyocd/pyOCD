
# Copyright (c) 2018, Arm Limited and affiliates.
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

import platform

# Make sure that any global generic setup is run
from . import base  # noqa: F401

def create_mbed_detector(**kwargs):
    """! Factory used to create host OS specific mbed-lstools object

    :param kwargs: keyword arguments to pass along to the constructors
    @return Returns MbedLsTools object or None if host OS is not supported

    """
    host_os = platform.system()
    if host_os == "Windows":
        from .windows import StlinkDetectWindows

        return StlinkDetectWindows(**kwargs)
    elif host_os == "Linux":
        from .linux import StlinkDetectLinuxGeneric

        return StlinkDetectLinuxGeneric(**kwargs)
    elif host_os == "Darwin":
        from .darwin import StlinkDetectDarwin

        return StlinkDetectDarwin(**kwargs)
    else:
        return None




