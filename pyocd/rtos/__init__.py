# pyOCD debugger
# Copyright (c) 2016,2020 Arm Limited
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

import pkg_resources

from .provider import ThreadProvider
from .argon import ArgonThreadProvider
from .freertos import FreeRTOSThreadProvider
from .zephyr import ZephyrThreadProvider
from .rtx5 import RTX5ThreadProvider
from ..core.plugin import load_plugin_classes_of_type

## @brief Dictionary of loaded RTOS plugins, indexed by name.
RTOS = {}

# Load RTOS plugins when this module is loaded.
load_plugin_classes_of_type('pyocd.rtos', RTOS, ThreadProvider)
