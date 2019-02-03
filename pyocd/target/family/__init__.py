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

import re
from collections import namedtuple

from . import target_kinetis

FamilyInfo = namedtuple("FamilyInfo", "vendor matches klass")

## @brief Lookup table to convert from CMSIS-Pack family names to a family class.
#
# The vendor name must be an exact match to the 'Dvendor' attribute of the CMSIS-Pack family
# element.
#
# At least one of the regexes must match the entirety of either the CMSIS-Pack 'Dfamily' or
# 'DsubFamily' (if present) attributes.
FAMILIES = [
    FamilyInfo("NXP",   [re.compile(r'MK[LEVWS]?.*')],              target_kinetis.Kinetis),
    ]
