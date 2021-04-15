# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

import re
from collections import namedtuple

from . import target_imxrt
from . import target_kinetis
from . import target_lpc5500
from . import target_nRF52

## @brief Container for family matching information.
FamilyInfo = namedtuple("FamilyInfo", "vendor matches klass")

## @brief Lookup table to convert from CMSIS-Pack family names to a family class.
#
# The vendor name must be an exact match to the 'Dvendor' attribute of the CMSIS-Pack family
# element.
#
# The regexe must match the entirety of one the CMSIS-Pack attributes 'Dfamily','DsubFamily' (if
# present), or the 'Dname' or 'Dvariant' part numbers. The comparisons are performed in order from
# specific to general, starting with the part number.
FAMILIES = [
    FamilyInfo("NXP",                   re.compile(r'LPC55?[0-9]{2}.*'),    target_lpc5500.LPC5500Family    ),
    FamilyInfo("NXP",                   re.compile(r'MIMXRT[0-9]{4}.*'),    target_imxrt.IMXRT              ),
    FamilyInfo("NXP",                   re.compile(r'MK[LEVWS]?.*'),        target_kinetis.Kinetis          ),
    FamilyInfo("Nordic Semiconductor",  re.compile(r'nRF52[0-9]+.*'),       target_nRF52.NRF52              ),
    ]
