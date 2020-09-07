# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (RamRegion, MemoryMap)

class AN522(CoreSightTarget):

    VENDOR = "Arm"
    
    MEMORY_MAP = MemoryMap(
        RamRegion(  name='itcm',        start=0x00000000, length=0x00080000, access='rwx'),
        RamRegion(  name='sram',        start=0x30000000, length=0x00100000, access='rwx'),
        RamRegion(  name='dram6_ns',    start=0x60000000, length=0x10000000, access='rwx'),
        RamRegion(  name='dram7_s',     start=0x70000000, length=0x10000000, access='rwxs'),
        RamRegion(  name='dram8_ns',    start=0x80000000, length=0x10000000, access='rwx'),
        RamRegion(  name='dram9_s',     start=0x90000000, length=0x10000000, access='rwxs'),
        )

    def __init__(self, session):
        super(AN522, self).__init__(session, self.MEMORY_MAP)

