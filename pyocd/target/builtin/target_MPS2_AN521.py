# pyOCD debugger
# Copyright (c) 2023 Arm Limited
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

from typing import Optional
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (RamRegion, MemoryMap)

from ...core.target import Target

# see https://developer.arm.com/documentation/101104/0200/programmers-model/system-control-element/system-control-register-block
SYSTEM_CONTROL = 0x50021000
RESET_MASK = SYSTEM_CONTROL + 0x104
RESET_MASK_SYSRSTREQ0_EN = 1 << 4
RESET_MASK_SYSRSTREQ1_EN = 1 << 5
CPU_WAIT = SYSTEM_CONTROL + 0x118
CPU_WAIT_CPU0 = 1
CPU_WAIT_CPU1 = 2

class AN521(CoreSightTarget):

    VENDOR = "Arm"

    MEMORY_MAP = MemoryMap(
        RamRegion(  name='code_ns',     start=0x00000000, length=0x08000000, access='rwx'),
        RamRegion(  name='code_s',      start=0x10000000, length=0x08000000, access='rwxs'),

        RamRegion(  name='sram_ns',     start=0x20000000, length=0x02000000, access='rwx'),
        RamRegion(  name='mtb_ns',      start=0x24000000, length=0x00004000, access='rwx'),
        RamRegion(  name='sram2_ns',    start=0x28000000, length=0x00200000, access='rwx'),
        RamRegion(  name='sram3_ns',    start=0x28200000, length=0x00200000, access='rwx'),

        RamRegion(  name='sram_s',      start=0x30000000, length=0x02000000, access='rwxs'),
        RamRegion(  name='mtb_s',       start=0x34000000, length=0x00004000, access='rwxs'),
        RamRegion(  name='sram2_s',     start=0x38000000, length=0x00200000, access='rwxs'),
        RamRegion(  name='sram3_s',     start=0x38200000, length=0x00200000, access='rwxs'),
        # External Parallel SRAM only mapped to non-secure
        RamRegion(  name='psram_ns',    start=0x80000000, length=0x01000000, access='rwx'),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def create_init_sequence(self):
        seq = super().create_init_sequence()

        seq.insert_before('halt_on_connect',
            ('enable_sysresetreq',        self._enable_sysresetreq),
        )

        return seq

    def _enable_sysresetreq(self):
        reset_mask = self.read32(RESET_MASK)
        reset_mask |= RESET_MASK_SYSRSTREQ0_EN
        self.write32(RESET_MASK, reset_mask)


    def reset_and_halt(self, reset_type: Optional[Target.ResetType] = None):
        self.write32(CPU_WAIT, CPU_WAIT_CPU1)
        super().reset_and_halt(reset_type)
