# pyOCD debugger
# Copyright (c) 2023 Northern Mechatronics, Inc.
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

from ...coresight.cortex_m import CortexM

LOG = logging.getLogger(__name__)

class AMA3BFamily(CortexM):
    REG_MCU_CTRL_BOOTLOADER = 0x400201A0
    REG_MCU_CTRL_SCRATCH0 = 0x400201B0

    def set_reset_catch(self, reset_type=None):
        # If Debugger Support is disabled by the SDBG bit in INFO0_SECURITY,
        # The least significant bit of register REG_MCU_CTRL_SCRATCH0 must be
        # set to indicate that a halt is requested by the debugger after
        # primary boot.
        #
        # Refer to document A-SOCA3B-UGGA02EN for more details.
        
        # Check the REG_MCU_CTRL_BOOTLOADER register to see if secure boot
        # is enabled for:
        #   bit 31:30 warm reset
        #   bit 29:28 cold reset
        #   bit 27:26 secure boot feature enabled
        secure_boot = False
        reg_bootloader = self.read_memory(self.REG_MCU_CTRL_BOOTLOADER)
        if (reg_bootloader & 0xFC000000):
            secure_boot = True
        LOG.debug("AMA3B Secure Boot: %x" % secure_boot)
        
        if(secure_boot is True):
            # Modify only the least significant bit and preserve the scratch
            # register as it could be used by the application firmware.
            reg_scratch0 = self.read_memory(self.REG_MCU_CTRL_SCRATCH0) | 0x01
            self.write_memory(self.REG_MCU_CTRL_SCRATCH0, reg_scratch0)
        else:
            LOG.debug("normal_set_reset_catch")
            super().set_reset_catch(reset_type)
