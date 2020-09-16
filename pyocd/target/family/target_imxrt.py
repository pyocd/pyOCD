# pyOCD debugger
# Copyright (c) 2017 NXP
# Copyright (c) 2006-2020 Arm Limited
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
import time
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM

LOG = logging.getLogger(__name__)

class IMXRT(CoreSightTarget):
    VENDOR = "NXP"

    def create_init_sequence(self):
        seq = super(IMXRT, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def create_cores(self):
        core = CortexM7_IMXRT(self.session, self.aps[0], self.memory_map, 0)
        core.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[0].core = core
        core.init()
        self.add_core(core)


class CortexM7_IMXRT(CortexM):

    # System Control Space(SRC)
    SRC_SBMR1 = 0x400F8004
    SRC_SBMR2 = 0x400F801C

    FPB_CTRL = 0xE0002000
    FPB_COMP0 = 0xE0002008

    BOOT_MODES = {
        0x00: "Boot From Fuses",
        0x01: "Serial Download Mode",
        0x02: "Internal Boot",
        0x03: "Reserved"
    }

    def set_reset_catch(self, reset_type=None):
        # Read Boot Mode
        # SBMR2: Bit 25..24:
        # BOOT_MODE[1:0]: 00b - Boot From Fuses
        #                 01b - Serial Downloader
        #                 10b - Internal Boot
        #                 11b - Reserved
        bootmode = (self.read_memory(CortexM7_IMXRT.SRC_SBMR2) & 0x03000000) >> 24
        # Read Boot Device
        # Boot Device: 0000b - Serial NOR boot via FlexSPI
        #              001xb - SD boot via uSDHC
        #              10xxb - eMMC/MMC boot via uSDHC
        #              01xxb - SLC NAND boot via SEMC
        #              0001b - Parallel NOR boot via SEMC
        #              11xxb - Serial NAND boot via FlexSPI
        bootdevice = (self.read_memory(CortexM7_IMXRT.SRC_SBMR1) & 0x000000F0) >> 4
        LOG.info("IMXRT Boot mode: %s" % self.BOOT_MODES[bootmode])
        self.boot_from_flexspi_nor = bootmode == 2 and bootdevice == 0

        if self.boot_from_flexspi_nor and reset_type in \
            (self.ResetType.SW_SYSRESETREQ, self.ResetType.SW_VECTRESET):
            # Disable Reset Vector Catch in DEMCR
            value = self.read_memory(CortexM.DEMCR)
            self.write_memory(CortexM.DEMCR, (value & (~0x00000001)))
            # Read user Image Vector Table address
            vectable = self.read_memory(0x60001004)
            if (vectable != 0xFFFFFFFF):
                # Read user image entry point and clear Thumb bit
                imageentry = self.read_memory(vectable + 4) & (~0x00000001)
                if (imageentry != 0xFFFFFFFF):
                    LOG.debug("vectable: %s, imageentry: %s" % (vectable, imageentry))
                    # Program FPB Comparator 0 to user image entry point
                    self.write_memory(CortexM7_IMXRT.FPB_COMP0, (imageentry | 1))
                    # Enable FPB (FPB_CTRL = FPB_KEY|FPB_ENABLE)
                    self.write_memory(CortexM7_IMXRT.FPB_CTRL, 0x00000003)
                    LOG.debug("enable fpb")

            if not self.is_halted:
                self.halt()
            return
        else:
            super(CortexM7_IMXRT, self).set_reset_catch()

    def clear_reset_catch(self, reset_type=None):
        if not self.boot_from_flexspi_nor:
            super(CortexM7_IMXRT, self).clear_reset_catch()
        else:
            # Disable Reset Vector Catch in DEMCR
            value = self.read_memory(CortexM.DEMCR)
            self.write_memory(CortexM.DEMCR, (value& (~0x00000001)))
            # Clear BP0 and FPB
            self.write_memory(CortexM7_IMXRT.FPB_COMP0, 0);                         # Clear BP0
            self.write_memory(CortexM7_IMXRT.FPB_CTRL, 0x00000002);                # Disable FPB
            LOG.debug("clear fpb")
