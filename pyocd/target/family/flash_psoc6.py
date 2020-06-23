# pyOCD debugger
# Copyright (c) 2020 Cypress Semiconductor Corporation
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

from ...core.memory_map import (RamRegion, RomRegion)
from ...flash.flash import Flash

LOG = logging.getLogger(__name__)


class Flash_PSoC64(Flash):
    isFlashing = False

    def init(self, operation, address=None, clock=0, reset=True):
        if self._active_operation != operation and self._active_operation is not None:
            self.uninit()

        Flash_PSoC64.isFlashing = True
        super(Flash_PSoC64, self).init(operation, address, clock, reset)
        Flash_PSoC64.isFlashing = True
        LOG.debug("Flash_PSoC64: initialised for %s", operation)

    def uninit(self):
        if self._active_operation is None:
            return

        super(Flash_PSoC64, self).uninit()
        Flash_PSoC64.isFlashing = False
        LOG.debug("Flash_PSoC64: uninitialised")


class PSoC6FlashParams:
    # Main/Work Flash flash operation weights
    MFLASH_ERASE_ALL_WEIGHT = 0.5
    MFLASH_ERASE_SECTOR_WEIGHT = 0.05
    MFLASH_PROGRAM_PAGE_WEIGHT = 0.07

    # External (SMIF) Flash flash operation weights
    SMIF_ERASE_ALL_WEIGHT = 140
    SMIF_ERASE_SECTOR_WEIGHT = 1
    SMIF_PROGRAM_PAGE_WEIGHT = 0.5

    defaultRomRegion = RomRegion(start=0x00000000, length=0x20000)
    defaultRamRegion = RamRegion(start=0x08000000, length=0x8000)
