# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2019 Monadnock Systems Ltd.
# Copyright (c) 2024 Nordic Semiconductor ASA
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
from time import sleep
import os
import re
from zipfile import ZipFile
from tempfile import TemporaryDirectory
from intelhex import IntelHex

from ...core import exceptions
from ...core.memory_map import FlashRegion
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...flash.eraser import FlashEraser
from ...flash.file_programmer import FileProgrammer
from ...utility.timeout import Timeout
from ...utility.progress import print_progress
from ...commands.base import CommandBase
from ...commands.execution_context import CommandSet

AHB_AP_NUM = 0x0
AUX_AHB_AP_NUM = 0x1
CTRL_AP_NUM = 0x2

CTRL_AP_RESET = 0x000
CTRL_AP_ERASEALL = 0x004
CTRL_AP_ERASEALLSTATUS = 0x008
CTRL_AP_ERASEPROTECTSTATUS = 0x00C
CTRL_AP_ERASEPROTECTDISABLE = 0x010
CTRL_AP_APPROTECTSTATUS = 0x014
CTRL_AP_MAILBOX_TXDATA = 0x020
CTRL_AP_MAILBOX_TXSTATUS = 0x024
CTRL_AP_MAILBOX_RXDATA = 0x028
CTRL_AP_MAILBOX_RXSTATUS = 0x02C
CTRL_AP_IDR = 0x0FC

CTRL_AP_ERASEALLSTATUS_READY = 0x0
CTRL_AP_ERASEALLSTATUS_READYTORESET = 0x1
CTRL_AP_ERASEALLSTATUS_BUSY = 0x2
CTRL_AP_ERASEALLSTATUS_ERROR = 0x3

CTRL_AP_APPROTECTSTATUS_APPROTECT_MSK = 0x1
CTRL_AP_APPROTECTSTATUS_SECUREAPPROTECT_MSK = 0x2
CTRL_AP_ERASEPROTECTSTATUS_MSK = 0x1

CTRL_IDR_EXPECTED = 0x32880000

MASS_ERASE_TIMEOUT = 30.0

CSW_DEVICEEN =  0x00000040

LOG = logging.getLogger(__name__)

def bytes_to_word(bts):
    result = 0
    for i, b in enumerate(bts):
        result |= b << (8*i)
    return result

def word_to_bytes(wrd):
    result = []
    for i in range(4):
        result.append((wrd >> (8*i)) & 0xFF)
    return bytes(result)

class NRF54L(CoreSightTarget):

    VENDOR = "Nordic Semiconductor"

    def __init__(self, session, memory_map=None):
        super(NRF54L, self).__init__(session, memory_map)
        self.ctrl_ap = None
        self.was_locked = False

    def create_init_sequence(self):
        seq = super(NRF54L, self).create_init_sequence()

        # Must check whether security is enabled, and potentially auto-unlock, before
        # any init tasks that require system bus access.
        seq.wrap_task('discovery',
            lambda seq: seq.insert_before('find_components',
                              ('check_ctrl_ap_idr', self.check_ctrl_ap_idr),
                              ('check_flash_security', self.check_flash_security),
                          )
            )
        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_aps', ('fixup_rom_base', self.fixup_rom_base))
            )
        seq.insert_before('post_connect_hook',
                          ('check_part_info', self.check_part_info))

        return seq

    def fixup_rom_base(self):
        self.aps[0].rom_addr = 0xE00FE000
        self.aps[0].has_rom_table = True

    def check_ctrl_ap_idr(self):
        LOG.info("Checking CTRL-AP IDR")
        self.ctrl_ap = self.dp.aps[CTRL_AP_NUM]

        # Check CTRL-AP ID.
        if self.ctrl_ap.idr != CTRL_IDR_EXPECTED:
            LOG.error("%s: bad CTRL-AP IDR (is 0x%08x)", self.part_number, self.ctrl_ap.idr)

    def ap_is_enabled(self):
        csw = self.dp.read_ap(AHB_AP_NUM << 24)
        return csw & CSW_DEVICEEN

    def check_flash_security(self):
        """@brief Check security and unlock device.

        This init task determines whether the device is locked (APPROTECT enabled). If it is,
        and if auto unlock is enabled, then perform a mass erase to unlock the device.

        This init task runs *before* cores are created.
        """

        target_id = self.dp.read_dp(0x24)
        if target_id & 0xFFF != 0x289:
            LOG.error(f"This doesn't look like a Nordic Semiconductor device!")
        if target_id & 0xF0000 != 0xC0000:
            LOG.error(f"This doesn't look like an nRF54L device!")

        if not self.ap_is_enabled():
            if self.session.options.get('auto_unlock'):
                LOG.warning("%s APPROTECT enabled: will try to unlock via mass erase", self.part_number)

                self.mass_erase()
        else:
            LOG.warning("%s is not in a secure state", self.part_number)


    def check_part_info(self):
        partno = self.read32(0x00FFC31C)
        variant = self.read32(0x00FFC320)

        LOG.info(f"This appears to be an nRF{partno:X} " +
                 f"{word_to_bytes(variant).decode('ASCII', errors='ignore')}")

        deviceaddr = (self.read32(0x00FFC3A4),self.read32(0x00FFC3A8))
        mac_bytes = list(word_to_bytes(deviceaddr[0]) + word_to_bytes(deviceaddr[1])[:2])
        mac_bytes[5] |= 0xc0 # Set a Bluetooth LE random address as a static address
        mac = ":".join(f"{x:02X}" for x in mac_bytes[::-1])
        LOG.info(f"BLE MAC: {mac}")

    def mass_erase(self):
        # See Nordic Whitepaper nWP-027 for magic numbers and order of operations from the vendor
        self.ctrl_ap.write_reg(CTRL_AP_ERASEALL, 1)
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.ctrl_ap.read_reg(CTRL_AP_ERASEALLSTATUS)
                if status == CTRL_AP_ERASEALLSTATUS_BUSY:
                    break
                sleep(0.5)
            else:
                # Timed out
                LOG.error("Mass erase timeout waiting for ERASEALLSTATUS")
                return False
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.ctrl_ap.read_reg(CTRL_AP_ERASEALLSTATUS)
                if status == CTRL_AP_ERASEALLSTATUS_READYTORESET:
                    break
                sleep(0.5)
            else:
                # Timed out
                LOG.error("Mass erase timeout waiting for ERASEALLSTATUS")
                return False
        sleep(0.01)
        self.ctrl_ap.write_reg(CTRL_AP_RESET, 2)
        self.ctrl_ap.write_reg(CTRL_AP_RESET, 0)
        sleep(0.2)
        return True
