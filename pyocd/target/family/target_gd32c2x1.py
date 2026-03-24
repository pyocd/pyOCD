# pyOCD debugger
# Copyright (c) 2017 NXP
# Copyright (c) 2006-2020,2025 Arm Limited
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

from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM
from ...flash.eraser import FlashEraser
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)
GD32C2X1_TAG = "GD32C2x1"

FMC_KEY = 0x40022008
FMC_OBKEY = 0x4002200C
FMC_STAT = 0x40022010
FMC_CTL = 0x40022014
FMC_OBCTL = 0x40022020
FMC_DCRP0 = 0x40022024
FMC_DCRP1 = 0x40022028
FMC_WP0 = 0x4002202C
FMC_WP1 = 0x40022030
FMC_DCRP2 = 0x40022034
FMC_DCRP3 = 0x40022038
FMC_SCR = 0x40022080

FMC_KEY0 = 0x45670123
FMC_KEY1 = 0xCDEF89AB
FMC_OBKEY0 = 0x08192A3B
FMC_OBKEY1 = 0x4C5D6E7F

FMC_CTL_OBWEN = 0x00020000
FMC_CTL_OBSTART = 0x08000000
FMC_CTL_OBLAUNCH = 0x80000000

OB_BASE = 0x1FFF7800
OBCTL_OFFSET = 0x00
WP0_START_OFFSET = 0x18
WP0_END_OFFSET = 0x1A
WP1_START_OFFSET = 0x20
WP1_END_OFFSET = 0x22
DCRP0_START_OFFSET = 0x08
DCRP0_END_OFFSET = 0x10
DCRP1_START_OFFSET = 0x28
DCRP1_END_OFFSET = 0x30
DCRP_EREN_OFFSET = 0x13
SCR_PAGE_CNT_OFFSET = 0x70
SCR_BOOTLK_OFFSET = 0x72

SPC_UNLOCKED = 0xA5
SPC_LOW_LEVEL_PROTECTION = 0xBB

# Factory-default OB values observed on GD32C231 devices (no protections active).
# Used to restore a clean state when the OB sector is corrupted (SPC=0xFF).
_OB_SAFE_DEFAULTS = {
    "spc":          SPC_UNLOCKED,
    "user":         0x1f697e,
    "wp0_saddr":    0x3f,
    "wp0_eaddr":    0x00,
    "wp1_saddr":    0x3f,
    "wp1_eaddr":    0x00,
    "dcrp0_saddr":  0x7f,
    "dcrp0_eaddr":  0x00,
    "dcrp1_saddr":  0x7f,
    "dcrp1_eaddr":  0x00,
    "dcrp_eren":    0x00,
    "scr_page_cnt": 0x00,
    "scr_bootlk":   0x00,
}

FLASH_TIMEOUT = 5.0
SECURITY_STATE_RETRIES = 3
AP0_CSW_ADDR = 0x00
AP0_CSW_ADDR_VAL = 0x03000012
AP0_TAR_ADDR = 0x04
AP0_DRW_ADDR = 0x0C
AP0_IDR_ADDR = 0xFC
MEM_AP_IDR_MASK = 0x0FFFE00F
MEM_AP_IDR_EXPECTED = 0x04770005


class GD32C2x1(CoreSightTarget):
    VENDOR = "GigaDevice:123"

    def create_init_sequence(self):
        LOG.debug("%s: create_init_sequence for %s", GD32C2X1_TAG, self.__class__.__name__)
        seq = super().create_init_sequence()
        if self.session.options.get("connect_mode") in ("halt", "under-reset"):
            seq.insert_after("dp_init", ("safe_reset_and_halt", self.safe_reset_and_halt))
        seq.insert_before("create_flash", ("check_flash_security", self.check_flash_security))
        return seq

    def safe_reset_and_halt(self):
        LOG.debug("%s: safe_reset_and_halt entered (reset asserted=%s)", GD32C2X1_TAG, self.dp.is_reset_asserted())
        if not self.dp.is_reset_asserted():
            return

        ap_idr = self.dp.read_ap(AP0_IDR_ADDR)
        if (ap_idr & MEM_AP_IDR_MASK) != MEM_AP_IDR_EXPECTED:
            raise exceptions.TargetError(f"unexpected GD32C2x1 MEM-AP IDR: 0x{ap_idr:08x}")

        self.dp.write_ap(AP0_CSW_ADDR, AP0_CSW_ADDR_VAL)

        demcr_value = self._mini_read32(CortexM.DEMCR)

        # Halt the core as it leaves reset so discovery sees a valid CPUID and stable memory map.
        self._mini_write32(CortexM.DEMCR, CortexM.DEMCR_VC_CORERESET | CortexM.DEMCR_TRCENA)
        self._mini_write32(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)

        self.dp.assert_reset(False)
        time.sleep(0.01)

        self._mini_write32(CortexM.DEMCR, demcr_value)
        LOG.debug("%s: safe_reset_and_halt completed", GD32C2X1_TAG)

    def check_flash_security(self):
        LOG.debug("%s: check_flash_security entered", GD32C2X1_TAG)
        if self.is_locked():
            if self.session.options.get("auto_unlock"):
                LOG.warning("%s low-level protection enabled: will try to unlock via mass erase", self.part_number)
                if not self.mass_erase():
                    raise exceptions.TargetError("unable to unlock GD32C2x1")
            else:
                LOG.warning("%s low-level protection enabled: not automatically unlocking", self.part_number)
        else:
            LOG.info("%s not in secure state", self.part_number)

        # After a connect under reset with erased flash, let the generic discovery finish first
        # and then force the core back into a clean halted state before any flash read/compare.
        if self.session.options.get("connect_mode") in ("halt", "under-reset"):
            LOG.warning("%s: forcing final reset_and_halt before flash operations", GD32C2X1_TAG)
            self.reset_and_halt()

    def is_locked(self):
        ob = self._read_option_bytes()
        return ob["spc"] == SPC_LOW_LEVEL_PROTECTION

    def unlock(self):
        return self._set_security_state(SPC_UNLOCKED)

    def lock(self):
        return self._set_security_state(SPC_LOW_LEVEL_PROTECTION)

    def mass_erase(self):
        if self.is_locked():
            if not self.unlock():
                return False

        eraser = FlashEraser(self.session, FlashEraser.Mode.CHIP)
        eraser._log_chip_erase = False
        eraser.erase()
        return True

    def _set_security_state(self, spc_value):
        last_error = None

        for attempt in range(1, SECURITY_STATE_RETRIES + 1):
            try:
                LOG.info("%s: _set_security_state start target_spc=0x%02x attempt=%d",
                            GD32C2X1_TAG, spc_value, attempt)

                self._prepare_security_state_attempt()

                ob = self._read_option_bytes()
                LOG.info("%s: current option bytes spc=0x%02x user=0x%06x",
                            GD32C2X1_TAG, ob["spc"], ob["user"])
                if ob["spc"] == 0xFF:
                    if spc_value != SPC_UNLOCKED:
                        # Locking with corrupted user bits would leave DCRP/WP set to 0xFF
                        # (maximum protection), making recovery very difficult.
                        raise exceptions.TargetError(
                            f"{GD32C2X1_TAG}: option bytes corrupted (SPC=0xFF); "
                            "power-cycle the device and retry before locking"
                        )
                    # Unlocking is a recovery attempt.  Replace the corrupted OB values with
                    # known-safe factory defaults so user/WP/DCRP are not left as 0xFF.
                    LOG.warning("%s: option bytes corrupted (SPC=0xFF); restoring with factory defaults",
                                GD32C2X1_TAG)
                    ob = dict(_OB_SAFE_DEFAULTS)
                if ob["spc"] == spc_value:
                    return True

                ob["spc"] = spc_value
                LOG.info("%s: writing option bytes for spc=0x%02x",
                            GD32C2X1_TAG, ob["spc"])
                self._write_option_bytes(ob)

                LOG.info("%s: option bytes launched, reconnecting with reset_and_halt",
                            GD32C2X1_TAG)
                self.reset_and_halt()
                verify = self._read_option_bytes()
                LOG.info("%s: verify option bytes spc=0x%02x user=0x%06x",
                            GD32C2X1_TAG, verify["spc"], verify["user"])
                return verify["spc"] == spc_value
            except (exceptions.TransferError, exceptions.TargetError, exceptions.TimeoutError) as err:
                last_error = err
                LOG.warning("%s: security state attempt %d failed: %s",
                            GD32C2X1_TAG, attempt, err)

        if last_error is not None:
            raise last_error
        return False

    def _wait_flash_ready(self):
        with Timeout(FLASH_TIMEOUT) as to:
            while to.check():
                if (self._mini_read32(FMC_STAT) & 0x1) == 0:
                    return
        raise exceptions.TimeoutError("timed out waiting for GD32C2x1 FMC ready")

    def _unlock_fmc_and_option_bytes(self):
        self._mini_write32(FMC_KEY, FMC_KEY0)
        self._mini_write32(FMC_KEY, FMC_KEY1)
        self._mini_write32(FMC_OBKEY, FMC_OBKEY0)
        self._mini_write32(FMC_OBKEY, FMC_OBKEY1)

    def _read_option_bytes(self):
        obctl = self._mini_read32(OB_BASE + OBCTL_OFFSET)

        return {
            "spc": obctl & 0xFF,
            "user": (obctl >> 8) & 0x00FFFFFF,
            "wp0_saddr": self._mini_read8(OB_BASE + WP0_START_OFFSET),
            "wp0_eaddr": self._mini_read8(OB_BASE + WP0_END_OFFSET),
            "wp1_saddr": self._mini_read8(OB_BASE + WP1_START_OFFSET),
            "wp1_eaddr": self._mini_read8(OB_BASE + WP1_END_OFFSET),
            "dcrp0_saddr": self._mini_read8(OB_BASE + DCRP0_START_OFFSET),
            "dcrp0_eaddr": self._mini_read8(OB_BASE + DCRP0_END_OFFSET),
            "dcrp1_saddr": self._mini_read8(OB_BASE + DCRP1_START_OFFSET),
            "dcrp1_eaddr": self._mini_read8(OB_BASE + DCRP1_END_OFFSET),
            "dcrp_eren": self._mini_read8(OB_BASE + DCRP_EREN_OFFSET),
            "scr_page_cnt": self._mini_read8(OB_BASE + SCR_PAGE_CNT_OFFSET),
            "scr_bootlk": self._mini_read8(OB_BASE + SCR_BOOTLK_OFFSET),
        }

    def _write_option_bytes(self, ob):
        self._unlock_fmc_and_option_bytes()
        self._wait_flash_ready()

        self._mini_write32(FMC_OBCTL, ((ob["user"] & 0x00FFFFFF) << 8) | (ob["spc"] & 0xFF))
        self._mini_write32(FMC_WP0, ob["wp0_saddr"])
        self._mini_write32(FMC_WP1, ob["wp1_saddr"])
        self._mini_write32(FMC_DCRP0, ob["dcrp0_saddr"])
        self._mini_write32(FMC_DCRP1, ob["dcrp0_eaddr"])
        self._mini_write32(FMC_DCRP2, ob["dcrp1_saddr"])
        self._mini_write32(FMC_DCRP3, ob["dcrp1_eaddr"])
        self._mini_write32(FMC_SCR, (ob["scr_bootlk"] << 8) | ob["scr_page_cnt"])

        self._mini_write32(FMC_CTL, FMC_CTL_OBWEN)
        self._wait_flash_ready()
        self._mini_write32(FMC_CTL, FMC_CTL_OBSTART)
        self._mini_write32(FMC_CTL, FMC_CTL_OBLAUNCH)

    def _prepare_security_state_attempt(self):
        if self.session.options.get("connect_mode") == "under-reset":
            self.dp.assert_reset(True)
            time.sleep(0.01)
            self.safe_reset_and_halt()

    def _mini_read32(self, addr):
        self.dp.write_ap(AP0_TAR_ADDR, addr)
        return self.dp.read_ap(AP0_DRW_ADDR)

    def _mini_write32(self, addr, value):
        self.dp.write_ap(AP0_TAR_ADDR, addr)
        self.dp.write_ap(AP0_DRW_ADDR, value)

    def _mini_read8(self, addr):
        word = self._mini_read32(addr & ~0x3)
        return (word >> (8 * (addr & 0x3))) & 0xFF
