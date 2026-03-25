# pyOCD debugger
# Copyright (c) 2026 Kai
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

from ...core import exceptions
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import FlashRegion, MemoryMap, RamRegion
from ...coresight import ap
from ...coresight.cortex_m import CortexM
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)

MDM_STATUS = 0x00000000
MDM_CTRL = 0x00000004
MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE = (1 << 0)
MDM_STATUS_FLASH_READY = (1 << 1)
MDM_STATUS_SYSTEM_SECURITY = (1 << 2)
MDM_STATUS_MASS_ERASE_ENABLE = (1 << 5)
MDM_STATUS_CORE_HALTED = (1 << 16)

MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS = (1 << 0)
MDM_CTRL_DEBUG_REQUEST = (1 << 2)
MDM_CTRL_CORE_HOLD_RESET = (1 << 4)

MDM_IDR_EXPECTED = 0x001C0000
MDM_IDR_VERSION_MASK = 0xF0
MDM_IDR_VERSION_SHIFT = 4

HALT_TIMEOUT = 2.0
MASS_ERASE_TIMEOUT = 10.0
ACCESS_TEST_ATTEMPTS = 10

_G32A1XXX_SEC_INSTRUCTIONS = [
    0xe7fdbe00,
    0x4606b570, 0x4c092500, 0x70202080, 0x69b1e003, 0xd0001c48, 0x78204788, 0xd0f809c0, 0x21717820,
    0xd0004208, 0x46282501, 0x0000bd70, 0x40020000, 0x4770ba40, 0x4770ba40, 0x4770bac0, 0x4770bac0,
    0x493cb510, 0x20ff680a, 0x600a4302, 0x4302684a, 0x688a604a, 0x608a4302, 0x430268ca, 0x493760ca,
    0x604a4a35, 0x608a4a36, 0x600a4a36, 0x22fe4936, 0x70084449, 0x70887048, 0x710a70c8, 0x71887148,
    0x483271c8, 0x44482100, 0x21016001, 0x60410509, 0x60810209, 0x06892105, 0x210060c1, 0x610143c9,
    0x31144601, 0xf854f000, 0xd0002800, 0xbd102001, 0x47702000, 0x4601b28a, 0xb5104824, 0x23004448,
    0xf0003014, 0x2800f895, 0x2001d000, 0x481fbd10, 0x4448b510, 0xf0003014, 0x2800f8bc, 0x481bd10b,
    0x21814b19, 0x444b4448, 0x00c92208, 0xf0003014, 0x2800f8be, 0x2001d000, 0x4601bd10, 0xb5104813,
    0x44482201, 0x30140352, 0xf82ef000, 0xd0002800, 0xbd102001, 0x1dc94613, 0x460108ca, 0xb510480b,
    0x00d24448, 0xf0003014, 0x2800f8a2, 0x2001d000, 0x0000bd10, 0x40001400, 0xd928c520, 0x40052000,
    0x0000ffff, 0x00002120, 0x00000004, 0x0000000c, 0x608a6882, 0x604a6842, 0x600a6802, 0x610a68c2,
    0x61886900, 0x47702000, 0x460cb5f8, 0x68b94607, 0x46152000, 0xd30b428c, 0x185268fa, 0xd30742a2,
    0xd10e0762, 0x05d22201, 0x190c1a51, 0xe0111316, 0x428c6839, 0x687ad30b, 0x42a21852, 0x0722d307,
    0x2001d001, 0x1a64e006, 0x03762601, 0x2001e002, 0x462e2500, 0x420d1e71, 0x2001d013, 0x4854bdf8,
    0x09c97801, 0x2170d012, 0x21097001, 0x0c2171c1, 0x0a217181, 0x71047141, 0xf7ff4638, 0x1badff11,
    0x280019a4, 0x2d00d1ea, 0xbdf8d1e9, 0xbdf82002, 0x6884b570, 0xd30a42a1, 0x192d68c5, 0xd306428d,
    0xd10d074d, 0x05ed2501, 0x18611b2c, 0x6804e00b, 0xd30542a1, 0x192d6845, 0xd301428d, 0xd001070d,
    0xbd702001, 0x4c3a1b09, 0x09ed7825, 0x2570d00f, 0x25017025, 0x0c0d71e5, 0x0a0d71a5, 0x71217165,
    0x72e10a11, 0x726372a2, 0xfedaf7ff, 0x2002bd70, 0xb510bd70, 0x780a492e, 0xd00609d2, 0x700a2270,
    0x71ca2244, 0xfeccf7ff, 0x2002bd10, 0xb5f8bd10, 0x46154607, 0x461e2000, 0xd1380752, 0x429168ba,
    0x68fbd308, 0x428b189b, 0x2301d304, 0x1a9a05db, 0xe0271854, 0x4291683a, 0x687bd329, 0x428b189b,
    0x1a8cd325, 0x481ae01e, 0x09c97801, 0x2170d01d, 0x21077001, 0x0c2171c1, 0x0a217181, 0x71047141,
    0x20004b13, 0x18c13308, 0x1c405c32, 0x700ab2c0, 0xd3f82808, 0xf7ff4638, 0x3408fe93, 0x36083d08,
    0xd1012800, 0xd1de2d00, 0x2002bdf8, 0x2001bdf8, 0xb510bdf8, 0x780a4906, 0xd00609d2, 0x700a2270,
    0x71ca2249, 0xfe7cf7ff, 0x2002bd10, 0x0000bd10, 0x40020000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
]


def _flash_algo(flash_size: int) -> dict:
    return {
        'load_address': 0x20000000,
        'instructions': list(_G32A1XXX_SEC_INSTRUCTIONS),
        'pc_init': 0x20000045,
        'pc_unInit': 0x200000b5,
        'pc_program_page': 0x20000119,
        'pc_erase_sector': 0x200000ff,
        'pc_eraseAll': 0x200000d3,
        'static_base': 0x20000000 + 0x00000004 + 0x00000314,
        'begin_stack': 0x20001b60,
        'end_stack': 0x20000b60,
        'page_size': 0x400,
        'analyzer_supported': False,
        'analyzer_address': 0x00000000,
        'page_buffers': [0x20000360, 0x20000760],
        'min_program_length': 0x400,
        'ro_start': 0x4,
        'ro_size': 0x314,
        'rw_start': 0x318,
        'rw_size': 0xc,
        'zi_start': 0x324,
        'zi_size': 0x30,
        'flash_start': 0x0,
        'flash_size': flash_size,
        'sector_sizes': (
            (0x0, 0x2000),
        ),
    }


FLASH_ALGO_512K = _flash_algo(0x00080000)
FLASH_ALGO_1024K = _flash_algo(0x00100000)


class _G32A14xxBase(CoreSightTarget):
    VENDOR = "Geehy"
    PART_NUMBER = "G32A14xx"

    def __init__(self, session, memory_map):
        super().__init__(session, memory_map)
        self.mdm_ap = None
        self._force_halt_on_connect = False

    def create_init_sequence(self):
        seq = super().create_init_sequence()
        seq.wrap_task(
            'discovery',
            lambda seq: seq
                .insert_before(
                    'find_components',
                    ('check_mdm_ap_idr', self.check_mdm_ap_idr),
                    ('check_flash_security', self.check_flash_security),
                )
                # ROM table probing is unreliable on G32A14xx during bring-up, but AP0 access
                # and direct core creation are stable once MDM-AP has granted debug access.
                .replace_task('find_components', self.find_components)
                .replace_task('create_cores', self.create_cores)
        )
        return seq

    def find_components(self):
        LOG.info("%s skipping ROM table component discovery; creating core directly from AP0", self.PART_NUMBER)

    def create_cores(self):
        last_error = None
        for attempt in range(1, 4):
            try:
                if self.mdm_ap:
                    mdm_ctrl = MDM_CTRL_DEBUG_REQUEST
                    if self.dp.is_reset_asserted():
                        mdm_ctrl |= MDM_CTRL_CORE_HOLD_RESET
                    LOG.info(
                        "%s enabling debug access via MDM-AP before core creation "
                        "(attempt %d, MDM_CTRL=0x%08x)",
                        self.PART_NUMBER, attempt, mdm_ctrl
                    )
                    self.mdm_ap.write_reg(MDM_CTRL, mdm_ctrl)

                core = CortexM(self.session, self.aps[0], self.memory_map, 0)
                core.default_reset_type = self.ResetType.SYSRESETREQ
                self.aps[0].core = core
                core.init()
                self.add_core(core)
                self.selected_core = 0
                LOG.info("%s core0 created directly from AP0", self.PART_NUMBER)
                return
            except exceptions.TransferError as err:
                last_error = err
                LOG.warning("%s core creation attempt %d failed: %s", self.PART_NUMBER, attempt, err)
                sleep(0.02)

        if last_error is not None:
            raise last_error

    def check_mdm_ap_idr(self):
        if not self.dp.aps:
            LOG.debug("%s: no valid APs found, skip MDM-AP check", self.PART_NUMBER)
            return

        self.mdm_ap = self.dp.aps[1]

        if (self.mdm_ap.idr & ~MDM_IDR_VERSION_MASK) != MDM_IDR_EXPECTED:
            LOG.error("%s: bad MDM-AP IDR (is 0x%08x)", self.part_number, self.mdm_ap.idr)

        mdm_ap_version = (self.mdm_ap.idr & MDM_IDR_VERSION_MASK) >> MDM_IDR_VERSION_SHIFT
        LOG.debug("%s MDM-AP version %d", self.PART_NUMBER, mdm_ap_version)

    def is_locked(self) -> bool:
        if not self.mdm_ap:
            return False

        self._wait_for_flash_init()
        val = self.mdm_ap.read_reg(MDM_STATUS)
        LOG.info("%s MDM-AP status = 0x%08x", self.PART_NUMBER, val)
        return (val & MDM_STATUS_SYSTEM_SECURITY) != 0

    def check_flash_security(self):
        if not self.dp.aps:
            return

        is_locked = self.is_locked()

        if is_locked:
            can_access = False
        else:
            try:
                if isinstance(self.aps[0], ap.MEM_AP):
                    for _ in range(ACCESS_TEST_ATTEMPTS):
                        self.aps[0].read32(CortexM.DHCSR)
            except exceptions.TransferError:
                LOG.debug("%s access test failed with fault", self.PART_NUMBER)
                can_access = False
            else:
                can_access = True

        if not can_access:
            LOG.info("%s asserting reset for security/debug handoff", self.PART_NUMBER)
            self.dp.assert_reset(True)
            self._force_halt_on_connect = True

            is_locked = self.is_locked()

            if not is_locked and self.session.options.get('connect_mode') == 'attach':
                LOG.warning("%s forcing halt on connect to gain control of device", self.PART_NUMBER)
                self._force_halt_on_connect = True

        if is_locked:
            if self.session.options.get('auto_unlock'):
                LOG.warning(
                    "%s in secure state: will try to unlock via mass erase "
                    "(destructive recovery path, all flash contents will be lost)",
                    self.PART_NUMBER,
                )
                if not self.mass_erase():
                    self.dp.assert_reset(False)
                    if self.mdm_ap:
                        self.mdm_ap.write_reg(MDM_CTRL, 0)
                    LOG.error("%s: mass erase failed", self.PART_NUMBER)
                    raise exceptions.TargetError("unable to unlock device")
                self._force_halt_on_connect = True
            else:
                LOG.warning("%s in secure state: not automatically unlocking", self.PART_NUMBER)
                raise exceptions.TargetError("device is secure; mass erase is required to unlock")
        else:
            LOG.info("%s not in secure state", self.PART_NUMBER)

    def mass_erase(self) -> bool:
        was_reset_asserted = self.dp.is_reset_asserted()
        if not was_reset_asserted:
            LOG.info("%s asserting reset for mass erase", self.PART_NUMBER)
            self.dp.assert_reset(True)

        result = self._mass_erase()

        if not was_reset_asserted:
            self.dp.assert_reset(False)
        return result

    def _wait_for_flash_init(self):
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.mdm_ap.read_reg(MDM_STATUS)
                if status & MDM_STATUS_FLASH_READY:
                    break
                sleep(0.01)
        return not to.did_time_out

    def _mass_erase(self) -> bool:
        if not self._wait_for_flash_init():
            LOG.error("%s mass erase timeout waiting for flash to finish init", self.PART_NUMBER)
            return False

        status = self.mdm_ap.read_reg(MDM_STATUS)
        if not (status & MDM_STATUS_MASS_ERASE_ENABLE):
            LOG.error("%s mass erase disabled. MDM status: 0x%x", self.PART_NUMBER, status)
            return False

        self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS)

        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                val = self.mdm_ap.read_reg(MDM_STATUS)
                if val & MDM_STATUS_FLASH_MASS_ERASE_ACKNOWLEDGE:
                    break
                sleep(0.1)
            else:
                LOG.error("%s mass erase timeout waiting for Flash Mass Erase Ack to set", self.PART_NUMBER)
                return False

        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                val = self.mdm_ap.read_reg(MDM_CTRL)
                if (val & MDM_CTRL_FLASH_MASS_ERASE_IN_PROGRESS) == 0:
                    break
                sleep(0.1)
            else:
                LOG.error("%s mass erase timeout waiting for in-progress to clear", self.PART_NUMBER)
                return False

        val = self.mdm_ap.read_reg(MDM_STATUS)
        if (val & MDM_STATUS_SYSTEM_SECURITY) == 0:
            LOG.warning("%s secure state: unlocked successfully (MDM status 0x%08x)", self.PART_NUMBER, val)
            return True

        LOG.error("%s failed to unlock. MDM status: 0x%x", self.PART_NUMBER, val)
        return False

    def perform_halt_on_connect(self) -> None:
        mode = self.session.options.get('connect_mode')
        if mode == 'under-reset' or self._force_halt_on_connect:
            if not self.mdm_ap:
                return
            LOG.info("%s configuring MDM-AP to halt when coming out of reset", self.PART_NUMBER)
            with Timeout(HALT_TIMEOUT) as to:
                while to.check():
                    self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET)
                    if self.mdm_ap.read_reg(MDM_CTRL) & (MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET) == (
                        MDM_CTRL_DEBUG_REQUEST | MDM_CTRL_CORE_HOLD_RESET
                    ):
                        break
                else:
                    raise exceptions.TimeoutError("Timed out attempting to set DEBUG_REQUEST and CORE_HOLD_RESET in MDM-AP")

            self.aps[0].write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)
        else:
            super().perform_halt_on_connect()

    def post_connect(self) -> None:
        mode = self.session.options.get('connect_mode')
        if mode == 'under-reset' or self._force_halt_on_connect:
            if not self.mdm_ap:
                return
            LOG.info("Deasserting reset post connect")
            self.dp.assert_reset(False)

            self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)

            with Timeout(HALT_TIMEOUT) as to:
                while to.check():
                    if self.mdm_ap.read_reg(MDM_STATUS) & MDM_STATUS_CORE_HALTED == MDM_STATUS_CORE_HALTED:
                        break
                    LOG.debug("Waiting for MDM halt")
                    sleep(0.01)
                else:
                    raise exceptions.TimeoutError("Timed out waiting for core to halt")

            self.mdm_ap.write_reg(MDM_CTRL, 0)

            if self.get_state() == Target.State.RUNNING:
                raise exceptions.DebugError("Target failed to stay halted during init sequence")
        else:
            super().post_connect()
            if self.mdm_ap:
                self.mdm_ap.write_reg(MDM_CTRL, 0)


class G32A1445(_G32A14xxBase):
    PART_NUMBER = "G32A1445"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x00000000, length=0x00080000, blocksize=0x2000, page_size=0x400,
            is_boot_memory=True, algo=FLASH_ALGO_512K),
        # IRAM1 is common to all package variants and sufficient for flash algo execution.
        RamRegion(start=0x20000000, length=0x00007000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)


class G32A1465(_G32A14xxBase):
    PART_NUMBER = "G32A1465"

    MEMORY_MAP = MemoryMap(
        FlashRegion(start=0x00000000, length=0x00100000, blocksize=0x2000, page_size=0x400,
            is_boot_memory=True, algo=FLASH_ALGO_1024K),
        # IRAM2 base differs by package, so only the common IRAM1 region is modelled here.
        RamRegion(start=0x20000000, length=0x0000F000),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
