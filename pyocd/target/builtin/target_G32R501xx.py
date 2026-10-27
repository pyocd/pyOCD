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
import time

from ...core import exceptions
from ...core.memory_map import FlashRegion, MemoryMap, RamRegion
from ...core.target import Target
from ...coresight.ap import APv1Address, AccessPort
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM
from ...coresight.minimal_mem_ap import MinimalMemAP as MiniAP
from ...flash.flash import Flash

LOG = logging.getLogger(__name__)


class DBGMCU:
    CTRL = 0xE0059004
    CTRL_VALUE = 0x00000000
    APB1CFG0 = 0xE0059030
    APB1CFG0_VALUE = 0x00000000  # CPU0 APB1 halt freeze
    APB1CFG1 = 0xE0059034
    APB1CFG1_VALUE = 0x00000000  # CPU1 APB1 halt freeze
    APB2CFG0 = 0xE0059038
    APB2CFG0_VALUE = 0x00000000  # CPU0 APB2 halt freeze
    APB2CFG1 = 0xE005903C
    APB2CFG1_VALUE = 0x00000000  # CPU1 APB2 halt freeze
    AHB1CFG0 = 0xE0059040
    AHB1CFG0_VALUE = 0x00000001  # freeze WDT when CPU0 halted
    AHB1CFG1 = 0xE0059044
    AHB1CFG1_VALUE = 0x00000001  # freeze WDT when CPU1 halted


FLASH_ALGO = {
    'load_address': 0x20300000,
    'instructions': [
        0xe7fdbe00,
        0x4178f100, 0x1280f5a0, 0x2f20f5b1, 0x0385f244, 0x912fea5f, 0x2f20f5b2, 0x922fea5f, 0x3f50ebb3,
        0x0002ea41, 0x911fea5f, 0x47704308, 0xf64eb580, 0xf2ce5188, 0x680a0100, 0x020cf042, 0x2101600a,
        0x111cee00, 0x4152f246, 0x0102f2c5, 0xf042880a, 0x800a0268, 0x0285f244, 0xebb22100, 0xee003f50,
        0xd00b111c, 0x4178f100, 0x2f20f5b1, 0xf5a0d306, 0x0c401080, 0xd9012804, 0xbd802000, 0x210a2000,
        0x0001f2c5, 0xf8a2f000, 0x2000b920, 0xf8a3f000, 0xd0f12800, 0xbd802001, 0x47702000, 0xb085b5f0,
        0x77fff64d, 0x6400f04f, 0xf6c0ad01, 0xbf000709, 0x46212006, 0xf894f000, 0xbf004606, 0xf895f000,
        0xd1fb2802, 0xf000b986, 0xb968f895, 0xf44f4620, 0x462a6100, 0xf893f000, 0x42bcb930, 0x5400f504,
        0x2000d9e6, 0xbdf0b005, 0xb0052001, 0xbf00bdf0, 0xb084b5b0, 0xf1004604, 0xf5b04078, 0xd3072f20,
        0x1080f5a4, 0x28040c40, 0x2000d902, 0xbdb0b004, 0x46212006, 0xf864f000, 0xbf004605, 0xf865f000,
        0xd1fb2802, 0xf000b955, 0xb938f865, 0x466a4620, 0x6100f44f, 0xf863f000, 0xd0e62800, 0xb0042001,
        0xbf00bdb0, 0x45f0e92d, 0x4606b083, 0xf0004248, 0xf04f0007, 0x18440800, 0x4615d034, 0x0a85f244,
        0xbf00e00a, 0x60306828, 0x60706868, 0xf1063c08, 0xf1050608, 0xd0230508, 0x3f56ebba, 0xf106d009,
        0xf5b04078, 0xd3042f20, 0x1080f5a6, 0x28040c40, 0x4630d8e8, 0x22024629, 0xf8cd2300, 0xf8cd8000,
        0xf0008004, 0x4607f831, 0xf81ff000, 0xd1fb2802, 0xf000b91f, 0x2800f81f, 0xf04fd0d8, 0xe0010801,
        0x0800f04f, 0xb0034640, 0x85f0e8bd, 0x0c01f244, 0x0c00f2c1, 0xf2444760, 0xf2c10c31, 0x47600c00,
        0x1ce1f244, 0x0c00f2c1, 0xf2444760, 0xf2c10c1d, 0x47600c00, 0x0c11f244, 0x0c00f2c1, 0xf6444760,
        0xf2c16c41, 0x47600c00, 0x4c79f244, 0x0c00f2c1, 0x00004760, 0x00000000,
    ],
    'pc_init': 0x20300031,
    'pc_unInit': 0x2030009d,
    'pc_program_page': 0x20300149,
    'pc_erase_sector': 0x203000f5,
    'pc_eraseAll': 0x203000a1,
    'static_base': 0x20300000 + 0x00000004 + 0x00000214,
    'begin_stack': 0x20305220,
    'end_stack': 0x20304220,
    'begin_data': 0x20300000 + 0x1000,
    'page_size': 0x2000,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20300220, 0x20302220],
    'min_program_length': 0x2000,
    'ro_start': 0x4,
    'ro_size': 0x214,
    'rw_start': 0x218,
    'rw_size': 0x4,
    'zi_start': 0x21c,
    'zi_size': 0x0,
    'flash_start': 0x08000000,
    'flash_size': 0xA0000,
    'sector_sizes': (
        (0x0, 0x2000),
    ),
}

OTP_ALGO = {
    'load_address': 0x20300000,
    'instructions': [
        0xe7fdbe00,
        0x4178f100, 0x1280f5a0, 0x2f20f5b1, 0x0385f244, 0x912fea5f, 0x2f20f5b2, 0x922fea5f, 0x3f50ebb3,
        0x0002ea41, 0x911fea5f, 0x47704308, 0xf64eb580, 0xf2ce5188, 0x680a0100, 0x020cf042, 0x2101600a,
        0x111cee00, 0x4152f246, 0x0102f2c5, 0xf042880a, 0x800a0268, 0x0285f244, 0xebb22100, 0xee003f50,
        0xd00b111c, 0x4178f100, 0x2f20f5b1, 0xf5a0d306, 0x0c401080, 0xd9012804, 0xbd802000, 0x210a2000,
        0x0001f2c5, 0xf838f000, 0x2000b920, 0xf839f000, 0xd0f12800, 0xbd802001, 0x47702000, 0x47702000,
        0x41f0e92d, 0x4606b082, 0xf0004248, 0xf04f0007, 0x18440800, 0x4615d01c, 0x46294630, 0x23002202,
        0x8000f8cd, 0x8004f8cd, 0xf820f000, 0xbf004607, 0xf821f000, 0xd1fb2802, 0x3c08b947, 0x0608f106,
        0x0508f105, 0xf04fd1e8, 0xe0010800, 0x0801f04f, 0xb0024640, 0x81f0e8bd, 0x0c01f244, 0x0c00f2c1,
        0xf2444760, 0xf2c10c31, 0x47600c00, 0x4c79f244, 0x0c00f2c1, 0xf2444760, 0xf2c10c1d, 0x47600c00,
        0x00000000,
    ],
    'pc_init': 0x20300031,
    'pc_unInit': 0x2030009d,
    'pc_program_page': 0x203000a5,
    'pc_erase_sector': 0x203000a1,
    'static_base': 0x20300124,
    'begin_stack': 0x20301930,
    'end_stack': 0x20301130,
    'begin_data': 0x20300130,
    'page_size': 0x800,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20300130, 0x20300930],
    'min_program_length': 0x800,
    'ro_start': 0x4,
    'ro_size': 0x120,
    'rw_start': 0x124,
    'rw_size': 0x4,
    'zi_start': 0x128,
    'zi_size': 0x0,
    'flash_start': 0x0810A000,
    'flash_size': 0x800,
    'sector_sizes': (
        (0x0, 0x800),
    ),
}

DECRYPT_KEYS = [
    (0x50024020, 0xFFFFFFFF),
    (0x50024024, 0xFFFFFFDC),
    (0x50024028, 0xFFFFFFFF),
    (0x5002402C, 0xFFFFFFFF),
    (0x500240A0, 0xFFFFFFFF),
    (0x500240A4, 0xFFFEDFFF),
    (0x500240A8, 0xFFFFFFFF),
    (0x500240AC, 0xFFFFFFFF),
]

DISABLED_VECTOR_TABLE_ADDRESS = 0xFFFFFFFF
CORE0_SET_ADDR = 0x08000000
CORE1_SET_ADDR = 0x08050000
CORE1_START_ADDR = 0x08050000
FLASH_START = 0x08000000
FLASH_END = 0x080A0000
ITCM_FLASH_START = 0x00100000
ITCM_FLASH_END = 0x001A0000
ITCM_START = 0x00000000
ITCM_END = 0x0000C000
DTCM_START = 0x20000000
DTCM_END = 0x20400000


class G32R501Flash(Flash):
    def _ensure_sram3_accessible(self):
        """SRAM3 (flash algo + page buffers) is DCS-encrypted after every reset."""
        if hasattr(self.target, "r501_refresh_sram3_for_flash"):
            self.target.r501_refresh_sram3_for_flash()

    def init(self, operation, address=None, clock=0, reset=False):
        if self._active_operation is not None and self._active_operation != operation:
            LOG.debug(
                "G32R501 switching flash operation from %s to %s without FLM unInit",
                self._active_operation.name,
                operation.name,
            )
            self._abort_active_flash_operation()
        if operation == self.Operation.PROGRAM and hasattr(self.target, '_g32r501_flash_operation_ready'):
            self.target._g32r501_flash_operation_ready = False
        self._g32r501_flm_call_completed = False
        self._ensure_sram3_accessible()
        try:
            return super().init(operation, address, clock, reset=reset)
        except exceptions.FlashFailure:
            self._did_prepare_target = False
            self._active_operation = None
            raise
        finally:
            self._g32r501_flm_needs_reinit = False
            self._g32r501_flm_call_completed = False

    def uninit(self):
        if self._active_operation is None:
            return
        try:
            super().uninit()
        except exceptions.FlashFailure as exc:
            LOG.warning("G32R501 flash unInit failed (%s); clearing algo state", exc)
            self._abort_active_flash_operation()

    def prepare_target(self):
        self._ensure_sram3_accessible()
        if hasattr(self.target, "prepare_for_flash_operation"):
            self.target.prepare_for_flash_operation()
        self._apply_flash_cpu_init()
        if hasattr(self.target, "_apply_dbgmcu"):
            self.target._apply_dbgmcu()
        self._ensure_core_halted(timeout=2.0)
        self._mask_runtime_interrupts()

    def restore_target(self):
        super().restore_target()
        target = self.target
        if getattr(target, '_g32r501_skip_restore_after_flash', False):
            target._g32r501_skip_restore_after_flash = False
            return
        if hasattr(target, "restore_after_flash_operation"):
            target.restore_after_flash_operation()

    def _abort_active_flash_operation(self):
        try:
            self._ensure_core_halted(timeout=2.0)
        except exceptions.FlashFailure:
            LOG.debug("G32R501 could not halt before aborting flash operation")
        self._active_operation = None
        self._did_prepare_target = False
        # Keep _g32r501_flash_operation_ready set: VERIFY->ERASE must not SYSRESETREQ again.

    def _disable_nvic_interrupts(self):
        for reg in (
            0xE000E180, 0xE000E184, 0xE000E188, 0xE000E18C,
            0xE000E190, 0xE000E194, 0xE000E198, 0xE000E19C,
            0xE000E1A0, 0xE000E1A4, 0xE000E1A8, 0xE000E1AC,
            0xE000E1B0, 0xE000E1B4, 0xE000E1B8, 0xE000E1BC,
            0xE000E280, 0xE000E284, 0xE000E288, 0xE000E28C,
            0xE000E290, 0xE000E294, 0xE000E298, 0xE000E29C,
            0xE000E2A0, 0xE000E2A4, 0xE000E2A8, 0xE000E2AC,
            0xE000E2B0, 0xE000E2B4, 0xE000E2B8, 0xE000E2BC,
        ):
            try:
                self.target.write32(reg, 0xFFFFFFFF)
            except exceptions.Error:
                pass

    def _mask_runtime_interrupts(self):
        core = self.target.selected_core
        if core is None:
            return

        try:
            self._ensure_core_halted(timeout=2.0)
            self._disable_nvic_interrupts()
            try:
                core.write_core_register("primask", 1)
            except Exception:
                pass
            try:
                core.write_core_register("basepri", 0)
            except Exception:
                pass
            try:
                core.write_core_register("control", 0)
            except Exception:
                pass
            self.target.write32(0xE000E010, 0x00000000)
        except exceptions.Error as exc:
            LOG.debug("G32R501 flash context setup skipped: %s", exc)

    def _ensure_core_halted(self, timeout=1.0):
        core = self.target.selected_core
        if core is None:
            return

        core.halt()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if core.is_halted():
                return
            time.sleep(0.01)

        raise exceptions.FlashFailure("G32R501 core did not halt before flash algorithm call")

    def program_page(self, address, bytes):
        self._ensure_sram3_accessible()
        return super().program_page(address, bytes)

    def program_phrase(self, address, bytes):
        self._ensure_sram3_accessible()
        return super().program_phrase(address, bytes)

    def load_page_buffer(self, buffer_number, address, bytes):
        # Do not halt here: double-buffered program loads the next page while FLM runs.
        self._ensure_sram3_accessible()
        return super().load_page_buffer(buffer_number, address, bytes)

    def _ensure_flm_session_ready(self):
        # PROGRAM may need a fresh FLM session after each call. ERASE must not:
        # erase_all / multi-sector erase issue many erase_sector calls under one init;
        # rebuilding here forces SYSRESET + init_cpu once per sector.
        if self._active_operation == self.Operation.ERASE:
            return
        if not getattr(self, '_g32r501_flm_call_completed', False):
            return
        op = self._active_operation
        if op is None:
            return
        if hasattr(self.target, '_g32r501_flash_operation_ready'):
            self.target._g32r501_flash_operation_ready = False
        self._active_operation = None
        self._did_prepare_target = False
        self.init(op, reset=False)

    def start_program_page_with_buffer(self, buffer_number, address):
        self._ensure_sram3_accessible()
        self._ensure_flm_session_ready()
        return super().start_program_page_with_buffer(buffer_number, address)

    def erase_sector(self, address):
        if self.region is not None and not self.region.is_erasable:
            return
        self._ensure_flm_session_ready()
        return super().erase_sector(address)

    def wait_for_completion(self, timeout=None):
        result = super().wait_for_completion(timeout=timeout)
        self._ensure_sram3_accessible()
        self._g32r501_flm_call_completed = True
        if getattr(self.target, '_g32r501_flm_reset_during_call', False):
            self.target._g32r501_flm_reset_during_call = False
        return result

    def erase_all(self):
        # With DCS/bootmode/DBGMCU prepare, FLM EraseChip works (was HardFault/IPSR=3).
        # Prefer one EraseChip call over ~80 sector erases (~5s+).
        if self.region is not None and not self.region.is_erasable:
            return
        return super().erase_all()
    def _apply_flash_cpu_init(self):
        if hasattr(self.target, "init_cpu"):
            if self.target.delegate_implements("geehy_r501_init_cpu"):
                self.target.call_delegate("geehy_r501_init_cpu", target=self.target)
            else:
                self.target.init_cpu()

    def _call_function(self, pc, r0=None, r1=None, r2=None, r3=None, init=False):
        self._ensure_core_halted()
        self._mask_runtime_interrupts()
        self._ensure_sram3_accessible()
        super()._call_function(pc, r0, r1, r2, r3, init)


def _build_memory_map(flash_algo, otp_algo):
    return MemoryMap(
        FlashRegion(
            start=0x08000000,
            length=0xA0000,
            sector_size=0x2000,
            page_size=0x1000,
            is_boot_memory=True,
            are_erased_sectors_readable=False,
            algo=flash_algo,
            flash_class=G32R501Flash,
        ),
        FlashRegion(
            start=0x0810A000,
            length=0x800,
            sector_size=0x800,
            page_size=0x800,
            is_erasable=False,
            is_testable=False,
            algo=otp_algo,
            flash_class=G32R501Flash,
        ),
        FlashRegion(
            start=0x0810B000,
            length=0x800,
            sector_size=0x800,
            page_size=0x800,
            is_erasable=False,
            is_testable=False,
            algo=otp_algo,
            flash_class=G32R501Flash,
        ),
        RamRegion(start=0x00000000, length=0xC000, access="rwx", is_cacheable=False),
        RamRegion(start=0x20000000, length=0x4000, access="rwx", is_cacheable=False),
        RamRegion(start=0x20100000, length=0x2000, access="rwx", init="0"),
        RamRegion(start=0x20200000, length=0x2000, access="rwx", init="0"),
        RamRegion(start=0x20300000, length=0x8000, access="rwx", init="0"),
    )

MEMORY_MAP_G32R501XX = _build_memory_map(FLASH_ALGO, OTP_ALGO)

class G32R501CortexM(CortexM):
    def halt(self) -> None:
        super().halt()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if self.is_halted():
                return
            time.sleep(0.01)
        LOG.warning("G32R501 core%d did not report halted within timeout.", self.core_number)

    def reset(self, reset_type=None) -> None:
        # pyOCD >= 0.45: CortexM.reset_and_halt() calls self.reset().
        # Only perform the raw reset here. Do NOT apply startup or resume —
        # that would defeat reset-catch and break flash algo (IPSR=3 HardFault).
        # Debug "reset and run" is handled by G32R501xxBase.reset().
        board = self.session.board.target
        board._g32r501_refresh_before_resume = False
        rt = reset_type if reset_type is not None else board.ResetType.SYSRESETREQ
        super().reset(rt)

    def reset_and_halt(self, reset_type=None):
        board = self.session.board.target
        board._g32r501_refresh_before_resume = False
        rt = reset_type if reset_type is not None else board.ResetType.SYSRESETREQ
        super().reset_and_halt(rt)
        if getattr(board, "_g32r501_flash_reset", False):
            board.r501_refresh_sram3_for_flash(bootmode=True)
            return
        board.apply_startup_configuration()
        # Keep halted after applying user vectors (flash / debug halt paths).
        if not self.is_halted():
            self.halt()

    def resume(self) -> None:
        board = self.session.board.target
        if getattr(board, "_g32r501_refresh_before_resume", False):
            board._g32r501_refresh_before_resume = False
            LOG.info("Applying G32R501 startup before resume.")
            if not board.apply_startup_configuration():
                LOG.info("Resume skipped because no valid user vector is present.")
                return
        super().resume()


class G32R501xxBase(CoreSightTarget):
    VENDOR = "Geehy"
    VALID_APS = (0, 1, 2)
    HAS_CORE1 = False
    BRINGUP_CORE1_VECTOR = True
    SAFE_CORE0_SP = 0x20002000
    SAFE_CORE1_SP = 0x20002000

    def __init__(self, session, memory_map):
        self._decrypt_keys = list(DECRYPT_KEYS)
        self._flash_algo = FLASH_ALGO
        self._core_vector_addresses = {
            0: CORE0_SET_ADDR,
            1: CORE1_SET_ADDR,
        }
        self._core_start_addresses = {
            1: CORE1_START_ADDR,
        }
        super().__init__(session, memory_map)
        self._g32r501_refresh_before_resume = False
        self._g32r501_user_vector_valid = {0: False, 1: False}
        self._g32r501_flash_reset = False
        self._g32r501_flash_operation_ready = False
        self._g32r501_flm_reset_during_call = False
        self._g32r501_skip_restore_after_flash = False
        self.session.subscribe(self._g32r501_on_post_flash_program, Target.Event.POST_FLASH_PROGRAM)
        self.session.subscribe(self._g32r501_on_post_reset, Target.Event.POST_RESET)
        self.session.subscribe(self._g32r501_on_pre_flash_erase, Target.Event.PRE_FLASH_ERASE)

    def _g32r501_on_pre_flash_erase(self, notification):
        self._g32r501_skip_restore_after_flash = True

    def _g32r501_on_post_flash_program(self, notification):
        self._g32r501_refresh_before_resume = True

    def _g32r501_on_post_reset(self, notification):
        if not self._g32r501_flash_operation_ready:
            return
        LOG.debug("G32R501 POST_RESET during flash session: refreshing SRAM3 DCS access")
        self._g32r501_flm_reset_during_call = True
        self.r501_refresh_sram3_for_flash()

    def set_decrypt_keys(self, decrypt_keys):
        self._decrypt_keys = list(decrypt_keys)

    def set_vector_table_address(self, core_number, address):
        self._core_vector_addresses[core_number] = address

    def set_core_start_address(self, core_number, address):
        self._core_start_addresses[core_number] = address

    def configure_startup(self, decrypt_keys=None, core0_vector_address=None,
            core1_vector_address=None, core1_start_address=None):
        if decrypt_keys is not None:
            self.set_decrypt_keys(decrypt_keys)
        if core0_vector_address is not None:
            self.set_vector_table_address(0, core0_vector_address)
        if core1_vector_address is not None:
            self.set_vector_table_address(1, core1_vector_address)
        if core1_start_address is not None:
            self.set_core_start_address(1, core1_start_address)

    def r501_dcs_setup(self, log_sequence=True):
        ap = MiniAP(self.dp)
        ap.init()

        ap.write32(0x50020000, 0x5AFFFFFF)
        ap.write32(0x50020004, 0xFFFFFF03)
        ap.write32(0x50020008, 0xFFFFFFFF)

        if log_sequence:
            LOG.info("G32R501 DCS key sequence ...")
        for addr, value in self._decrypt_keys:
            ap.write32(addr, value)
            if log_sequence:
                LOG.info("0x%08X -> [0x%08X]", addr, value)

        itcm_size = ap.read32(0x50020064)
        LOG.debug("CFGSMS / ITCM indicator (0x50020064) = %s (flash algo uses SRAM3)", itcm_size)

        if log_sequence:
            LOG.info("G32R501 DCS setup completed successfully.")
        else:
            LOG.debug("G32R501 DCS setup refreshed before flash algorithm call.")

    def _ensure_core_halted(self, core, timeout: float = 0.5) -> bool:
        core.halt()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if core.is_halted():
                return True
            time.sleep(0.01)
        return False

    def _is_valid_user_vector(self, sp_value: int, pc_value: int, core_number: int) -> bool:
        if sp_value in (0x00000000, 0xFFFFFFFF) or pc_value in (0x00000000, 0xFFFFFFFF):
            return False
        sp_ok = (DTCM_START < sp_value <= DTCM_END) or (ITCM_START < sp_value <= ITCM_END)
        pc_addr = pc_value & ~1
        pc_ok = (
            (pc_value & 1) != 0
            and (
                (FLASH_START <= pc_addr < FLASH_END)
                or (ITCM_FLASH_START <= pc_addr < ITCM_FLASH_END)
                or (ITCM_START <= pc_addr < ITCM_END)
            )
        )
        if core_number == 1:
            pc_ok = pc_ok and pc_addr >= CORE1_SET_ADDR
        return sp_ok and pc_ok

    def set_core_vector_table(self, core_number):
        self._g32r501_user_vector_valid[core_number] = False
        vector_table_address = self._core_vector_addresses.get(core_number, DISABLED_VECTOR_TABLE_ADDRESS)
        if vector_table_address == DISABLED_VECTOR_TABLE_ADDRESS:
            return False

        core = self.cores.get(core_number)
        if core is None:
            LOG.warning("Skipping SP/PC setup because core%d is not available.", core_number)
            return False

        if not self._ensure_core_halted(core):
            LOG.warning(
                "Skipping SP/PC setup for core%d: core did not enter halt within timeout.",
                core_number,
            )
            return False
        sp_value, pc_value = core.read_memory_block32(vector_table_address, 2)
        if not self._is_valid_user_vector(sp_value, pc_value, core_number):
            LOG.warning(
                "Vector table at 0x%08X is invalid (MSP=0x%08X PC=0x%08X); core%d remains halted.",
                vector_table_address,
                sp_value,
                pc_value,
                core_number,
            )
            return False
        LOG.info("Applying core%d vector table from 0x%08X", core_number, vector_table_address)
        LOG.info("  MSP = 0x%08X", sp_value)
        LOG.info("  PC  = 0x%08X", pc_value)
        core.write_memory(0xE000ED08, vector_table_address)
        core.write_core_register("msp", sp_value)
        core.write_core_register("psp", sp_value)
        core.write_core_register("xpsr", 0x01000000)
        core.write_core_register("pc", pc_value & ~1)
        self._g32r501_user_vector_valid[core_number] = True
        return True

    def bootmode_setup(self):
        self.write32(0x50020000, 0xA5FFFFFF)
        LOG.info("Entering standalone boot mode (skip BootROM user path)")

    def init_cpu(self):
        self.write32(0xE000ED08, 0x10000000)

        value = self.read32(0xE000ED88)
        value |= 0x0C
        self.write32(0xE000ED88, value)

        value8 = self.read8(0x50010600)
        value8 |= 0xF0
        self.write8(0x50010600, value8)

        value16 = self.read16(0x50026452)
        value16 |= 0x68
        self.write16(0x50026452, value16)

        self.write32(0x50020074, 0x01)
        self.write16(0x500264C0, 0x0001)

        if (self.read32(0x50020B00) & 0x01) == 0x01:
            value = self.read32(0x50010830)
            value |= 0xFFFF
            self.write32(0x50010830, value)

        if (self.read32(0x50020B00) & 0x03) == 0x03:
            self.write32(0x50010000, 0x00000900)
            self.write32(0x50020844, 0x00000000)

            value = self.read32(0x0810B910)
            if ((value & 0xFF000000) >> 24) != 0x5A:
                self.write32(0x50020828, 18)
            if ((value & 0xFF000000) >> 24) == 0x5A:
                self.write32(0x50020828, (value >> 0x08) & 0xFF)

            temp_val = self.read32(0x0810B878)
            if (temp_val & 0xFF03) == 0x5A00:
                value = self.read32(0x500280D4)
                value |= 0x8000
                self.write32(0x500280D4, value)

            temp_val = self.read32(0x0810B894)
            if (temp_val & 0xFFFF) == 0x5A5A:
                self.write32(0x50028024, self.read32(0x0810B884))
                self.write32(0x50028028, self.read32(0x0810B888))
                self.write32(0x5002801C, self.read32(0x0810B88C))
                self.write32(0x50028020, self.read32(0x0810B890))

            if ((value & 0xFF000000) >> 24) == 0x5A:
                mask = value & 0xF0000
                self.write32(0x50021100, mask)
                self.write32(0x50021104, mask)
                self.write32(0x50020844, value & 0xFC)

            value2 = self.read32(0x0810B910)
            if ((value2 & 0xFF000003) == 0x5A000003) and (self.read32(0x5002082C) & 0x01):
                reg_val = self.read32(0x5002081C)
                reg_val |= 0x02
                self.write32(0x5002081C, reg_val)

        self.write32(0x50010000, 0x00000F00)

        value = self.read32(0x0810B800)
        self.write32(0x50020510, value)
        value = self.read32(0x0810B804)
        self.write32(0x50020514, value)
        value = self.read32(0x0810B80C)
        self.write32(0x50020524, value)
        value = self.read32(0x0810B814)
        self.write32(0x5002052C, value)
        value = self.read32(0x0810B818)
        self.write32(0x50020530, value)
        value = self.read32(0x0810B81C)
        self.write32(0x50020534, value)
        value = self.read32(0x0810B824)
        self.write32(0x5002053C, value)
        value = self.read32(0x0810B828)
        self.write32(0x50020540, value)
        value = self.read32(0x0810B82C)
        self.write32(0x50020544, value)
        value = self.read32(0x0810B830)
        self.write32(0x50020548, value)
        value = self.read32(0x0810B834)
        self.write32(0x5002054C, value)
        value = self.read32(0x0810B840)
        self.write32(0x50020558, value)
        value = self.read32(0x0810B844)
        self.write32(0x5002055C, value)
        value = self.read32(0x0810B84C)
        self.write32(0x50020564, value)
        value = self.read32(0x0810B850)
        self.write32(0x50020568, value)
        value = self.read32(0x0810B858)
        self.write32(0x50020570, value)
        value = self.read32(0x0810B860)
        self.write32(0x50020574, value)
        value = self.read32(0x0810B864)
        self.write32(0x50020578, value)
        value = self.read32(0x0810B868)
        self.write32(0x5002057C, value)
        value = self.read32(0x0810B86C)
        self.write32(0x50020580, value)
        value = self.read32(0x0810B870)
        self.write32(0x50020584, value)

        value = self.read32(0x0810B914)
        if ((value & 0xFF000000) >> 24) == 0x5A:
            self.write32(0x5002075C, value)

        temp = self.read32(0x50010604)
        self.write32(0x20307F30, temp)
        temp = self.read32(0x50010650)
        self.write32(0x20307F34, temp)
        temp = self.read32(0x50010608)
        self.write32(0x20307F28, temp)
        temp = self.read32(0x50010654)
        self.write32(0x20307F2C, temp)

        error_status = self.read32(0x50024014)
        if ((error_status & 0xFF000000) >> 24) == 0x5A:
            pin_sel = (error_status & 0x00000030) >> 4
            if pin_sel == 0x0:
                gpamux2 = self.read32(0x40030010)
                gpamux2 = (gpamux2 & ~(0x03 << 16)) | (0x01 << 16)
                self.write32(0x40030010, gpamux2)

                gpagmux2 = self.read32(0x40030044)
                gpagmux2 = (gpagmux2 & ~(0x03 << 16)) | (0x03 << 16)
                self.write32(0x40030044, gpagmux2)

                lock = self.read32(0x40030078)
                lock |= (0x01 << 24)
                self.write32(0x40030078, lock)
            elif pin_sel == 0x1:
                gpamux2 = self.read32(0x40030010)
                gpamux2 = (gpamux2 & ~(0x03 << 24)) | (0x01 << 24)
                self.write32(0x40030010, gpamux2)

                gpagmux2 = self.read32(0x40030044)
                gpagmux2 = (gpagmux2 & ~(0x03 << 24)) | (0x03 << 24)
                self.write32(0x40030044, gpagmux2)

                lock = self.read32(0x40030078)
                lock |= (0x01 << 28)
                self.write32(0x40030078, lock)
            elif pin_sel == 0x2:
                gpamux2 = self.read32(0x40030010)
                gpamux2 = (gpamux2 & ~(0x03 << 26)) | (0x01 << 26)
                self.write32(0x40030010, gpamux2)

                gpagmux2 = self.read32(0x40030044)
                gpagmux2 = (gpagmux2 & ~(0x03 << 26)) | (0x03 << 26)
                self.write32(0x40030044, gpagmux2)

                lock = self.read32(0x40030078)
                lock |= (0x01 << 29)
                self.write32(0x40030078, lock)

        config_val = self.read32(0x0810B914) & 0xFF
        if config_val == 0x00:
            self.write32(0x40030018, 0xFFCFFFFF)
            self.write32(0x40030098, 0x0F6001FF)
        elif config_val == 0x01:
            self.write32(0x40030018, 0xFFCFFFFF)
            self.write32(0x40030098, 0x00607FFF)
        elif config_val == 0x02:
            self.write32(0x40030018, 0x31CF3FFF)
            self.write32(0x40030098, 0x0000007B)
        elif config_val == 0x03:
            self.write32(0x40030018, 0x31CF3BFF)
            self.write32(0x40030098, 0x0000007B)
        elif config_val == 0x04:
            self.write32(0x40030018, 0x310D30FF)
            self.write32(0x40030098, 0x0000007B)

        if (self.read32(0x0810BA00) & 0xFFFF) == 0xA5A5:
            if (self.read32(0x50020B00) & 0x03) == 0x03:
                self.write32(0x5002800C, self.read32(0x0810BA04))
                self.write32(0x50028000, self.read32(0x0810BA08))
                self.write32(0x50028004, self.read32(0x0810BA0C))

        value = self.read32(0x50020A78)
        value |= 0x0F
        self.write32(0x50020A78, value)

        self.write32(0x50028010, self.read32(0x0810BA5C))
        self.write32(0x50028014, self.read32(0x0810BA60))
        self.write32(0x50028018, self.read32(0x0810BA64))
        self.write32(0x50028068, self.read32(0x0810BA68))
        self.write32(0x5002806C, self.read32(0x0810BA6C))
        self.write32(0x50028070, self.read32(0x0810BA70))

        self.write32(0x4002007C, self.read32(0x0810BA10))
        self.write32(0x4002047C, self.read32(0x0810BA14))
        self.write32(0x4002087C, self.read32(0x0810BA18))

        self.write16(0x40020076, self.read32(0x0810BA1C))
        self.write16(0x40020476, self.read32(0x0810BA20))
        self.write16(0x40020876, self.read32(0x0810BA24))

        self.write32(0x400200E0, self.read32(0x0810BA28))
        self.write32(0x400200E4, self.read32(0x0810BA2C))
        self.write32(0x400200E8, self.read32(0x0810BA30))
        self.write32(0x400204E0, self.read32(0x0810BA34))
        self.write32(0x400204E4, self.read32(0x0810BA38))
        self.write32(0x400204E8, self.read32(0x0810BA3C))
        self.write32(0x400208E0, self.read32(0x0810BA40))
        self.write32(0x400208E4, self.read32(0x0810BA44))

        value = self.read32(0x50020A84)
        value |= 0x00030000
        self.write32(0x50020A84, value)

        self.write16(0x5000180C, self.read16(0x0810BA50))
        self.write16(0x50001C0C, self.read16(0x0810BA54))

        value = self.read32(0x50020B00)
        value &= ~(0x03)
        self.write32(0x50020B00, value)

        for addr in range(0xE000E180, 0xE000E1C0, 4):
            self.write32(addr, 0xFFFFFFFF)
        for addr in range(0xE000E280, 0xE000E2C0, 4):
            self.write32(addr, 0xFFFFFFFF)

        LOG.info("CPU and peripheral initialization completed")

    def _apply_dbgmcu(self):
        self.write32(DBGMCU.CTRL, DBGMCU.CTRL_VALUE)
        self.write32(DBGMCU.APB1CFG0, DBGMCU.APB1CFG0_VALUE)
        self.write32(DBGMCU.APB1CFG1, DBGMCU.APB1CFG1_VALUE)
        self.write32(DBGMCU.APB2CFG0, DBGMCU.APB2CFG0_VALUE)
        self.write32(DBGMCU.APB2CFG1, DBGMCU.APB2CFG1_VALUE)
        self.write32(DBGMCU.AHB1CFG0, DBGMCU.AHB1CFG0_VALUE)
        self.write32(DBGMCU.AHB1CFG1, DBGMCU.AHB1CFG1_VALUE)

    def _apply_hardware_startup(self):
        if self.delegate_implements("geehy_r501_startup"):
            self.call_delegate("geehy_r501_startup", target=self)
            self._apply_dbgmcu()
            return

        self.r501_dcs_setup()
        self.bootmode_setup()
        if self.delegate_implements("geehy_r501_init_cpu"):
            self.call_delegate("geehy_r501_init_cpu", target=self)
        else:
            self.init_cpu()
        self._apply_dbgmcu()

    def r501_refresh_sram3_for_flash(self, bootmode=False):
        """Unlock SRAM3 after reset; flash algo and page buffers use 0x20300000."""
        self.r501_dcs_setup(log_sequence=False)
        if bootmode:
            self.bootmode_setup()

    def _apply_flash_startup(self):
        self.r501_refresh_sram3_for_flash(bootmode=True)
        self._apply_dbgmcu()

    def prepare_for_flash_operation(self):
        if self._g32r501_flash_operation_ready:
            self.r501_refresh_sram3_for_flash()
            return

        self._g32r501_flash_reset = True
        try:
            previous_core = self.selected_core.core_number if self.selected_core is not None else None
            if 0 in self.cores:
                self.selected_core = 0
            # Halt secondary cores before FLM; a running CPU1 can contend for flash.
            for core_number, core in self.cores.items():
                if core_number == 0:
                    continue
                try:
                    core.halt()
                except exceptions.Error as exc:
                    LOG.debug("Could not halt core%d before flash: %s", core_number, exc)
            rt = self.ResetType.SYSRESETREQ
            if self.selected_core is not None:
                self.selected_core.reset_and_halt(rt)
            else:
                super(G32R501xxBase, self).reset_and_halt(rt)
            self.apply_startup_configuration_for_flash()
            self._g32r501_flash_operation_ready = True
            if previous_core is not None and previous_core in self.cores:
                self.selected_core = previous_core
        finally:
            self._g32r501_flash_reset = False

    def restore_after_flash_operation(self):
        self._g32r501_flash_operation_ready = False
        # After sector erase the flash vector is blank; full init_cpu between erase and
        # program (builder.cleanup) would disturb SRAM3/FLM state. Refresh DCS only.
        try:
            msp, pc = self.read_memory_block32(self._core_vector_addresses.get(0, CORE0_SET_ADDR), 2)
            vector_valid = self._is_valid_user_vector(msp, pc, 0)
        except exceptions.Error:
            vector_valid = False
        if not vector_valid:
            LOG.debug("G32R501 post-flash restore: flash vector blank, refreshing SRAM3 DCS only")
            self.r501_refresh_sram3_for_flash()
            return
        self.apply_startup_configuration()

    def apply_startup_configuration_for_flash(self):
        previous_core = self.selected_core.core_number if self.selected_core is not None else None
        if 0 in self.cores:
            self.selected_core = 0

        try:
            self._apply_flash_startup()
        finally:
            if previous_core is not None and previous_core in self.cores:
                self.selected_core = previous_core

    def apply_startup_configuration(self):
        previous_core = self.selected_core.core_number if self.selected_core is not None else None
        if 0 in self.cores:
            self.selected_core = 0

        try:
            if self.delegate_implements("geehy_r501_startup"):
                self.call_delegate("geehy_r501_startup", target=self)
                return True

            self._apply_hardware_startup()
            core0_ok = self.set_core_vector_table(0)
            if self.HAS_CORE1 and self.BRINGUP_CORE1_VECTOR:
                self.set_core_vector_table(1)
            return core0_ok
        finally:
            if previous_core is not None and previous_core in self.cores:
                self.selected_core = previous_core

    def post_connect_hook(self):
        self.apply_startup_configuration()

    def _is_flash_cli_reset(self) -> bool:
        return getattr(self.session, 'command', None) in ('load', 'erase')

    def reset(self, reset_type=None):
        self._g32r501_refresh_before_resume = False
        self.reset_and_halt(reset_type or self.ResetType.SYSRESETREQ)
        core = self.cores.get(0)
        if core is not None and self._g32r501_user_vector_valid.get(0, False):
            core.resume()
            LOG.info("Reset completed; core resumed.")
        else:
            LOG.info("Reset completed; core remains halted because no valid user vector is present.")

    def reset_and_halt(self, reset_type=None):
        self._g32r501_refresh_before_resume = False
        if self._is_flash_cli_reset():
            self.prepare_for_flash_operation()
            return
        super().reset_and_halt(reset_type or self.ResetType.SYSRESETREQ)

    def create_init_sequence(self):
        seq = super().create_init_sequence()
        seq.wrap_task(
            'discovery',
            lambda seq: seq.replace_task('find_aps', self.find_aps).replace_task('create_cores', self.create_cores),
        )
        return seq

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return
        self.dp.read_ap(0xFC)
        self.dp.valid_aps = list(self.VALID_APS)
        AccessPort.create(self.dp, APv1Address(0))

    def create_cores(self):
        core = G32R501CortexM(self.session, self.aps[0], self.memory_map, 0)
        core.default_reset_type = self.ResetType.CORE
        self.aps[0].core = core
        core.init()
        self.add_core(core)
        self.selected_core = 0
        LOG.info("core0 is created and initialized.")


class G32R501Dxx(G32R501xxBase):
    MEMORY_MAP = MEMORY_MAP_G32R501XX
    HAS_CORE1 = True
    BRINGUP_CORE1_VECTOR = False
    _CORE1_BOOT_CTRL_ADDR = 0x50020058
    _CORE1_BOOT_ENABLE_MASK = 0x2

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def _cpu1_vector_table_in_flash_valid(self) -> bool:
        addr = self._core_vector_addresses.get(1, CORE1_SET_ADDR)
        if addr in (DISABLED_VECTOR_TABLE_ADDRESS, 0xFFFFFFFF):
            return False
        try:
            msp = self.read32(addr)
            reset_handler = self.read32(addr + 4)
        except Exception as exc:
            LOG.debug("CPU1 vector table probe at 0x%08X failed: %s", addr, exc)
            return False
        if msp in (0, 0xFFFFFFFF) or reset_handler in (0, 0xFFFFFFFF):
            return False
        return True

    def _maybe_release_and_bringup_core1(self) -> None:
        if 1 not in self.cores:
            return
        vaddr = self._core_vector_addresses.get(1, CORE1_SET_ADDR)
        if not self._cpu1_vector_table_in_flash_valid():
            LOG.warning(
                "CPU1 vector at 0x%08X looks blank; CPU1 boot not released (safe for erase/program).",
                vaddr,
            )
            return
        LOG.info("CPU1 flash vector valid: releasing CPU1 boot and applying debugger vector context.")
        self.release_core1_boot()
        self.bringup_core1_vector()

    def _halt_core1_unless_released(self) -> None:
        core1 = self.cores.get(1)
        if core1 is None:
            return
        try:
            core1.halt()
        except exceptions.Error as exc:
            LOG.debug("Could not halt core1: %s", exc)

    def apply_startup_configuration(self):
        core0_ok = super().apply_startup_configuration()
        if self.delegate_implements("geehy_r501_startup"):
            return core0_ok
        if self._cpu1_vector_table_in_flash_valid():
            self._maybe_release_and_bringup_core1()
        else:
            LOG.info("CPU1 flash vector blank; keeping CPU1 halted (CPU0-only debug).")
            self._halt_core1_unless_released()
        return core0_ok

    def release_core1_boot(self) -> None:
        if 0 not in self.aps:
            LOG.warning("release_core1_boot: AP0 missing")
            return
        ap0 = self.aps[0]
        ap0.init()
        value = ap0.read32(self._CORE1_BOOT_CTRL_ADDR)
        ap0.write32(self._CORE1_BOOT_CTRL_ADDR, value | self._CORE1_BOOT_ENABLE_MASK)
        LOG.info(
            "CPU1 boot released (0x%08X = 0x%08X); entry from 0x50020054 = 0x%08X",
            self._CORE1_BOOT_CTRL_ADDR,
            value | self._CORE1_BOOT_ENABLE_MASK,
            self._core_start_addresses.get(1, CORE1_START_ADDR),
        )

    def bringup_core1_vector(self) -> None:
        self.set_core_vector_table(1)

    def create_cores(self):
        core0 = G32R501CortexM(self.session, self.aps[0], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.CORE
        self.aps[0].core = core0
        core0.init()
        self.add_core(core0)
        LOG.info("core0 is created and initialized.")

        LOG.info("Programming core1 boot address via AP0.")
        ap0 = self.aps[0]
        ap0.init()
        core1_start_addr = self._core_start_addresses.get(1, CORE1_START_ADDR)
        ap0.write32(0x50020054, core1_start_addr)

        core1 = G32R501CortexM(self.session, self.aps[1], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.CORE
        self.aps[1].core = core1
        core1.init()
        self.add_core(core1)
        self.selected_core = 0
        LOG.info("core1 is created and initialized.")


class G32R501xx(G32R501xxBase):
    MEMORY_MAP = MEMORY_MAP_G32R501XX

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)

    def create_cores(self):
        super().create_cores()
