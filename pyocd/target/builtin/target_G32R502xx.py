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
    CFG = 0xE0059004
    CFG_VALUE = 0x00000000
    CTRL1 = 0xE0059030
    CTRL1_VALUE = 0x00000000  # PWM/CAP/COMP/QEP halt freeze
    CTRL2 = 0xE0059038
    CTRL2_VALUE = 0x00000000  # comm peripheral / Flash bank halt freeze
    CTRL3 = 0xE0059040
    CTRL3_VALUE = 0x00000001  # freeze WDT when CPU halted


FLASH_ALGO = {
    'load_address' : 0x20000000,
    'instructions': [
    0xe7fdbe00,
    0xf5a04601, 0xf36f1280, 0xf1b10111, 0xf2446f00, 0xea5f0385, 0xf5b2911f, 0xea5f2f20, 0xebb3922f,
    0xea5f3f50, 0x4308901f, 0x47704310, 0xf240b570, 0xf04f0608, 0xf2c031ff, 0xf2400600, 0xf849050c,
    0xf64e1006, 0xf2ce5188, 0x22000100, 0xf647680b, 0xf2c04400, 0xf0430500, 0xf809030c, 0x600b2005,
    0xee002101, 0x2152111c, 0x0401f2c4, 0x0101f2c4, 0xf043880b, 0x800b0368, 0x0185f244, 0x3f50ebb1,
    0x211cee00, 0x2100d023, 0x71f6f6cf, 0x22c0f501, 0xf1b24002, 0xd01a6f00, 0x10d0f5a0, 0xd2164288,
    0x0478f8d4, 0x0104f240, 0x0100f2c0, 0xf44f07c0, 0xbf085000, 0x4080f44f, 0x0001f849, 0x30fff04f,
    0x0006f849, 0xf8092001, 0x20000005, 0x4620bd70, 0xf0002132, 0xb920f8f1, 0xf0002000, 0x2800f8f2,
    0x2001d0de, 0xbf00bd70, 0x47702000, 0x41f0e92d, 0xf240b084, 0x27000804, 0x6400f04f, 0xf2c0466d,
    0xf6c00800, 0xbf000704, 0x46212006, 0xf8def000, 0xbf004606, 0xf8dff000, 0xd1fb2802, 0xf000b996,
    0xb978f8df, 0xf44f4620, 0x462a6100, 0xf8ddf000, 0xf859b940, 0x44040008, 0xd3e542bc, 0xb0042000,
    0x81f0e8bd, 0xb0042001, 0x81f0e8bd, 0xb085b5f0, 0x010cf240, 0x0100f2c0, 0x2001f819, 0xf248b9da,
    0xf2400278, 0xf2c40304, 0x68120201, 0x0300f2c0, 0xf44f07d2, 0xbf085200, 0x4280f44f, 0x2003f849,
    0x0208f240, 0x33fff04f, 0x0200f2c0, 0x3002f849, 0xf8092201, 0x46022001, 0x0211f36f, 0x6f00f1b2,
    0xf819d114, 0x29011001, 0xf240d136, 0xf2c00604, 0xf8590600, 0xf5b11006, 0xd10a5f00, 0x0708f240,
    0x0700f2c0, 0x1007f859, 0xd10e4288, 0xb0052000, 0x424abdf0, 0xd51f0113, 0xf1004010, 0xfbb24278,
    0xfb03f3f1, 0xb9b92111, 0x4601e7e8, 0x460c2006, 0xf86cf000, 0xbf004605, 0xf86df000, 0xd1fb2802,
    0xf000b955, 0xb938f86d, 0x0006f859, 0x0881aa01, 0xf0004620, 0xb110f86a, 0xb0052001, 0xf849bdf0,
    0xe7d34007, 0x4df0e92d, 0x4606b082, 0xf0004248, 0xf04f0007, 0x18440800, 0x2000d03a, 0xf6cf4615,
    0xf24470f6, 0xf5000a85, 0xe0102bc0, 0xf5a62100, 0xf6cf10d0, 0x428871f6, 0x6828d211, 0x68686030,
    0x3c086070, 0x0608f106, 0x0508f105, 0xebbad01e, 0xbf1c3f56, 0x000bea06, 0x6f00f1b0, 0x4630d1e6,
    0x22024629, 0xf8cd2300, 0xf8cd8000, 0xf0008004, 0x4607f831, 0xf81ff000, 0xd1fb2802, 0xf000b91f,
    0x2800f81f, 0xf04fd0dd, 0xe0010801, 0x0800f04f, 0xb0024640, 0x8df0e8bd, 0x0c01f244, 0x0c00f2c1,
    0xf6464760, 0xf2c10c01, 0x47600c00, 0x6ca1f644, 0x0c00f2c1, 0xf2444760, 0xf2c14cd1, 0x47600c00,
    0x2c01f644, 0x0c00f2c1, 0xf2444760, 0xf2c15c71, 0x47600c00, 0x3c21f645, 0x0c00f2c1, 0x00004760,
    0x00000000, 0x00002000, 0xffffffff, 0x00000000
    ],
    'pc_init': 0x20000031,
    'pc_unInit': 0x200000ed,
    'pc_program_page': 0x20000229,
    'pc_erase_sector': 0x20000151,
    'pc_eraseAll': 0x200000f1,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000300,
    'begin_stack' : 0x20001b20,
    'end_stack' : 0x20000b20,
    'begin_data' : 0x20000320,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [
        0x20000320,
        0x20000720
    ],
    'min_program_length' : 0x400,
    'ro_start': 0x4,
    'ro_size': 0x300,
    'rw_start': 0x304,
    'rw_size': 0xc,
    'zi_start': 0x310,
    'zi_size': 0x4,
    'flash_start': 0x08000000,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}

OTP_ALGO = {
    'load_address': 0x20000000,
    'instructions': [
        0xe7fdbe00,
        0xf5a04601, 0xf36f1280, 0xf1b10111, 0xf2446f00, 0xea5f0385, 0xf5b2911f, 0xea5f2f20, 0xebb3922f,
        0xea5f3f50, 0x4308901f, 0x47704310, 0xf64eb580, 0xf2ce5188, 0x680a0100, 0x020cf042, 0x2101600a,
        0x111cee00, 0xf2c42152, 0x880a0101, 0x0268f042, 0xf244800a, 0x21000285, 0x3f50ebb2, 0x111cee00,
        0x2100d00e, 0x71f6f6cf, 0x22c0f501, 0xf1b24002, 0xd0056f00, 0x10d0f5a0, 0xd2014288, 0xbd802000,
        0x4000f647, 0xf2c42132, 0xf0000001, 0xb920f839, 0xf0002000, 0x2800f83a, 0x2001d0f0, 0xbf00bd80,
        0x47702000, 0x47702000, 0x41f0e92d, 0x4606b082, 0xf0004248, 0xf04f0007, 0x18440800, 0x4615d01c,
        0x46294630, 0x23002202, 0x8000f8cd, 0x8004f8cd, 0xf820f000, 0xbf004607, 0xf821f000, 0xd1fb2802,
        0x3c08b947, 0x0608f106, 0x0508f105, 0xf04fd1e8, 0xe0010800, 0x0801f04f, 0xb0024640, 0x81f0e8bd,
        0x0c01f244, 0x0c00f2c1, 0xf6464760, 0xf2c10c01, 0x47600c00, 0x3c21f645, 0x0c00f2c1, 0xf2444760,
        0xf2c14cd1, 0x47600c00, 0x00000000,
    ],
    'pc_init': 0x20000031,
    'pc_unInit': 0x200000a5,
    'pc_program_page': 0x200000ad,
    'pc_erase_sector': 0x200000a9,
    'static_base': 0x2000012c,
    'begin_stack': 0x20001730,
    'end_stack': 0x20001130,
    'begin_data': 0x20000130,
    'page_size': 0x800,
    'analyzer_supported': False,
    'analyzer_address': 0x00000000,
    'page_buffers': [0x20000130, 0x20000930],
    'min_program_length': 0x800,
    'ro_start': 0x4,
    'ro_size': 0x128,
    'rw_start': 0x12c,
    'rw_size': 0x4,
    'zi_start': 0x130,
    'zi_size': 0x0,
    'flash_start': 0x0810A000,
    'flash_size': 0x800,
    'sector_sizes': (
        (0x0, 0x800),
    ),
}

DECRYPT_KEYS = [
    (0x40010820, 0xFFFFFFFF),
    (0x40010824, 0xFFFFFFDC),
    (0x40010828, 0xFFFFFFFF),
    (0x4001082C, 0xFFFFFFFF),
    (0x400108A0, 0xFFFFFFFF),
    (0x400108A4, 0xFFFEDFFF),
    (0x400108A8, 0xFFFFFFFF),
    (0x400108AC, 0xFFFFFFFF),
]

DISABLED_VECTOR_TABLE_ADDRESS = 0xFFFFFFFF
VECTOR_TABLE_ADDR = 0x08000000
FLASH_START = 0x08000000
FLASH_END = 0x08040000
ITCM_START = 0x00000000
ITCM_END = 0x00008000
DTCM_START = 0x20000000
DTCM_END = 0x20008000


class G32R502Flash(Flash):
    def init(self, operation, address=None, clock=0, reset=False):
        if self._active_operation is not None and self._active_operation != operation:
            LOG.debug(
                "G32R502 switching flash operation from %s to %s without FLM unInit",
                self._active_operation.name,
                operation.name,
            )
            self._abort_active_flash_operation()
        return super().init(operation, address, clock, reset=reset)

    def uninit(self):
        if self._active_operation is None:
            return
        try:
            super().uninit()
        except exceptions.FlashFailure as exc:
            LOG.warning("G32R502 flash unInit failed (%s); clearing algo state", exc)
            self._abort_active_flash_operation()

    def prepare_target(self):
        if hasattr(self.target, "prepare_for_flash_operation"):
            self.target.prepare_for_flash_operation()
        if hasattr(self.target, "_apply_dbgmcu"):
            self.target._apply_dbgmcu()
        self._ensure_core_halted(timeout=2.0)
        self._mask_runtime_interrupts()

    def restore_target(self):
        super().restore_target()
        if hasattr(self.target, "restore_after_flash_operation"):
            self.target.restore_after_flash_operation()

    def _abort_active_flash_operation(self):
        try:
            self._ensure_core_halted(timeout=2.0)
        except exceptions.FlashFailure:
            LOG.debug("G32R502 could not halt before aborting flash operation")
        self._active_operation = None
        self._did_prepare_target = False
        if hasattr(self.target, "_g32r502_flash_operation_ready"):
            self.target._g32r502_flash_operation_ready = False

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
            LOG.debug("G32R502 flash context setup skipped: %s", exc)

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

        raise exceptions.FlashFailure("G32R502 core did not halt before flash algorithm call")

    def _call_function(self, pc, r0=None, r1=None, r2=None, r3=None, init=False):
        self._ensure_core_halted()
        self._mask_runtime_interrupts()
        if hasattr(self.target, "r502_dcs_setup"):
            self.target.r502_dcs_setup(log_sequence=False)
        super()._call_function(pc, r0, r1, r2, r3, init)


MEMORY_MAP_G32R502XX = MemoryMap(
    FlashRegion(
        start=0x08000000,
        length=0x40000,
        sector_size=0x2000,
        page_size=0x400,
        is_boot_memory=True,
        algo=FLASH_ALGO,
        flash_class=G32R502Flash,
    ),
    FlashRegion(
        start=0x0810A000,
        length=0x800,
        sector_size=0x800,
        page_size=0x800,
        is_erasable=False,
        is_testable=False,
        algo=OTP_ALGO,
        flash_class=G32R502Flash,
    ),
    FlashRegion(
        start=0x0810B000,
        length=0x800,
        sector_size=0x800,
        page_size=0x800,
        is_erasable=False,
        is_testable=False,
        algo=OTP_ALGO,
        flash_class=G32R502Flash,
    ),
    RamRegion(start=0x00000000, length=0x4000, access="rwx", is_cacheable=False),
    RamRegion(start=0x20000000, length=0x6000, access="rwx", init="0"),
)


class G32R502CortexM(CortexM):
    def halt(self) -> None:
        super().halt()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if self.is_halted():
                return
            time.sleep(0.01)
        LOG.warning("G32R502 core did not report halted within timeout.")

    def reset(self, reset_type=None) -> None:
        # pyOCD >= 0.45: CortexM.reset_and_halt() calls self.reset().
        # Only perform the raw reset here. Do NOT apply startup or resume —
        # that would defeat reset-catch and break flash algo (IPSR=3 HardFault).
        # Debug "reset and run" is handled by G32R502xx.reset().
        board = self.session.board.target
        board._g32r502_refresh_before_resume = False
        rt = reset_type if reset_type is not None else board.ResetType.SYSRESETREQ
        super().reset(rt)

    def reset_and_halt(self, reset_type=None):
        board = self.session.board.target
        board._g32r502_refresh_before_resume = False
        rt = reset_type if reset_type is not None else board.ResetType.SYSRESETREQ
        super().reset_and_halt(rt)
        if getattr(board, "_g32r502_flash_reset", False):
            return
        board.apply_startup_configuration()
        # Keep halted after applying user vectors (flash / debug halt paths).
        if not self.is_halted():
            self.halt()

    def resume(self) -> None:
        board = self.session.board.target
        if getattr(board, "_g32r502_refresh_before_resume", False):
            board._g32r502_refresh_before_resume = False
            LOG.info("Applying G32R502 startup before resume.")
            if not board.apply_startup_configuration():
                LOG.info("Resume skipped because no valid user vector is present.")
                return
        super().resume()


class G32R502xx(CoreSightTarget):
    VENDOR = "Geehy"
    MEMORY_MAP = MEMORY_MAP_G32R502XX
    VALID_APS = (0,)
    SAFE_SP = 0x20001FF8

    def __init__(self, session):
        self._decrypt_keys = list(DECRYPT_KEYS)
        self._flash_algo = FLASH_ALGO
        self._vector_table_address = VECTOR_TABLE_ADDR
        super().__init__(session, self.MEMORY_MAP)
        self._g32r502_refresh_before_resume = False
        self._g32r502_user_vector_valid = False
        self._g32r502_flash_reset = False
        self._g32r502_flash_operation_ready = False
        self.session.subscribe(self._g32r502_on_post_flash_program, Target.Event.POST_FLASH_PROGRAM)

    def _g32r502_on_post_flash_program(self, notification):
        self._g32r502_refresh_before_resume = True

    def set_decrypt_keys(self, decrypt_keys):
        self._decrypt_keys = list(decrypt_keys)

    def set_vector_table_address(self, address):
        self._vector_table_address = address

    def configure_startup(self, decrypt_keys=None, vector_table_address=None):
        if decrypt_keys is not None:
            self.set_decrypt_keys(decrypt_keys)
        if vector_table_address is not None:
            self.set_vector_table_address(vector_table_address)

    def r502_dcs_setup(self, log_sequence=True):
        ap = MiniAP(self.dp)
        ap.init()

        ap.write32(0x40012C00, 0x5AFFFFFF)
        ap.write32(0x40012C04, 0xFFFFFF03)
        ap.write32(0x40012C08, 0xFFFFFFFF)

        if log_sequence:
            LOG.info("G32R502 DCS key sequence ...")
        for addr, value in self._decrypt_keys:
            ap.write32(addr, value)
            if log_sequence:
                LOG.info("0x%08X -> [0x%08X]", addr, value)

        if log_sequence:
            LOG.info("G32R502 DCS setup completed successfully.")
        else:
            LOG.debug("G32R502 DCS setup refreshed before flash algorithm call.")

    def _ensure_core_halted(self, core, timeout: float = 0.5) -> bool:
        core.halt()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if core.is_halted():
                return True
            time.sleep(0.01)
        return False

    def _is_valid_user_vector(self, sp_value: int, pc_value: int) -> bool:
        if sp_value in (0x00000000, 0xFFFFFFFF) or pc_value in (0x00000000, 0xFFFFFFFF):
            return False
        sp_ok = (DTCM_START < sp_value <= DTCM_END) or (ITCM_START < sp_value <= ITCM_END)
        pc_addr = pc_value & ~1
        pc_ok = (
            (pc_value & 1) != 0
            and (
                (FLASH_START <= pc_addr < FLASH_END)
                or (ITCM_START <= pc_addr < ITCM_END)
            )
        )
        return sp_ok and pc_ok

    def set_core_vector_table(self):
        self._g32r502_user_vector_valid = False
        vector_table_address = self._vector_table_address
        if vector_table_address == DISABLED_VECTOR_TABLE_ADDRESS:
            return False

        core = self.cores.get(0)
        if core is None:
            LOG.warning("Skipping SP/PC setup because the core is not available.")
            return False

        if not self._ensure_core_halted(core):
            LOG.warning(
                "Skipping SP/PC setup: core did not enter halt within timeout.",
            )
            return False
        sp_value, pc_value = core.read_memory_block32(vector_table_address, 2)
        if not self._is_valid_user_vector(sp_value, pc_value):
            LOG.warning(
                "Vector table at 0x%08X is invalid (MSP=0x%08X PC=0x%08X); core remains halted.",
                vector_table_address,
                sp_value,
                pc_value,
            )
            return False
        LOG.info("Applying vector table from 0x%08X", vector_table_address)
        LOG.info("  MSP = 0x%08X", sp_value)
        LOG.info("  PC  = 0x%08X", pc_value)
        core.write_memory(0xE000ED08, vector_table_address)
        core.write_core_register("msp", sp_value)
        core.write_core_register("psp", sp_value)
        core.write_core_register("xpsr", 0x01000000)
        core.write_core_register("pc", pc_value & ~1)
        self._g32r502_user_vector_valid = True
        return True

    def bootmode_setup(self):
        self.write32(0x40012C00, 0xA5FFFFFF)
        LOG.info("Entering standalone boot mode (skip BootROM user path)")

    def init_cpu(self):
        self.write32(0xE000ED88, self.read32(0xE000ED88) | 0x0C)

        self.write32(0x40018200, self.read32(0x40018200) & 0xFFFFFFF0)
        self.write16(0x40010052, self.read16(0x40010052) | 0x68)
        self.write32(0x40012C74, 0x01)
        self.write16(0x400100C0, 0x0001)

        self.write32(0x4001341C, 0x00000000)
        self.write32(0x40013444, 0x00000000)

        self.write32(0x40016C78, self.read32(0x0810B93C))
        self.write32(0x40016C88, self.read32(0x0810B940))

        self.write32(0x40017C40, 0x0000000F)

        if (self.read32(0x0810B894) & 0xFFFF) == 0x5A5A:
            if (self.read32(0x0810B878) & 0xFFFF) == 0x5A00:
                self.write32(0x40016CD4, self.read32(0x40016CD4) | 0x8000)
            self.write32(0x40016C24, self.read32(0x0810B884))
            self.write32(0x40016C1C, self.read32(0x0810B888))
            self.write32(0x40016C20, self.read32(0x0810B88C))
            self.write32(0x40016C28, self.read32(0x0810B890))

        if (self.read32(0x0810B898) & 0xFFFF) == 0x5A5A:
            self.write32(0x40016C00, self.read32(0x0810B89C))
            self.write32(0x40016C04, self.read32(0x0810B8A0))
            self.write32(0x40016C0C, self.read32(0x0810B8A4))

        self.write32(0x40016C98, self.read32(0x0810B944))

        self.write32(0x40013110, self.read32(0x0810B800))
        self.write32(0x40013114, self.read32(0x0810B804))
        self.write32(0x4001312C, self.read32(0x0810B814))
        self.write32(0x40013130, self.read32(0x0810B818))
        self.write32(0x40013134, self.read32(0x0810B81C))
        self.write32(0x40013140, self.read32(0x0810B828))
        self.write32(0x40013144, self.read32(0x0810B82C))
        self.write32(0x40013148, self.read32(0x0810B830))
        self.write32(0x4001314C, self.read32(0x0810B834))
        self.write32(0x40013158, self.read32(0x0810B840))
        self.write32(0x4001315C, self.read32(0x0810B844))
        self.write32(0x40013164, self.read32(0x0810B84C))
        self.write32(0x40013174, self.read32(0x0810B860))
        self.write32(0x4001317C, self.read32(0x0810B868))
        self.write32(0x40013180, self.read32(0x0810B86C))
        self.write32(0x40013184, self.read32(0x0810B870))
        self.write32(0x4001335C, self.read32(0x0810B914) & 0x0000000F)

        if (self.read32(0x0810B914) & 0xFF000000) == 0x5A000000:
            if (self.read32(0x0810B914) & 0xFF) == 0x01:
                self.write32(0x40030018, self.read32(0x40030018) & 0xFFFFFFFF)
                self.write32(0x40030098, self.read32(0x40030098) & 0x0003FFFF)
            if (self.read32(0x0810B914) & 0xFF) == 0x02:
                self.write32(0x40030018, self.read32(0x40030018) & 0x31FF3FFF)
                self.write32(0x40030098, self.read32(0x40030098) & 0x000083FB)
            if (self.read32(0x0810B914) & 0xFF) == 0x04:
                self.write32(0x40030018, self.read32(0x40030018) & 0x311D30FF)
                self.write32(0x40030098, self.read32(0x40030098) & 0x000090FB)
            if (self.read32(0x0810B914) & 0xFF) == 0x05:
                self.write32(0x40030018, self.read32(0x40030018) & 0x310C08AB)
                self.write32(0x40030098, self.read32(0x40030098) & 0x000080F9)

        if (self.read32(0x0810BA00) & 0xFFFF) == 0xA5A5:
            self.write32(0x40016C0C, self.read32(0x0810BA04))
            self.write32(0x40016C00, self.read32(0x0810BA08))
            self.write32(0x40016C04, self.read32(0x0810BA0C))

            self.write32(0x40013678, self.read32(0x40013678) | 0x05)
            self.write32(0x50001C7C, self.read32(0x0810BA10))
            self.write32(0x5000207C, self.read32(0x0810BA18))
            self.write16(0x50001C76, self.read16(0x0810BA1C))
            self.write16(0x50002076, self.read16(0x0810BA24))
            self.write32(0x50001CE0, self.read32(0x0810BA28))
            self.write32(0x50001CE4, self.read32(0x0810BA2C))
            self.write32(0x50001CE8, self.read32(0x0810BA30))
            self.write32(0x500020E0, self.read32(0x0810BA40))
            self.write32(0x500020E4, self.read32(0x0810BA44))
            self.write32(0x500020E8, self.read32(0x0810BA48))

            self.write32(0x40016C3C, self.read32(0x0810BA4C))

            self.write32(0x40013684, self.read32(0x40013684) | 0x00030000)
            self.write16(0x4002400C, (self.read16(0x4002400C) & 0xFF00) | (self.read16(0x0810BA50) & 0x00FF))
            self.write16(0x4002440C, (self.read16(0x4002440C) & 0xFF00) | (self.read16(0x0810BA54) & 0x00FF))

            self.write32(0x40016C10, self.read32(0x0810BA5C))
            self.write32(0x40016C18, self.read32(0x0810BA64))
            self.write32(0x40016C68, self.read32(0x0810BA68))
            self.write32(0x40016C70, self.read32(0x0810BA70))

        self.write32(0x40017C00, 0x00000F00)

        self.write32(0x400136FC, 0x00000003)

        self.write32(0xE000E180, 0xFFFFFFFF)
        self.write32(0xE000E184, 0xFFFFFFFF)
        self.write32(0xE000E188, 0xFFFFFFFF)
        self.write32(0xE000E18C, 0xFFFFFFFF)
        self.write32(0xE000E190, 0xFFFFFFFF)
        self.write32(0xE000E194, 0xFFFFFFFF)
        self.write32(0xE000E198, 0xFFFFFFFF)
        self.write32(0xE000E19C, 0xFFFFFFFF)
        self.write32(0xE000E1A0, 0xFFFFFFFF)
        self.write32(0xE000E1A4, 0xFFFFFFFF)
        self.write32(0xE000E1A8, 0xFFFFFFFF)
        self.write32(0xE000E1AC, 0xFFFFFFFF)
        self.write32(0xE000E1B0, 0xFFFFFFFF)
        self.write32(0xE000E1B4, 0xFFFFFFFF)
        self.write32(0xE000E1B8, 0xFFFFFFFF)
        self.write32(0xE000E1BC, 0xFFFFFFFF)
        self.write32(0xE000E280, 0xFFFFFFFF)
        self.write32(0xE000E284, 0xFFFFFFFF)
        self.write32(0xE000E288, 0xFFFFFFFF)
        self.write32(0xE000E28C, 0xFFFFFFFF)
        self.write32(0xE000E290, 0xFFFFFFFF)
        self.write32(0xE000E294, 0xFFFFFFFF)
        self.write32(0xE000E298, 0xFFFFFFFF)
        self.write32(0xE000E29C, 0xFFFFFFFF)
        self.write32(0xE000E2A0, 0xFFFFFFFF)
        self.write32(0xE000E2A4, 0xFFFFFFFF)
        self.write32(0xE000E2A8, 0xFFFFFFFF)
        self.write32(0xE000E2AC, 0xFFFFFFFF)
        self.write32(0xE000E2B0, 0xFFFFFFFF)
        self.write32(0xE000E2B4, 0xFFFFFFFF)
        self.write32(0xE000E2B8, 0xFFFFFFFF)
        self.write32(0xE000E2BC, 0xFFFFFFFF)

        LOG.info("CPU and peripheral initialization completed")

    def _apply_dbgmcu(self):
        self.write32(DBGMCU.CFG, DBGMCU.CFG_VALUE)
        self.write32(DBGMCU.CTRL1, DBGMCU.CTRL1_VALUE)
        self.write32(DBGMCU.CTRL2, DBGMCU.CTRL2_VALUE)
        self.write32(DBGMCU.CTRL3, DBGMCU.CTRL3_VALUE)

    def _apply_hardware_startup(self):
        if self.delegate_implements("geehy_r502_startup"):
            self.call_delegate("geehy_r502_startup", target=self)
            self._apply_dbgmcu()
            return

        self.r502_dcs_setup()
        self.bootmode_setup()
        if self.delegate_implements("geehy_r502_init_cpu"):
            self.call_delegate("geehy_r502_init_cpu", target=self)
        else:
            self.init_cpu()
        self._apply_dbgmcu()

    def _apply_flash_startup(self):
        # Flash path: unlock DCS / bootmode / DBGMCU only. Do not load user SP/PC
        # or resume — FLM must run halted with a clean vector-catch state.
        self.r502_dcs_setup(log_sequence=False)
        self.bootmode_setup()
        self._apply_dbgmcu()
        core = self.cores.get(0)
        if core is not None and not core.is_halted():
            core.halt()

    def prepare_for_flash_operation(self):
        if self._g32r502_flash_operation_ready:
            return

        self._g32r502_flash_reset = True
        try:
            rt = self.ResetType.SYSRESETREQ
            if self.selected_core is not None:
                self.selected_core.reset_and_halt(rt)
            else:
                super(G32R502xx, self).reset_and_halt(rt)
            self.apply_startup_configuration_for_flash()
            self._g32r502_flash_operation_ready = True
        finally:
            self._g32r502_flash_reset = False

    def restore_after_flash_operation(self):
        self._g32r502_flash_operation_ready = False
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
            if self.delegate_implements("geehy_r502_startup"):
                self.call_delegate("geehy_r502_startup", target=self)
                return True

            self._apply_hardware_startup()
            return self.set_core_vector_table()
        finally:
            if previous_core is not None and previous_core in self.cores:
                self.selected_core = previous_core

    def post_connect_hook(self):
        self.apply_startup_configuration()

    def reset(self, reset_type=None):
        self._g32r502_refresh_before_resume = False
        self.reset_and_halt(reset_type or self.ResetType.SYSRESETREQ)
        core = self.cores.get(0)
        if core is not None and self._g32r502_user_vector_valid:
            core.resume()
            LOG.info("Reset completed; core resumed.")
        else:
            LOG.info("Reset completed; core remains halted because no valid user vector is present.")

    def _is_flash_cli_reset(self) -> bool:
        return getattr(self.session, 'command', None) in ('load', 'erase')

    def reset_and_halt(self, reset_type=None):
        self._g32r502_refresh_before_resume = False
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
        core = G32R502CortexM(self.session, self.aps[0], self.memory_map, 0)
        core.default_reset_type = self.ResetType.CORE
        self.aps[0].core = core
        core.init()
        self.add_core(core)
        self.selected_core = 0
        LOG.info("Core is created and initialized.")
