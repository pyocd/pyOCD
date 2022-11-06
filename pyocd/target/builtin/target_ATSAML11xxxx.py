# pyOCD debugger
# Copyright (c) 2021 Nuvoton
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

from typing import (overload, TYPE_CHECKING)
from ...core import exceptions
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile
from ...utility.timeout import Timeout

SCS_DHCSR       = 0xE000EDF0
SCS_DHCSR_S_SDE = 0x00100000
SCU_SRAMNSSET   = 0x4002F024

DSU_CTRL    = 0x41002100
DSU_STATUSA = 0x41002101
DSU_STATUSB = 0x41002102
DSU_BCC0    = 0x41002120
DSU_BCC1    = 0x41002124

BOOTROM_CMD_PREFIX = 0x44424700
BOOTROM_SIG_PREFIX = 0xec000000

DSU_STATUSA_DONE    = (1<<0)
DSU_STATUSA_CRSTEXT = (1<<1)

DSU_STATUSB_BCCD0 = (1<<6)
DSU_STATUSB_BCCD1 = (1<<7)

BOOTROM_CMD_INIT = 0x55
BOOTROM_CMD_EXIT = 0xAA
BOOTROM_CMD_CE2  = 0xe2

BOOTROM_STATUS_SIG_COMM        = 0x20
BOOTROM_STATUS_SIG_CMD_SUCCESS = 0x21
BOOTROM_STATUS_SIG_CMD_VALID   = 0x24
BOOTROM_STATUS_SIG_BOOTOK      = 0x39

NVM_BOOTCONFIG = 0x0080c000
BOCOR_CEKEY0 = 0x10
BOCOR_CEKEY1 = 0x20
BOCOR_CEKEY2 = 0x30

MASS_ERASE_TIMEOUT = 15.0

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")

# first 2k of SRAM is cleared on reset
FLASH_ALGO = {
    'load_address' : 0x20000800,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xb084b580, 0x60f8af00, 0x607a60b9, 0xf640b672, 0xf2c40300, 0x691a0300, 0x0300f640, 0x0300f2c4,
    0x430a2108, 0xf640611a, 0xf2c40300, 0x699a0300, 0x0300f640, 0x0300f2c4, 0x430a2104, 0x2300619a,
    0x46bd0018, 0xbd80b004, 0xb082b580, 0x6078af00, 0x00182300, 0xb00246bd, 0x0000bd80, 0xb084b580,
    0x6078af00, 0x60fb687b, 0xf24546c0, 0xf2c40300, 0x8b1b1300, 0x001ab29b, 0x40132304, 0xd0f42b00,
    0x0300f245, 0x1300f2c4, 0xb29b8b1b, 0x2302001a, 0xb18b4013, 0x0300f245, 0x1300f2c4, 0x801a4a1c,
    0xf24546c0, 0xf2c40300, 0x8b1b1300, 0x001ab29b, 0x40132304, 0xd0f42b00, 0x22ff68fb, 0xf245601a,
    0xf2c40300, 0x4a131300, 0x46c0801a, 0x0300f245, 0x1300f2c4, 0xb29b8b1b, 0x2304001a, 0x2b004013,
    0xf245d0f4, 0xf2c40300, 0x4a091300, 0x46c0801a, 0x0300f245, 0x1300f2c4, 0xb29b8b1b, 0x2304001a,
    0x2b004013, 0x2300d0f4, 0x46bd0018, 0xbd80b004, 0xffffa544, 0xffffa502, 0xb088b580, 0x60f8af00,
    0x607a60b9, 0x68bb68fa, 0x613b18d3, 0x223f68fb, 0x33404393, 0xe05f61fb, 0x61bb68fb, 0x68fb69fa,
    0x68bb1ad2, 0xd9004293, 0x617b0013, 0x697b68ba, 0x60bb1ad3, 0x697b68fa, 0x60fb18d3, 0x334069fb,
    0x46c061fb, 0x0300f245, 0x1300f2c4, 0xb29b8b1b, 0x2304001a, 0x2b004013, 0xf245d0f4, 0xf2c40300,
    0x8b1b1300, 0x001ab29b, 0x40132302, 0xf245b18b, 0xf2c40300, 0x4a1d1300, 0x46c0801a, 0x0300f245,
    0x1300f2c4, 0xb29b8b1b, 0x2304001a, 0x2b004013, 0x697bd0f4, 0x617b089b, 0x687ae007, 0x607b1d13,
    0x1d1969bb, 0x681261b9, 0x697b601a, 0x617a1e5a, 0xd1f22b00, 0x0300f245, 0x1300f2c4, 0x801a4a0c,
    0xf24546c0, 0xf2c40300, 0x8b1b1300, 0x001ab29b, 0x40132304, 0xd0f42b00, 0x693b68fa, 0xd39b429a,
    0x00182300, 0xb00846bd, 0x46c0bd80, 0xffffa544, 0xffffa504, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000805,
    'pc_unInit': 0x2000084d,
    'pc_program_page': 0x2000091d,
    'pc_erase_sector': 0x20000861,
    'pc_eraseAll': 0x120000803,

    'static_base' : 0x20000800 + 0x00000004 + 0x00000220,
    'begin_stack' : 0x20001030,
    'end_stack' : 0x20000c30,
    'begin_data' : 0x20000800 + 0x1000,
    'page_size' : 0x40,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00001030,
    # Enable double buffering
    'page_buffers' : [
        0x20000a30,
        0x20000b30
    ],
    'min_program_length' : 0x40,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x220,
    'rw_start': 0x224,
    'rw_size': 0x0,
    'zi_start': 0x224,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x100),
    )
}

class ATSAML11D16A(CoreSightTarget):
    VENDOR = "Microchip:3"
    PART_FAMILIES = "SAML11"

    MEMORY_MAP = MemoryMap(
        FlashRegion(name='flash',      start=0x00000000, length=0x10000,    sector_size=0x100,
                                                                            page_size=0x100,
                                                                            is_boot_memory=True,
                                                                            algo=FLASH_ALGO),
        FlashRegion(name='data_flash', start=0x00400000, length=0x800,      sector_size=0x100,
                                                                            page_size=0x100,
                                                                            algo=FLASH_ALGO),
        RamRegion(  name='sram',       start=0x20000000, length=0x4000)
        )

    def __init__(self, link):
        super(ATSAML11D16A, self).__init__(link, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("ATSAML11D16A.svd")

    def _bootrom_data(self, data):
        self.write32(DSU_BCC0, data)
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.read8(DSU_STATUSB)
                if not (status & DSU_STATUSB_BCCD0):
                    break
                sleep(0.1)
            else:
                # Timed out
                LOG.error("timeout") 
                return False
        return True

    def _bootrom_cmd(self, cmd):
        self.write32(DSU_BCC0, BOOTROM_CMD_PREFIX | cmd)
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.read8(DSU_STATUSB)
                if not (status & DSU_STATUSB_BCCD0):
                    break
                sleep(0.1)
            else:
                # Timed out
                LOG.error("timeout") 
                return False
        return True

    def _bootrom_status(self, expected = None):
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.read8(DSU_STATUSB)
                if status & DSU_STATUSB_BCCD1:
                    break
                sleep(0.1)
            else:
                raise exceptions.TimeoutError("timeout waiting for status")
        status = self.read32(DSU_BCC1)
        if status & 0xffffff00 != BOOTROM_SIG_PREFIX:
            raise exceptions.InternalError("unexpected prefix 0x%x", status)
        res = status & 0xff
        if (expected != None) and (res != expected):
            return exceptions.InternalError("unexpected response %x %x", res, expected)
        return status

    def _cold_plug(self):
        self.session.probe.assert_reset_with_clk_low(True)
        sleep(0.1)
        self.session.probe.assert_reset_with_clk_low(False)

        with Timeout(2.0) as t_o:
            while t_o.check():
                try:
                    self.dp.connect()
                    self.flush()
                    break
                except exceptions.TransferError:
                    self.flush()
                sleep(0.1)

        # read CRSTEXT
        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    #self.dp.connect()
                    status = self.read8(DSU_STATUSA)
                    self.flush()
                    if (status & DSU_STATUSA_CRSTEXT) != 0:
                        break
                    sleep(0.1)
                except exceptions.TransferError:
                    pass
        self.write8(DSU_STATUSA, DSU_STATUSA_CRSTEXT)
        self.flush()
        with Timeout(5.0) as t_o:
            while t_o.check():
                try:
                    status = self.read8(DSU_STATUSA)
                    self.flush()
                    if (status & DSU_STATUSA_DONE) != 0:
                        self.write8(DSU_STATUSA, DSU_STATUSA_DONE)
                        break
                    sleep(0.1)
                except exceptions.TransferError:
                    pass

        # check STATUSB
        status = self.read8(DSU_STATUSB)
        if (status & DSU_STATUSB_BCCD1) != 0:
            errcode = self.read32(DSU_BCC1)
            LOG.error("unhandled status $%x , error $%x", status, errcode)
            raise NotImplementedError()

    def mass_erase(self):
        # mass erase happens in bootrom interactive mode
        #
        cekey0 = 0xffffffff
        cekey1 = 0xffffffff
        cekey2 = 0xffffffff
        cekey3 = 0xffffffff

        status = self.read8(DSU_STATUSB)
        if status & 3 == 2:
            try:
                cekey0 = self.read32(NVM_BOOTCONFIG + BOCOR_CEKEY2 + 0)
                cekey1 = self.read32(NVM_BOOTCONFIG + BOCOR_CEKEY2 + 4)
                cekey2 = self.read32(NVM_BOOTCONFIG + BOCOR_CEKEY2 + 8)
                cekey3 = self.read32(NVM_BOOTCONFIG + BOCOR_CEKEY2 + 12)
            except exceptions.TransferError:
                LOG.info("access to cekeys not available - using default values")

        self._cold_plug()
 
        status = self._bootrom_cmd(BOOTROM_CMD_INIT)
        if status == False:
            raise exceptions.TimeoutError("bootrom command write timeout")
        self._bootrom_status(BOOTROM_STATUS_SIG_COMM)

        status = self._bootrom_cmd(BOOTROM_CMD_CE2)
        if status == False:
            raise exceptions.TimeoutError("bootrom command write timeout")            
        self._bootrom_status(BOOTROM_STATUS_SIG_CMD_VALID)
        
        status = self._bootrom_data(cekey0)
        if status == False:
            raise exceptions.TimeoutError("bootrom data 0 write timeout")
        status = self._bootrom_data(cekey1)
        if status == False:
            raise exceptions.TimeoutError("bootrom data 1 write timeout")
        status = self._bootrom_data(cekey2)
        if status == False:
            raise exceptions.TimeoutError("bootrom data 2 write timeout")
        status = self._bootrom_data(cekey3)
        if status == False:
            raise exceptions.TimeoutError("bootrom data 3 write timeout")
        self._bootrom_status(BOOTROM_STATUS_SIG_CMD_SUCCESS)

        self.reset(Target.ResetType.HW)

        return True

    def create_init_sequence(self):
        seq = super(ATSAML11D16A, self).create_init_sequence()

        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_core)
            )

        return seq

    def create_core(self):
        core = CortexM_ATSAML11(
            self.session, self.aps[0], self.memory_map, 0)
        core.default_reset_type = self.ResetType.SW
        self.aps[0].core = core
        core.init()
        self.add_core(core)

class CortexM_ATSAML11(CortexM):

    def reset_and_halt(self, reset_type=None):

        XPSR_THUMB = 0x01000000

        reset_vec = self.read_memory(4) & 0xFFFFFFFE

        mem_map = self.get_memory_map()
        region = mem_map.get_region_for_address(reset_vec)
        if (region is None):
            # invalid reset vector
            LOG.warning("invalid reset vector - not attempting halt")
            self.reset(reset_type)
            self.halt()
            return

        borrowed_bp = None
        have_bp_set = self.find_breakpoint(reset_vec)
        if have_bp_set is None:
            if self.set_breakpoint(reset_vec):
                self.bp_manager.flush()
                TRACE.debug("Set breakpoint at 0x%08x", reset_vec)
            else:
                borrowed_bp = self.bp_manager.get_breakpoints()[0]
                self.remove_breakpoint(borrowed_bp)
                self.bp_manager.flush()
                if self.set_breakpoint(reset_vec):
                    self.bp_manager.flush()
                else:
                    LOG.info("Failed to set breakpoint at 0x%08x", reset_vec)

        self.reset(reset_type)

        if reset_type is not Target.ResetType.SW_EMULATED:
            with Timeout(self.session.options.get('reset.halt_timeout')) as t_o:
                while t_o.check():
                    if self.get_state() not in (Target.State.RESET, Target.State.RUNNING):
                        break
                    sleep(0.01)
                else:
                    LOG.warning("Timed out waiting for core to halt after reset (state is %s)", self.get_state().name)

        if have_bp_set is None:
            self.remove_breakpoint(reset_vec)
            self.bp_manager.flush()
            if borrowed_bp is not None:
                self.set_breakpoint(borrowed_hp)
            TRACE.debug("removed temporary breakpoint at 0x%08x", reset_vec)

        # Make sure the thumb bit is set in XPSR in case the reset handler
        # points to an invalid address. Only do this if the core is actually halted, otherwise we
        # can't access XPSR.
        if self.get_state() == Target.State.HALTED:
            xpsr = self.read_core_register('xpsr')
            if xpsr & XPSR_THUMB == 0:
                self.write_core_register('xpsr', xpsr | XPSR_THUMB)
        else:
            LOG.warning("not halted")

