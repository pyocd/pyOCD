# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
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

"""HPM67x0 (Y=0 base) part target definition for pyOCD.

HPM6700 family Y=0 base target (HPM6430/6450/6730/6750/64A0/64G0).
Dual-core RISC-V MCU with core-local ILM addressing.
No internal flash.

Memory map (no flash, core-local addressing):
    ILM:         0x00000000, 256KB (rwx, is_boot_memory) - Core-local
    DLM:         0x00080000, 256KB (rw)
    AXI_SRAM:    0x01080000, 768KB (rwx)
    SHARE_RAM:   0x0117C000, 16KB  (rw)
    AHB_SRAM:    0xF0300000, 32KB  (rw)
    APB_SRAM:    0xF40F0000, 8KB   (rw)

Dual-core notes:
    HPM6750 uses core-local ILM addressing: both cores see ILM at 0x00000000.
    The debug module selects the target hart for memory accesses.
    Core1 release is complex: requires reading chip revision, setting start
    point and boot flag before writing the release register.

Core1 release (source: HPMicro SDK soc/hpm6750-dual-core.cfg):
    Start-point vector at 0xF4002C08 depends on chip revision read from
    0x2001FF00 (0x20016284 when rev != 0x56010100, else 0x2001660c).
    Boot flag 0xC1BEF1A9 at 0xF4002C0C and release value 0x1000 at
    0xF4002C00 complete the handoff.
"""

from ....core.memory_map import MemoryMap, RamRegion
from .base import HPMicroTarget

import logging
LOG = logging.getLogger(__name__)

# -- Memory layout (core-local ILM addressing) --
_ILM_BASE = 0x00000000       # Instruction Local Memory (core-local)
_ILM_SIZE = 0x40000          # 256 KB
_DLM_BASE = 0x00080000       # Data Local Memory
_DLM_SIZE = 0x40000          # 256 KB

# Core0 ILM system-bus alias. HPM6750 dual-core core-local ILM: both cores
# see ILM at 0x0 (hart fetch), but SBA (system bus) has no 0x0 alias — only
# the per-core system address 0x01000000 (core0). Flash algo must load via
# this address so SBA can reach it. Verified bidirectional sync with 0x0.
_CORE0_ILM_SYSTEM_ALIAS = 0x01000000

# -- System SRAM --
_AXI_SRAM_BASE = 0x01080000
_AXI_SRAM_SIZE = 0xC0000      # 768 KB
_SHARE_RAM_BASE = 0x0117C000
_SHARE_RAM_SIZE = 0x4000      # 16 KB
_AHB_SRAM_BASE = 0xF0300000
_AHB_SRAM_SIZE = 0x8000       # 32 KB
_APB_SRAM_BASE = 0xF40F0000
_APB_SRAM_SIZE = 0x2000       # 8 KB

# -- XPI controller --
# XPI1 base: 0xF3040000 (defined in class XPI_MAP)

# -- Core1 release registers --
_CORE1_RELEASE_ADDR = 0xF4002C00
_CORE1_RELEASE_VALUE = 0x1000
_CORE1_STARTPOINT_ADDR = 0xF4002C08
_CORE1_BOOTFLAG_ADDR = 0xF4002C0C
_CORE1_BOOTFLAG_VALUE = 0xC1BEF1A9
_CHIP_REV_ADDR = 0x2001FF00


class HPM67x0(HPMicroTarget):
    """HPM67x0 (Y=0 base) RISC-V dual-core MCU.

    Family base target with RAM only. No flash region defined.
    HPM67x4 (Y=4) variant extends this with 4MB internal flash.
    Board subclasses call add_xpi_flash() with board-specific flash params.

    Core-local ILM: both cores see instruction memory at 0x00000000.
    Core1 release requires chip revision check and conditional start point.
    """

    CSR_CONFIGS = ["hpmicro/hpm_d45_csr.yaml"]

    PART_NUMBER = "HPM67x0"
    PART_FAMILIES = ["HPM6700"]

    XPI_MAP = {
        0x80000000: 0xF3040000,
    }
    # Flash algo loads to core0 ILM system alias (SBA-reachable, same physical
    # ILM as hart-local 0x0). See _CORE0_ILM_SYSTEM_ALIAS for rationale.
    # NOTE: algo is linked for 0x01000000 (not position-independent); loading
    # to hart-local 0x0 corrupts absolute address refs.
    # Loading to AXI_SRAM (0x01080000) also breaks absolute refs even with
    # GP fix — algo must be recompiled for the target address.
    _FLASH_RAM_START = _CORE0_ILM_SYSTEM_ALIAS
    _FLASH_RAM_SIZE = _ILM_SIZE
    # Page buffers in AXI_SRAM (XPI DMA can't read ILM_SLV buf due to CCTL
    # L1D_WB_ALL not working for LM physical cache lines).
    _PAGE_BUF_RAM_START = _AXI_SRAM_BASE

    MEMORY_MAP = MemoryMap(
        RamRegion(name="ILM", start=_ILM_BASE, length=_ILM_SIZE,
                  access='rwx', is_boot_memory=True),
        RamRegion(name="DLM", start=_DLM_BASE, length=_DLM_SIZE,
                  access='rw'),
        RamRegion(name="AXI_SRAM", start=_AXI_SRAM_BASE, length=_AXI_SRAM_SIZE,
                  access='rwx'),
        RamRegion(name="SHARE_RAM", start=_SHARE_RAM_BASE, length=_SHARE_RAM_SIZE,
                  access='rw'),
        RamRegion(name="AHB_SRAM", start=_AHB_SRAM_BASE, length=_AHB_SRAM_SIZE,
                  access='rw'),
        RamRegion(name="APB_SRAM", start=_APB_SRAM_BASE, length=_APB_SRAM_SIZE,
                  access='rw'),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self.register_pre_hart_discover_hook(self._release_core1)

    def _release_core1(self):
        """Release Core1 with chip revision-dependent start point.

        HPM6750 requires reading the chip revision to determine the
        correct start point address for Core1. After setting the start
        point and boot flag, writing the release register starts Core1.
        """
        try:
            chip_rev = self.dm.read_memory(_CHIP_REV_ADDR)
            LOG.info("Chip revision: 0x%08x", chip_rev)

            if chip_rev != 0x56010100:
                start_point = 0x20016284
            else:
                start_point = 0x2001660c

            self.dm.write_memory(_CORE1_STARTPOINT_ADDR, start_point)
            self.dm.write_memory(_CORE1_BOOTFLAG_ADDR, _CORE1_BOOTFLAG_VALUE)
            self.dm.write_memory(_CORE1_RELEASE_ADDR, _CORE1_RELEASE_VALUE)
            LOG.info("Core1 released: start=0x%08x, bootflag=0x%08x",
                     start_point, _CORE1_BOOTFLAG_VALUE)
        except Exception as e:
            LOG.warning("Core1 release failed: %s", e)

    def _register_reset_hooks(self) -> None:
        """Register base ISP re-detection plus HPM6750 Core1 re-release."""
        super()._register_reset_hooks()
        import logging
        LOG = logging.getLogger(__name__)

        def rerelease_core1():
            try:
                chip_rev = self.dm.read_memory(_CHIP_REV_ADDR)
                start_point = 0x20016284 if chip_rev != 0x56010100 else 0x2001660c
                self.dm.write_memory(_CORE1_STARTPOINT_ADDR, start_point)
                self.dm.write_memory(_CORE1_BOOTFLAG_ADDR, _CORE1_BOOTFLAG_VALUE)
                self.dm.write_memory(_CORE1_RELEASE_ADDR, _CORE1_RELEASE_VALUE)
                LOG.info("Core1 re-released after reset")
            except Exception as e:
                LOG.warning("Core1 re-release failed: %s", e)

        for core_num, core in self.cores.items():
            core.register_post_reset_hook(rerelease_core1)
