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

"""HPM62x0 (Y=0 base) part target definition for pyOCD.

HPM6200 family Y=0 base target (HPM6220/6240/6260/6280).
Dual-core RISC-V MCU. Each core has its own ILM/DLM.
No internal flash; board targets add external XPI flash.

Memory map (no flash):
    ILM0:  0x00000000, 128KB (rwx) - Core0 instruction local memory
    ILM1:  0x00040000, 128KB (rwx) - Core1 instruction local memory
    DLM0:  0x00200000, 128KB (rw)  - Core0 data local memory
    DLM1:  0x00240000, 128KB (rw)  - Core1 data local memory
    AXI_SRAM: 0x01200000, 240KB (rwx)
    SHARE_RAM: 0x0123C000, 16KB (rw) - Inter-core shared memory
    AHB_SRAM: 0xF0200000, 32KB (rw)

Dual-core notes:
    Core1 requires release via write to 0xF4002C00 = 0x1000 before debug access.
    RISCVTarget auto-discovers harts via DM capabilities.
    Multi-hart debug support is under development.
"""

from ....core.memory_map import MemoryMap, RamRegion
from .base import HPMicroTarget

import logging
LOG = logging.getLogger(__name__)

# -- Core0 memory layout --
_ILM0_BASE = 0x00000000       # Core0 Instruction Local Memory
_ILM0_SIZE = 0x20000          # 128 KB
_DLM0_BASE = 0x00200000       # Core0 Data Local Memory
_DLM0_SIZE = 0x20000          # 128 KB

# -- Core1 memory layout --
_ILM1_BASE = 0x00040000       # Core1 Instruction Local Memory
_ILM1_SIZE = 0x20000          # 128 KB
_DLM1_BASE = 0x00240000       # Core1 Data Local Memory
_DLM1_SIZE = 0x20000          # 128 KB

# -- System SRAM --
_AXI_SRAM_BASE = 0x01200000
_AXI_SRAM_SIZE = 0x3C000      # 240 KB
_SHARE_RAM_BASE = 0x0123C000
_SHARE_RAM_SIZE = 0x4000      # 16 KB
_AHB_SRAM_BASE = 0xF0200000
_AHB_SRAM_SIZE = 0x8000       # 32 KB

# -- XPI configuration (XPI1 on HPM6200) --
# XPI1 base: 0xF3040000 (defined in class XPI_MAP)

# -- Core1 release register --
_CORE1_RELEASE_ADDR = 0xF4002C00
_CORE1_RELEASE_VALUE = 0x1000

# -- Hart-local ILM/DLM bases (SBA addressing) --
# HPM6200 SBA uses hart-local addressing: when dmcontrol.hartsel selects a hart,
# SBA addresses 0x0-0x1FFFF map to that hart's ILM.
_HART_ILM_BASES = {0: 0x00000000, 1: 0x00020000}
_HART_DLM_BASES = {0: 0x00080000, 1: 0x000A0000}
_CORE_REGION_NAMES = {"ILM0", "ILM1", "DLM0", "DLM1"}


class HPM62x0(HPMicroTarget):
    """HPM62x0 (Y=0 base) RISC-V dual-core MCU.

    Family base target with RAM only. No flash region defined.
    HPM62x4 (Y=4) variant extends this with 4MB internal flash.
    Board subclasses call add_xpi_flash() with board-specific flash params.
    Supports automatic hart discovery via DebugModule capabilities.
    """

    CSR_CONFIGS = ["hpmicro/hpm_d45_csr.yaml"]

    PART_NUMBER = "HPM62x0"
    PART_FAMILIES = ["HPM6200"]

    XPI_MAP = {
        0x80000000: 0xF3040000,
    }
    _FLASH_RAM_START = _ILM0_BASE
    _FLASH_RAM_SIZE = _ILM0_SIZE

    MEMORY_MAP = MemoryMap(
        RamRegion(name="ILM0", start=_ILM0_BASE, length=_ILM0_SIZE,
                  access='rwx', is_boot_memory=True),
        RamRegion(name="ILM1", start=_ILM1_BASE, length=_ILM1_SIZE,
                  access='rwx'),
        RamRegion(name="DLM0", start=_DLM0_BASE, length=_DLM0_SIZE,
                  access='rw'),
        RamRegion(name="DLM1", start=_DLM1_BASE, length=_DLM1_SIZE,
                  access='rw'),
        RamRegion(name="AXI_SRAM", start=_AXI_SRAM_BASE, length=_AXI_SRAM_SIZE,
                  access='rwx'),
        RamRegion(name="SHARE_RAM", start=_SHARE_RAM_BASE, length=_SHARE_RAM_SIZE,
                  access='rw'),
        RamRegion(name="AHB_SRAM", start=_AHB_SRAM_BASE, length=_AHB_SRAM_SIZE,
                  access='rw'),
    )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self.register_pre_hart_discover_hook(self._release_core1)

    def _release_core1(self):
        """Release Core1 from reset before hart discovery.

        HPM6280 keeps Core1 in reset after power-on. The hart shows
        allunavail=True in dmstatus until released. Must release before
        _discover_harts() runs, otherwise hart 1 is marked unavailable.
        """
        try:
            self.dm.write_memory(_CORE1_RELEASE_ADDR, _CORE1_RELEASE_VALUE)
            LOG.info("Core1 released via write 0x%x to 0x%08x",
                     _CORE1_RELEASE_VALUE, _CORE1_RELEASE_ADDR)
        except Exception as e:
            LOG.warning("Core1 release failed (may already be released): %s", e)

    def _register_reset_hooks(self) -> None:
        """Register base ISP re-detection plus HPM6280 Core1 re-release.

        Base hook handles ISP mode re-detection and XPI AHB mapping
        restore after reset. Core1 re-release is HPM6280-specific: after
        reset, Core1 goes back into SoC reset and must be released again
        before haltreq takes effect on hart 1.

        Both hooks are registered on ALL cores because GDB may call
        reset_and_halt() on any core, and only that core's post_reset_hooks
        are invoked.
        """
        super()._register_reset_hooks()

        import logging
        LOG = logging.getLogger(__name__)

        def rerelease_core1():
            try:
                self.dm.write_memory(_CORE1_RELEASE_ADDR, _CORE1_RELEASE_VALUE)
                LOG.info("Core1 re-released after reset")
            except Exception as e:
                LOG.warning("Core1 re-release failed: %s", e)

        # Register on ALL cores since any core's reset may be invoked by GDB
        for core_num, core in self.cores.items():
            core.register_post_reset_hook(rerelease_core1)

    def get_hart_memory_map(self, hart_index: int) -> MemoryMap:
        """Return hart-local memory map for SBA addressing.

        HPM6200 SBA uses hart-local addressing: when dmcontrol.hartsel selects
        a hart, SBA addresses 0x0-0x1FFFF map to that hart's ILM, and
        0x80000-0x9FFFF map to that hart's DLM.
        """
        regions = [
            RamRegion(name="ILM", start=_HART_ILM_BASES[hart_index], length=_ILM0_SIZE,
                      access='rwx', is_boot_memory=True),
            RamRegion(name="DLM", start=_HART_DLM_BASES[hart_index], length=_DLM0_SIZE,
                      access='rw'),
        ]
        for r in self.memory_map:
            if r.name not in _CORE_REGION_NAMES:
                regions.append(r)
        return MemoryMap(*regions)
