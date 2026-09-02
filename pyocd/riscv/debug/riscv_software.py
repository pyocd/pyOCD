# pyOCD debugger
# Copyright (c) 2025 Ryan QIAN
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
from typing import (Dict, Optional, TYPE_CHECKING)

from ...debug.breakpoints.provider import (Breakpoint, BreakpointProvider)
from ...core import exceptions
from ...core.target import Target
from ..instructions import RiscvInstr

if TYPE_CHECKING:
    from ...core.core_target import CoreTarget

LOG = logging.getLogger(__name__)


class RiscvSoftwareBreakpoint(Breakpoint):
    """Breakpoint with RISC-V instruction size tracking."""

    def __init__(self, provider: BreakpointProvider) -> None:
        super().__init__(provider)
        self.type = Target.BreakpointType.SW
        self.instr_size: int = 16  # 16 or 32 bits


class RiscvSoftwareBreakpointProvider(BreakpointProvider):
    """Software breakpoint provider for RISC-V targets.

    Uses EBREAK (32-bit, 0x00100073) or C.EBREAK (16-bit, 0x9002)
    depending on the original instruction size detected at the target
    address. This is determined by reading bits[1:0] of the instruction
    halfword: != 0b11 means 16-bit compressed, == 0b11 means 32-bit regular.

    The filter_memory() method hides EBREAK instructions from GDB memory
    reads, returning the original instruction bytes instead. This ensures
    the debugger view remains consistent with the source code.
    """

    def __init__(self, core: "CoreTarget") -> None:
        super().__init__()
        self._core = core
        self._breakpoints: Dict[int, RiscvSoftwareBreakpoint] = {}

    def init(self) -> None:
        pass

    @property
    def bp_type(self) -> Target.BreakpointType:
        return Target.BreakpointType.SW

    @property
    def do_filter_memory(self) -> bool:
        return True

    @property
    def available_breakpoints(self) -> int:
        return -1

    def can_support_address(self, addr: int) -> bool:
        region = self._core.memory_map.get_region_for_address(addr)
        return (region is not None) and region.is_writable

    def find_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        return self._breakpoints.get(addr, None)

    def set_breakpoint(self, addr: int) -> Optional[Breakpoint]:
        assert self.can_support_address(addr)
        assert (addr & 1) == 0

        try:
            # Read the low 16 bits to detect instruction size.
            low16 = self._core.read16(addr)

            bp = RiscvSoftwareBreakpoint(self)
            bp.enabled = True
            bp.addr = addr

            if (low16 & 0x3) != 0x3:
                # Compressed 16-bit instruction: bits[1:0] != 0b11
                bp.instr_size = 16
                bp.original_instr = low16
                self._core.write16(addr, RiscvInstr.c_ebreak())
            else:
                # Regular 32-bit instruction: bits[1:0] == 0b11
                bp.instr_size = 32
                bp.original_instr = self._core.read32(addr)
                self._core.write32(addr, RiscvInstr.ebreak())

            self._core.invalidate_instruction_cache(addr)
            self._breakpoints[addr] = bp
            return bp
        except exceptions.TransferError:
            LOG.debug("Failed to set RISC-V sw bp at 0x%x" % addr)
            return None

    def remove_breakpoint(self, bp: Breakpoint) -> None:
        assert bp is not None and isinstance(bp, Breakpoint)

        try:
            rbp = bp
            if rbp.instr_size == 16:
                self._core.write16(bp.addr, bp.original_instr)
            else:
                self._core.write32(bp.addr, bp.original_instr)
            self._core.invalidate_instruction_cache(bp.addr)
            del self._breakpoints[bp.addr]
        except exceptions.TransferError:
            LOG.debug("Failed to remove RISC-V sw bp at 0x%x" % bp.addr)

    def filter_memory(self, addr: int, size: int, data: int) -> int:
        """Replace EBREAK/C.EBREAK in memory reads with original instructions.

        Uses byte-level overlap detection: for each breakpoint, compute the
        overlapping byte range between the read region [addr, addr+size//8)
        and the breakpoint region [bp.addr, bp.addr+bp.instr_size//8), then
        replace the overlapping bytes in data with the original instruction bytes.
        """
        read_size_bytes = size // 8
        read_bytes = list(data.to_bytes(read_size_bytes, 'little'))

        for bp in self._breakpoints.values():
            bp_size_bytes = bp.instr_size // 8
            bp_bytes = bp.original_instr.to_bytes(bp_size_bytes, 'little')

            # Compute byte-level overlap between read and breakpoint regions.
            overlap_start = max(addr, bp.addr)
            overlap_end = min(addr + read_size_bytes, bp.addr + bp_size_bytes)

            for byte_addr in range(overlap_start, overlap_end):
                read_offset = byte_addr - addr
                bp_offset = byte_addr - bp.addr
                read_bytes[read_offset] = bp_bytes[bp_offset]

        return int.from_bytes(read_bytes, 'little')

    def flush(self) -> None:
        pass
