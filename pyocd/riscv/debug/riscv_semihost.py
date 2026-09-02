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

"""RISC-V semihosting agent.

Extends the ARM SemihostAgent with RISC-V-specific trap detection.
All request handlers (SYS_OPEN, SYS_WRITE, SYS_READ, etc.) are
inherited from the ARM implementation unchanged.

RISC-V semihosting uses a 3-instruction sequence as the trap mechanism:
    slli x0, x0, 0x1f    # entry marker (HINT, encoded as 0x01f01013)
    ebreak                # trap to debugger (encoded as 0x00100073)
    srai x0, x0, 7       # exit marker  (HINT, encoded as 0x40705013)

When the target halts at an ebreak, the agent checks for the surrounding
entry/exit markers to distinguish semihosting traps from user breakpoints.

Register convention:
    a0 (x10) — operation number on entry, return value on exit
    a1 (x11) — pointer to parameter block

Reference: RISC-V Privileged Specification, Debug Mode section
"""

import logging

from pyocd.core import exceptions
from pyocd.core.target import Target
from pyocd.debug.semihost import SemihostAgent

LOG = logging.getLogger(__name__)

# RISC-V base ISA instruction size (bytes). All semihosting instructions
# must be 32-bit; compressed 16-bit encodings are not permitted.
RISCV_INSTR_SIZE = 4

# Number of instructions in the semihosting trap sequence:
#   slli x0, x0, 0x1f  ; ebreak  ; srai x0, x0, 7
SEMIHOST_SEQ_LENGTH = 3

# RISC-V semihosting instruction sequence encodings.
RISCV_SEMIHOST_ENTRY = 0x01F01013   # slli x0, x0, 0x1f
RISCV_SEMIHOST_EBREAK = 0x00100073  # ebreak
RISCV_SEMIHOST_EXIT = 0x40705013    # srai x0, x0, 7


def _read_le32(data, offset):
    """Read a little-endian 32-bit value from a byte list at the given offset."""
    return (data[offset]
            | (data[offset + 1] << 8)
            | (data[offset + 2] << 16)
            | (data[offset + 3] << 24))


class RiscvSemihostAgent(SemihostAgent):
    """RISC-V semihosting request handler.

    Inherits all ARM semihosting request handlers. Only overrides trap
    detection to use the RISC-V 3-instruction ebreak sequence.

    Args:
        context: Debug context for memory/register access.
        core: RISCVCore instance for halt reason and breakpoint queries.
        io_handler: Optional I/O handler for file operations.
        console: Optional console handler for stdio.
    """

    def __init__(self, context, core, io_handler=None, console=None):
        super().__init__(context, io_handler=io_handler, console=console)
        self.core = core

    def check_and_handle_semihost_request(self) -> bool:
        """Detect and handle a RISC-V semihosting request.

        Must be called after the target halts. Checks whether the halt
        was caused by the semihosting ebreak sequence, and if so,
        dispatches the request and advances PC.

        Returns:
            True if a semihosting request was handled, False otherwise.
        """
        # Halt reason must be BREAKPOINT.
        halt_reason = self.core.get_halt_reason()
        if halt_reason != Target.HaltReason.BREAKPOINT:
            LOG.debug("Semihost: not a breakpoint halt (reason=%s)", halt_reason)
            return False

        pc = self.core.read_core_register('pc')
        assert isinstance(pc, int)
        LOG.debug("Semihost: breakpoint halt at pc=0x%08x", pc)

        # Must not be a user-installed breakpoint.
        bp = self.core.find_breakpoint(pc)
        if bp:
            LOG.debug("Semihost: user breakpoint at pc=0x%08x, skipping", pc)
            return False

        # Read the 3-instruction sequence centered on the ebreak.
        # Use byte-level reads to handle potentially misaligned 32-bit
        # instructions when the C (compressed) extension is enabled.
        seq_bytes = SEMIHOST_SEQ_LENGTH * RISCV_INSTR_SIZE
        try:
            raw = self.context.read_memory_block8(
                pc - RISCV_INSTR_SIZE, seq_bytes)
            if len(raw) < seq_bytes:
                LOG.debug("Semihost: short read at pc=0x%08x (%d < %d)",
                          pc, len(raw), seq_bytes)
                return False
            entry_insn = _read_le32(raw, 0)
            ebreak_insn = _read_le32(raw, RISCV_INSTR_SIZE)
            exit_insn = _read_le32(raw, 2 * RISCV_INSTR_SIZE)
        except exceptions.TransferError:
            LOG.debug("Semihost: transfer error reading instruction at pc=0x%08x", pc)
            return False

        LOG.debug("Semihost: instructions at pc-4=0x%08x pc=0x%08x pc+4=0x%08x",
                  entry_insn, ebreak_insn, exit_insn)

        # Verify the full semihosting sequence.
        if (entry_insn != RISCV_SEMIHOST_ENTRY
                or ebreak_insn != RISCV_SEMIHOST_EBREAK
                or exit_insn != RISCV_SEMIHOST_EXIT):
            LOG.debug("Semihost: instruction sequence mismatch")
            return False

        LOG.info("Semihost: detected semihost trap at pc=0x%08x", pc)

        # Advance PC past the 3-instruction sequence.
        # From ebreak, skip the remaining (exit marker) instruction.
        pc_advance = (SEMIHOST_SEQ_LENGTH - 1) * RISCV_INSTR_SIZE
        self.core.write_core_register('pc', pc + pc_advance)

        # Read operation and arguments from RISC-V ABI registers.
        op = self.core.read_core_register('a0')
        args = self.core.read_core_register('a1')
        assert isinstance(op, int)
        assert isinstance(args, int)

        LOG.info("Semihost: op=0x%x (%d) args=0x%08x", op, op, args)

        # Dispatch to inherited request handlers.
        handler = self._REQUEST_MAP.get(op, None)
        if handler:
            try:
                result = handler(self, args)
                LOG.info("Semihost: op=%d result=%d", op, result)
            except NotImplementedError:
                LOG.warning("Semihost: unimplemented request pc=%x a0=%x a1=%x",
                            pc, op, args)
                result = -1
            except (exceptions.Error, OSError) as e:
                LOG.error("Error while handling semihost request: %s", e,
                          exc_info=self.context.session.log_tracebacks)
                result = -1
        else:
            LOG.warning("Semihost: unknown op=%d at pc=0x%08x", op, pc)
            result = -1

        # Write return value to a0.
        self.core.write_core_register('a0', result)

        return True
