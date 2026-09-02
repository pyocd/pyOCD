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

"""RISC-V instruction encodings.

Centralized definitions for RISC-V instruction encodings used across
the debug stack: program buffer execution, flash algorithm loading,
software breakpoint insertion, and cache coherence management.

All instructions are defined as static methods returning the encoded
instruction word (32-bit int for base ISA, 16-bit int for compressed).

Source: RISC-V Unprivileged Specification v20191213
        RISC-V Privileged Specification v1.12
"""


class RiscvInstr:
    """RISC-V instruction encodings.

    All instructions are provided as static methods.  Fixed-encoding
    instructions take no arguments; parameterized instructions take
    register numbers and/or immediates and return the encoded word.
    """

    # -- 32-bit instructions (RV32I) --

    @staticmethod
    def ebreak() -> int:
        """EBREAK: ebreak — cause breakpoint exception into debug mode.

        Encoding (I-type SYSTEM):
        0000000 00001 00000 000 00000 1110011
        """
        return 0x00100073

    @staticmethod
    def nop() -> int:
        """NOP: addi x0, x0, 0 — no operation.

        Encoding (I-type):
        000000000000 00000 000 00000 0010011
        """
        return 0x00000013

    @staticmethod
    def fence_i() -> int:
        """FENCE.I: fence.i — synchronize instruction and data streams.

        Encoding (SYSTEM):
        0000 0000 0000 00000 001 00000 0001111

        NOTE: FENCE.I has no compressed (C) encoding in the RISC-V spec.
        Use this 32-bit form in all contexts including program buffer.
        """
        return 0x0000100F

    # -- 16-bit compressed instructions (RV32C / Zca) --

    @staticmethod
    def c_ebreak() -> int:
        """C.EBREAK: c.ebreak — compressed ebreak.

        Encoding (CR-type, quadrant 2):
        funct4=1001[15:12] | rs1=0[11:7] | rs2=0[6:2] | op=10[1:0]
        """
        return 0x9002

    @staticmethod
    def c_nop() -> int:
        """C.NOP: c.nop — compressed no-operation.

        Encoding (CI-type, quadrant 1):
        funct3=000[15:13] | imm[5]=0[12] | rd=0[11:7] | imm[4:0]=0[6:2] | op=01[1:0]
        """
        return 0x0001

    # -- Parameterized 32-bit instructions --

    @staticmethod
    def lui(rd: int, imm: int) -> int:
        """Build LUI instruction: LUI rd, imm.

        U-type encoding:
        imm[31:12] | rd[11:7] | opcode=0110111[6:0]

        The 20-bit immediate becomes bits [31:12] of the destination
        register. Combined with ADDI for full 32-bit address construction.

        Args:
            rd: Destination register number (0-31)
            imm: 20-bit immediate value (placed at bits [31:12])
        """
        return ((imm & 0xFFFFF) << 12) | (rd << 7) | 0x37

    @staticmethod
    def csrr(rd: int, csr: int) -> int:
        """Build CSRR instruction: CSRR rd, csr.

        Encoding (I-type CSRRS with rs1=x0):
        csr[31:20] | rs1=0[19:15] | funct3=010[14:12] | rd[11:7] | opcode=0x73[6:0]
        """
        return (csr << 20) | (0b010 << 12) | (rd << 7) | 0x73

    @staticmethod
    def csrw(csr: int, rs1: int) -> int:
        """Build CSRW instruction: CSRW csr, rs1.

        Encoding (I-type CSRRW with rd=x0):
        csr[31:20] | rs1[19:15] | funct3=001[14:12] | rd=0[11:7] | opcode=0x73[6:0]
        """
        return (csr << 20) | (rs1 << 15) | (0b001 << 12) | 0x73

    @staticmethod
    def lw(rd: int, rs1: int, imm: int) -> int:
        """Build LW instruction: LW rd, imm(rs1)."""
        return ((imm & 0xFFF) << 20) | (rs1 << 15) | (0b010 << 12) | (rd << 7) | 0x03

    @staticmethod
    def sw(rs2: int, rs1: int, imm: int) -> int:
        """Build SW instruction: SW rs2, imm(rs1)."""
        return (((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (0b010 << 12) | ((imm & 0x1F) << 7) | 0x23

    @staticmethod
    def lhu(rd: int, rs1: int, imm: int) -> int:
        """Build LHU instruction: LHU rd, imm(rs1). Load 16-bit, zero-extend."""
        return ((imm & 0xFFF) << 20) | (rs1 << 15) | (0b101 << 12) | (rd << 7) | 0x03

    @staticmethod
    def lbu(rd: int, rs1: int, imm: int) -> int:
        """Build LBU instruction: LBU rd, imm(rs1). Load 8-bit, zero-extend."""
        return ((imm & 0xFFF) << 20) | (rs1 << 15) | (0b100 << 12) | (rd << 7) | 0x03

    @staticmethod
    def sh(rs2: int, rs1: int, imm: int) -> int:
        """Build SH instruction: SH rs2, imm(rs1). Store 16-bit."""
        return (((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (0b001 << 12) | ((imm & 0x1F) << 7) | 0x23

    @staticmethod
    def sb(rs2: int, rs1: int, imm: int) -> int:
        """Build SB instruction: SB rs2, imm(rs1). Store 8-bit."""
        return (((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (0b000 << 12) | ((imm & 0x1F) << 7) | 0x23

    @staticmethod
    def addi(rd: int, rs1: int, imm: int) -> int:
        """Build ADDI instruction: ADDI rd, rs1, imm.

        I-type encoding:
        imm[31:20] | rs1[19:15] | funct3=000[14:12] | rd[11:7] | opcode=0010011[6:0]

        Args:
            rd: Destination register number (0-31)
            rs1: Source register number (0-31)
            imm: 12-bit signed immediate (-2048 to 2047)
        """
        return ((imm & 0xFFF) << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0x13

