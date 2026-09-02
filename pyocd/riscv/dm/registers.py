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

"""
RISC-V Debug Module register definitions.

All register addresses and bit field positions verified against:
- RISC-V Debug Specification v0.13.2, Tables 3.5-3.7
"""


class DMReg:
    """Debug Module register addresses (DMI address space).

    RISC-V Debug Spec v0.13.2, Table 3.5.
    """
    # Abstract Data registers
    DATA0 = 0x04
    DATA1 = 0x05
    DATA2 = 0x06
    DATA3 = 0x07
    DATA4 = 0x08
    DATA5 = 0x09
    DATA6 = 0x0A
    DATA7 = 0x0B
    DATA8 = 0x0C
    DATA9 = 0x0D
    DATA10 = 0x0E
    DATA11 = 0x0F

    # Debug Module Control
    DMCONTROL = 0x10
    DMSTATUS = 0x11
    HARTINFO = 0x12
    HA2 = 0x13
    HAWINDOWSEL = 0x14
    HAWINDOW = 0x15

    # Abstract Command
    ABSTRACTCS = 0x16
    COMMAND = 0x17
    ABSTRACTAUTO = 0x18

    # Configuration
    CONFSTRPTR0 = 0x19
    CONFSTRPTR1 = 0x1A
    CONFSTRPTR2 = 0x1B
    CONFSTRPTR3 = 0x1C
    NEXTDM = 0x1D

    # Program Buffer
    PROGBUF0 = 0x20
    PROGBUF1 = 0x21
    PROGBUF2 = 0x22
    PROGBUF3 = 0x23
    PROGBUF4 = 0x24
    PROGBUF5 = 0x25
    PROGBUF6 = 0x26
    PROGBUF7 = 0x27
    PROGBUF8 = 0x28
    PROGBUF9 = 0x29
    PROGBUF10 = 0x2A
    PROGBUF11 = 0x2B
    PROGBUF12 = 0x2C
    PROGBUF13 = 0x2D
    PROGBUF14 = 0x2E
    PROGBUF15 = 0x2F

    # Halt Summary
    HALTSUM0 = 0x40
    HALTSUM1 = 0x41
    HALTSUM2 = 0x42
    HALTSUM3 = 0x43

    # System Bus Access
    SBCS = 0x38
    SBADDRESS0 = 0x39
    SBADDRESS1 = 0x3A
    SBADDRESS2 = 0x3B
    SBDATA0 = 0x3C
    SBDATA1 = 0x3D
    SBDATA2 = 0x3E
    SBDATA3 = 0x3F


class AbstractCS:
    """ABSTRACTCS register bit fields.

    Source: RISC-V Debug Spec v0.13.2, Section 3.5.2, Table 3.8
    """
    # Bits 28:24 - Number of 32-bit words in program buffer
    PROGBUFSIZE_SHIFT = 24
    PROGBUFSIZE_MASK = 0x1F  # 5 bits

    # Bit 13 - relaxedpriv (optional)
    RELAXEDPRIV_BIT = 13

    # Bit 12 - Command is being executed
    BUSY_BIT = 12
    BUSY_MASK = 1 << 12

    # Bits 10:8 - Error that occurred during command
    CMDERR_SHIFT = 8
    CMDERR_MASK = 0x7  # 3 bits
    CMDERR_CLEAR = 0x7 << 8  # Write 0b111 to clear

    # Bits 3:0 - Number of data registers
    DATACOUNT_SHIFT = 0
    DATACOUNT_MASK = 0xF  # 4 bits

    @staticmethod
    def parse_progbufsize(abstractcs: int) -> int:
        return (abstractcs >> AbstractCS.PROGBUFSIZE_SHIFT) & AbstractCS.PROGBUFSIZE_MASK

    @staticmethod
    def parse_busy(abstractcs: int) -> bool:
        return bool(abstractcs & AbstractCS.BUSY_MASK)

    @staticmethod
    def parse_cmderr(abstractcs: int) -> int:
        return (abstractcs >> AbstractCS.CMDERR_SHIFT) & AbstractCS.CMDERR_MASK

    @staticmethod
    def parse_datacount(abstractcs: int) -> int:
        return (abstractcs >> AbstractCS.DATACOUNT_SHIFT) & AbstractCS.DATACOUNT_MASK

    @staticmethod
    def build_clear_cmderr() -> int:
        return AbstractCS.CMDERR_CLEAR


class AbstractCmdErr:
    """Abstract command error codes (cmderr field).

    Source: RISC-V Debug Spec v0.13.2, Table 3.9
    """
    NONE = 0
    BUSY = 1         # Abstract command executed while previous was still running
    NOT_SUPPORTED = 2  # Command not supported
    EXCEPTION = 3    # Exception while executing command
    HALT_RESUME = 4  # Hart not in required state
    BUS_ERROR = 5    # Bus error during execution
    OTHER = 7        # Unknown error


class Command:
    """COMMAND register bit fields for Access Register command.

    Source: RISC-V Debug Spec v0.13.2, Section 3.5.2
    """
    # Bits 31:24 - Command type
    CMDTYPE_SHIFT = 24
    CMDTYPE_MASK = 0xFF

    # Access Register command type
    CMDTYPE_ACCESS_REG = 0
    CMDTYPE_QUICK_ACCESS = 1
    CMDTYPE_ACCESS_MEM = 2

    # Bits 22:20 - Access size (for Access Register)
    AARSIZE_SHIFT = 20
    AARSIZE_MASK = 0x7
    AARSIZE_8BIT = 0
    AARSIZE_16BIT = 1
    AARSIZE_32BIT = 2
    AARSIZE_64BIT = 3
    AARSIZE_128BIT = 4

    # Bit 19 - Auto-increment after access (Access Memory only)
    AARPOSTINCREMENT_BIT = 19

    # Bit 18 - Execute program buffer after transfer
    POSTEXEC_BIT = 18

    # Bit 17 - Perform the transfer
    TRANSFER_BIT = 17

    # Bit 16 - Direction: 0=read, 1=write
    WRITE_BIT = 16

    # Bits 15:0 - Register number
    REGNO_SHIFT = 0
    REGNO_MASK = 0xFFFF

    @staticmethod
    def build_access_register_read(regno: int, aarsize: int = 2,
                                   postexec: bool = False) -> int:
        """Build Access Register command for reading.

        Args:
            regno: Register number (see RiscvRegno)
            aarsize: Access size (2=32-bit, 3=64-bit)
            postexec: Execute program buffer after transfer
        """
        cmd = (Command.CMDTYPE_ACCESS_REG << Command.CMDTYPE_SHIFT)
        cmd |= (aarsize << Command.AARSIZE_SHIFT)
        cmd |= (1 << Command.TRANSFER_BIT)
        if postexec:
            cmd |= (1 << Command.POSTEXEC_BIT)
        cmd |= (regno & Command.REGNO_MASK)
        return cmd

    @staticmethod
    def build_access_register_write(regno: int, aarsize: int = 2,
                                    postexec: bool = False) -> int:
        """Build Access Register command for writing."""
        cmd = Command.build_access_register_read(regno, aarsize, postexec)
        cmd |= (1 << Command.WRITE_BIT)
        return cmd

    @staticmethod
    def build_postexec_only() -> int:
        """Build command that only executes program buffer (no transfer)."""
        return (1 << Command.POSTEXEC_BIT)

    # ========== Access Memory Commands (cmdtype=2) ==========

    # Access Memory specific field names (same bit positions as Access Register)
    # aamsize = aarsize (bits 22:20), aampostincrement = aarpostincrement (bit 19)
    AAMVIRTUAL_BIT = 23

    @staticmethod
    def build_access_memory_read(aamsize: int = 2,
                                  aamvirtual: bool = False,
                                  aampostincrement: bool = False) -> int:
        """Build Access Memory command for reading.

        Args:
            aamsize: Access size encoding (0=8bit, 1=16bit, 2=32bit, 3=64bit, 4=128bit)
            aamvirtual: Use virtual address translation (M-mode with MPRV)
            aampostincrement: Auto-increment arg1 (address) by access size

        Returns:
            32-bit command value. arg0=DATA0 receives read data, arg1=DATA1 holds address.
        """
        cmd = Command.CMDTYPE_ACCESS_MEM << Command.CMDTYPE_SHIFT
        cmd |= (aamsize & Command.AARSIZE_MASK) << Command.AARSIZE_SHIFT
        if aamvirtual:
            cmd |= 1 << Command.AAMVIRTUAL_BIT
        if aampostincrement:
            cmd |= 1 << Command.AARPOSTINCREMENT_BIT
        return cmd

    @staticmethod
    def build_access_memory_write(aamsize: int = 2,
                                   aamvirtual: bool = False,
                                   aampostincrement: bool = False) -> int:
        """Build Access Memory command for writing.

        Args:
            aamsize: Access size encoding
            aamvirtual: Use virtual address translation
            aampostincrement: Auto-increment arg1 (address) by access size

        Returns:
            32-bit command value. arg0=DATA0 holds write data, arg1=DATA1 holds address.
        """
        cmd = Command.build_access_memory_read(aamsize, aamvirtual, aampostincrement)
        cmd |= 1 << Command.WRITE_BIT
        return cmd


class DMControl:
    """DMCONTROL register bit fields.

    Source: RISC-V Debug Spec v0.13.2, Section 3.4.1
    """
    HALTREQ_BIT = 31
    RESUMEREQ_BIT = 30
    HARTSELHI_SHIFT = 6
    HARTSELHI_MASK = 0x3FF
    HASEL_BIT = 26
    HARTSELLO_SHIFT = 16
    HARTSELLO_MASK = 0x3FF
    ACKHAVERESET_BIT = 28
    HARTRESET_BIT = 29
    ACKUNAVAIL_BIT = 27
    SETRESETHALTREQ_BIT = 3
    CLRRESETHALTREQ_BIT = 2
    NDMRESET_BIT = 1
    DMACTIVE_BIT = 0

    @staticmethod
    def build_dmactive() -> int:
        return 1 << DMControl.DMACTIVE_BIT

    @staticmethod
    def build_haltreq(dmactive: int) -> int:
        return dmactive | (1 << DMControl.HALTREQ_BIT)

    @staticmethod
    def build_resumereq(dmactive: int) -> int:
        return dmactive | (1 << DMControl.RESUMEREQ_BIT)

    @staticmethod
    def build_setresethaltreq(dmcontrol: int) -> int:
        return dmcontrol | (1 << DMControl.SETRESETHALTREQ_BIT)

    @staticmethod
    def build_clrresethaltreq(dmcontrol: int) -> int:
        return dmcontrol | (1 << DMControl.CLRRESETHALTREQ_BIT)

    @staticmethod
    def clear_haltreq(dmcontrol: int) -> int:
        return dmcontrol & ~(1 << DMControl.HALTREQ_BIT)

    @staticmethod
    def clear_resumereq(dmcontrol: int) -> int:
        return dmcontrol & ~(1 << DMControl.RESUMEREQ_BIT)

    @staticmethod
    def parse_dmactive(dmcontrol: int) -> bool:
        return bool(dmcontrol & (1 << DMControl.DMACTIVE_BIT))

    @staticmethod
    def set_hartsel(dmcontrol: int, hart: int) -> int:
        """Set hartsel field (20-bit: hartsello[25:16] + hartselhi[15:6]).

        Reference: RISC-V Debug Spec v0.13.2 §3.4 (dmcontrol.hartsel)

        Args:
            dmcontrol: Current dmcontrol value
            hart: 20-bit hart index

        Returns:
            Updated dmcontrol value
        """
        dmcontrol &= ~(DMControl.HARTSELLO_MASK << DMControl.HARTSELLO_SHIFT)
        dmcontrol &= ~(DMControl.HARTSELHI_MASK << DMControl.HARTSELHI_SHIFT)
        dmcontrol |= (hart & DMControl.HARTSELLO_MASK) << DMControl.HARTSELLO_SHIFT
        dmcontrol |= ((hart >> 10) & DMControl.HARTSELHI_MASK) << DMControl.HARTSELHI_SHIFT
        return dmcontrol

    @staticmethod
    def parse_hartsel(dmcontrol: int) -> int:
        """Parse hartsel from dmcontrol (20-bit composite).

        hartsel = hartsello[25:16] | (hartselhi[15:6] << 10)

        Reference: RISC-V Debug Spec v0.13.2 §3.4 (dmcontrol.hartsel)

        Args:
            dmcontrol: dmcontrol register value

        Returns:
            20-bit hart index
        """
        lo = (dmcontrol >> DMControl.HARTSELLO_SHIFT) & DMControl.HARTSELLO_MASK
        hi = (dmcontrol >> DMControl.HARTSELHI_SHIFT) & DMControl.HARTSELHI_MASK
        return lo | (hi << 10)


class DMStatus:
    """DMSTATUS register bit fields.

    Source: RISC-V Debug Spec v0.13.2, Section 3.4.2
    """
    VERSION_SHIFT = 0
    VERSION_MASK = 0xF

    # Per RISC-V Debug Spec v0.13.2, Table 3.6 (DMSTATUS)
    ALLHALTED_BIT = 9
    ANYHALTED_BIT = 8
    ALLRUNNING_BIT = 11
    ANYRUNNING_BIT = 10
    ALLRESUMEACK_BIT = 17
    ANYRESUMEACK_BIT = 16
    ALLNONEXISTENT_BIT = 15
    ANYNONEXISTENT_BIT = 14
    ALLUNAVAIL_BIT = 13
    ANYUNAVAIL_BIT = 12
    ALLHAVERESET_BIT = 19
    ANYHAVERESET_BIT = 18
    IMPEBREAK_BIT = 22
    HASRESETHALTREQ_BIT = 5

    @staticmethod
    def parse_allhalted(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ALLHALTED_BIT))

    @staticmethod
    def parse_anyhalted(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ANYHALTED_BIT))

    @staticmethod
    def parse_allrunning(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ALLRUNNING_BIT))

    @staticmethod
    def parse_anyrunning(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ANYRUNNING_BIT))

    @staticmethod
    def parse_impebreak(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.IMPEBREAK_BIT))

    @staticmethod
    def parse_hasresethaltreq(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.HASRESETHALTREQ_BIT))

    @staticmethod
    def parse_allhavereset(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ALLHAVERESET_BIT))

    @staticmethod
    def parse_anyhavereset(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ANYHAVERESET_BIT))

    @staticmethod
    def parse_allresumeack(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ALLRESUMEACK_BIT))

    @staticmethod
    def parse_anynonexistent(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ANYNONEXISTENT_BIT))

    @staticmethod
    def parse_allnonexistent(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ALLNONEXISTENT_BIT))

    @staticmethod
    def parse_anyunavail(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ANYUNAVAIL_BIT))

    @staticmethod
    def parse_allunavail(dmstatus: int) -> bool:
        return bool(dmstatus & (1 << DMStatus.ALLUNAVAIL_BIT))


class AbstractAuto:
    """ABSTRACTAUTO register bit fields.

    When autoexecdata[n] is set, any read or write of DATAn causes
    the command in COMMAND to be re-executed automatically, eliminating
    per-word COMMAND writes in batch operations.

    Source: RISC-V Debug Spec v0.13.2, Section 3.5.3
    """
    # Bits 11:0 - Auto-execute on data register access
    AUTOEXECDATA_SHIFT = 0
    AUTOEXECDATA_MASK = 0xFFF

    # Bits 19:12 - Auto-execute on progbuf register access
    AUTOEXECPROGBUF_SHIFT = 12
    AUTOEXECPROGBUF_MASK = 0xFFF

    @staticmethod
    def enable_autoexecdata(data_index: int = 0) -> int:
        """Build ABSTRACTAUTO value to enable auto-exec on DATAn access."""
        return 1 << (AbstractAuto.AUTOEXECDATA_SHIFT + data_index)

    @staticmethod
    def disable_all() -> int:
        """Build ABSTRACTAUTO value that disables all auto-execution."""
        return 0


class SBCS:
    """SBCS register bit fields.

    Source: RISC-V Debug Spec v0.13.2, Section 3.6.2
    """
    # Bits 31:29 - System Bus version
    SBVERSION_SHIFT = 29
    SBVERSION_MASK = 0x7

    # Bit 22 - Busy error (sticky)
    SBBUSYERROR_BIT = 22

    # Bit 21 - System Bus busy
    SBBUSY_BIT = 21

    # Bit 20 - Auto-read on address write
    SBREADONADDR_BIT = 20

    # Bits 19:17 - Access size
    SBACCESS_SHIFT = 17
    SBACCESS_MASK = 0x7

    # Bit 16 - Auto-increment address
    SBAUTOINCREMENT_BIT = 16

    # Bit 15 - Auto-read on data read
    SBREADONDATA_BIT = 15

    # Bits 14:12 - Error code
    SBERROR_SHIFT = 12
    SBERROR_MASK = 0x7
    SBERROR_CLEAR = 0x7 << 12

    # Bits 11:5 - Address width
    SBASIZE_SHIFT = 5
    SBASIZE_MASK = 0x7F

    # Bits 4:0 - Supported access sizes
    SBACCESS128_BIT = 4
    SBACCESS64_BIT = 3
    SBACCESS32_BIT = 2
    SBACCESS16_BIT = 1
    SBACCESS8_BIT = 0

    @staticmethod
    def parse_sbversion(sbcs: int) -> int:
        return (sbcs >> SBCS.SBVERSION_SHIFT) & SBCS.SBVERSION_MASK

    @staticmethod
    def parse_sbasize(sbcs: int) -> int:
        return (sbcs >> SBCS.SBASIZE_SHIFT) & SBCS.SBASIZE_MASK

    @staticmethod
    def parse_sberror(sbcs: int) -> int:
        return (sbcs >> SBCS.SBERROR_SHIFT) & SBCS.SBERROR_MASK

    @staticmethod
    def parse_sbbusy(sbcs: int) -> bool:
        return bool(sbcs & (1 << SBCS.SBBUSY_BIT))

    @staticmethod
    def build_clear_error() -> int:
        return SBCS.SBERROR_CLEAR

    @staticmethod
    def build_read_config(sbaccess: int) -> int:
        """Build SBCS value for single read with sbreadonaddr."""
        return (sbaccess << SBCS.SBACCESS_SHIFT) | (1 << SBCS.SBREADONADDR_BIT)

    @staticmethod
    def build_batch_read_config(sbaccess: int) -> int:
        """Build SBCS value for batch read with auto-increment and auto-read."""
        return ((sbaccess << SBCS.SBACCESS_SHIFT) |
                (1 << SBCS.SBREADONADDR_BIT) |
                (1 << SBCS.SBAUTOINCREMENT_BIT) |
                (1 << SBCS.SBREADONDATA_BIT))

    @staticmethod
    def build_write_config(sbaccess: int, autoincrement: bool = False) -> int:
        """Build SBCS value for write."""
        cfg = sbaccess << SBCS.SBACCESS_SHIFT
        if autoincrement:
            cfg |= (1 << SBCS.SBAUTOINCREMENT_BIT)
        return cfg


class RiscvRegno:
    """RISC-V register numbers for abstract commands.

    Source: RISC-V Debug Spec v0.13.2, Table 3.11
    """
    # GPR registers
    X0 = 0x1000
    X1 = 0x1001
    X2 = 0x1002
    X3 = 0x1003
    X4 = 0x1004
    X5 = 0x1005
    X6 = 0x1006
    X7 = 0x1007
    X8 = 0x1008   # s0/fp
    X9 = 0x1009
    X10 = 0x100A  # a0
    X11 = 0x100B  # a1
    X12 = 0x100C
    X13 = 0x100D
    X14 = 0x100E
    X15 = 0x100F
    X16 = 0x1010
    X17 = 0x1011
    X18 = 0x1012
    X19 = 0x1013
    X20 = 0x1014
    X21 = 0x1015
    X22 = 0x1016
    X23 = 0x1017
    X24 = 0x1018
    X25 = 0x1019
    X26 = 0x101A
    X27 = 0x101B
    X28 = 0x101C
    X29 = 0x101D
    X30 = 0x101E
    X31 = 0x101F

    # Debug registers (RISC-V Debug Spec v0.13.2, Table 3.11)
    DCSR = 0x07B0
    DPC = 0x07B1
    DSCRATCH0 = 0x07B2
    DSCRATCH1 = 0x07B3

    # Supervisor registers
    SSTATUS = 0x100
    SIE = 0x104
    STVEC = 0x105
    SSCRATCH = 0x140
    SEPC = 0x141
    SCAUSE = 0x142
    STVAL = 0x143
    SIP = 0x144
    SATP = 0x180

    # Machine registers
    MSTATUS = 0x300
    MISA = 0x301
    MEDELEG = 0x302
    MIDELEG = 0x303
    MIE = 0x304
    MTVEC = 0x305
    MCOUNTEREN = 0x306
    MSCRATCH = 0x340
    MEPC = 0x341
    MCAUSE = 0x342
    MTVAL = 0x343
    MIP = 0x344
    PMPCFG0 = 0x3A0
    PMPADDR0 = 0x3B0

    # Trigger Module CSRs (Debug Spec v0.13 Sdtrig)
    TSELECT = 0x7A0
    TDATA1 = 0x7A1
    TDATA2 = 0x7A2
    TDATA3 = 0x7A3
    TINFO = 0x7A4


# Re-export RiscvInstr from instructions.py for backward compatibility.
from ..instructions import RiscvInstr  # noqa: F401


class HartInfo:
    """HARTINFO register bit fields.

    Source: RISC-V Debug Spec v0.13.2, Section 3.4.5, Table 3.12
    """
    # Bits 23:20 - Number of dscratch registers
    NSCRATCH_SHIFT = 20
    NSCRATCH_MASK = 0xF

    # Bit 16 - Data registers are memory-mapped (0=CSR, 1=memory)
    DATAACCESS_BIT = 16

    # Bits 15:12 - Number of data registers per hart
    DATASIZE_SHIFT = 12
    DATASIZE_MASK = 0xF

    # Bits 11:0 - Address of first data register
    DATAADDR_SHIFT = 0
    DATAADDR_MASK = 0xFFF

    @staticmethod
    def parse_nscratch(hartinfo: int) -> int:
        return (hartinfo >> HartInfo.NSCRATCH_SHIFT) & HartInfo.NSCRATCH_MASK

    @staticmethod
    def parse_dataaccess(hartinfo: int) -> bool:
        return bool(hartinfo & (1 << HartInfo.DATAACCESS_BIT))

    @staticmethod
    def parse_datasize(hartinfo: int) -> int:
        return (hartinfo >> HartInfo.DATASIZE_SHIFT) & HartInfo.DATASIZE_MASK

    @staticmethod
    def parse_dataaddr(hartinfo: int) -> int:
        return (hartinfo >> HartInfo.DATAADDR_SHIFT) & HartInfo.DATAADDR_MASK
