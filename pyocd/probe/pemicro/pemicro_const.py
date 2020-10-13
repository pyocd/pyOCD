#!/usr/bin/env python
#
# Copyright (c) 2020 P&E Microcomputer Systems, Inc
# All rights reserved.
# Visit us at www.pemicro.com
#
# SPDX-License-Identifier:
# BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# o Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
#
# o Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# o Neither the names of the copyright holders nor the names of the
#   contributors may be used to endorse or promote products derived from this
#   software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This file has been modified by NXP 2020 to implement into PyOCD project
"""PEMicro Python implementation by NXP.

The basics of the code is comming from original PEMicro version.
"""
from enum import IntEnum

#Types are provided via *.PYI interface files
#pylint: disable=missing-type-doc,missing-return-type-doc

# Enumeration of all PEMicro port types
class PEMicroPortType(IntEnum):
    """List of all supported PEMicro port types."""
    AUTODETECT = 99
    PARALLEL_PORT_CABLE = 1
    PCIBDM_LIGHTNING = 2
    USB_MULTILINK = 3
    CYCLONE_PRO_MAX_SERIAL = 4
    CYCLONE_PRO_MAX_USB = 5
    CYCLONE_PRO_MAX_ETHERNET = 6
    OPENSDA_USB = 9

# Enumeration of all PEMicro Special features
class PEMicroSpecialFeatures(IntEnum):
    """Enumeration of all PEMicro Special features."""
    # Special Features for Power Management
    PE_PWR_SET_POWER_OPTIONS = 0X38000001
    PE_PWR_TURN_POWER_ON = 0X38000011
    PE_PWR_TURN_POWER_OFF = 0X38000012

    # Special Features for debug communications mode
    PE_ARM_SET_COMMUNICATIONS_MODE = 0X44000001
    PE_ARM_SET_DEBUG_COMM_SWD = 0X00000000
    PE_ARM_SET_DEBUG_COMM_JTAG = 0X00000001

    PE_ARM_ENABLE_DEBUG_MODULE = 0X44000002
    PE_ARM_WRITE_AP_REGISTER = 0X44000003
    PE_ARM_READ_AP_REGISTER = 0X44000004
    PE_ARM_WRITE_DP_REGISTER = 0X44000007
    PE_ARM_READ_DP_REGISTER = 0X44000008
    PE_ARM_FLUSH_ANY_QUEUED_DATA = 0X44000005

    # SWD control special features
    PE_ARM_GET_LAST_SWD_STATUS = 0X44000006

    # Special Features for Setting current device and core
    PE_GENERIC_GET_DEVICE_LIST = 0X58004000
    PE_GENERIC_SELECT_DEVICE = 0X58004001
    PE_GENERIC_GET_CORE_LIST = 0X58004002
    PE_GENERIC_SELECT_CORE = 0X58004003
    PE_SET_DEFAULT_APPLICATION_FILES_DIRECTORY = 0X58006000

class PEMicroSpecialFeaturesSwdStatus(IntEnum):
    """Enumeration of all possible SWD status values."""
    PE_ARM_SWD_STATUS_ACK = 0X04
    PE_ARM_SWD_STATUS_WAIT = 0X02
    PE_ARM_SWD_STATUS_FAULT = 0X01

class PEMicroMemoryAccessResults(IntEnum):
    """Enumeration of all PEMicro Special features."""
    #No error occurred.
    PE_MAR_MEM_OK = 0
    #Access to memory was denied. (MCU is running).
    PE_MAR_MEM_NO_ACCESS = 1
    #A Bus error was detected.
    PE_MAR_MEM_BUS_ERROR = 2
    #Non-existent memory was accessed.
    PE_MAR_MEM_UNIMPLEMENTED = 3
    #Valid but indeterminate memory was accessed.
    PE_MAR_MEM_UNINITIALIZED = 4
    #Error occurred during programming sequence.
    PE_MAR_MEM_PROGRAMMING_ERROR = 5


class PEMicroMemoryAccessSize(IntEnum):
    """Memory access size used for block memmory operations."""
    PE_MEM_ACCESS_8BIT = 1
    PE_MEM_ACCESS_16BIT = 2
    PE_MEM_ACCESS_32BIT = 4

class PEMicroArmRegisters(IntEnum):
    """List of Arm registers used for Writing/Readin operations."""
    # Core registers
    PE_ARM_REG_R0 = 0
    PE_ARM_REG_R1 = 1
    PE_ARM_REG_R2 = 2
    PE_ARM_REG_R3 = 3
    PE_ARM_REG_R4 = 4
    PE_ARM_REG_R5 = 5
    PE_ARM_REG_R6 = 6
    PE_ARM_REG_R7 = 7
    PE_ARM_REG_R8 = 8
    PE_ARM_REG_R9 = 9
    PE_ARM_REG_R10 = 10
    PE_ARM_REG_R11 = 11
    PE_ARM_REG_R12 = 12
    PE_ARM_REG_R13 = 13
    PE_ARM_REG_R14 = 14
    PE_ARM_REG_R15 = 15
    PE_ARM_REG_SP = PE_ARM_REG_R13
    PE_ARM_REG_LR = PE_ARM_REG_R14
    PE_ARM_REG_PC = PE_ARM_REG_R15

    # Program status registers + Stack pointers
    PE_ARM_REG_XPSR = 16
    PE_ARM_REG_MSP = 17      # Main SP
    PE_ARM_REG_PSP = 18      # Process SP

    # Special registers
    # CONTROL bits [31:24]
    # FAULTMASK bits [23:16]
    # BASEPRI bits [15:8]
    # PRIMASK bits [7:0]
    PE_ARM_REG_SPECIAL_REG = 20

    # Floating-Point Status and Control Register
    PE_ARM_REG_FPSCR = 33

    # Floating point registers
    PE_ARM_REG_S0 = 64
    PE_ARM_REG_S1 = 65
    PE_ARM_REG_S2 = 66
    PE_ARM_REG_S3 = 67
    PE_ARM_REG_S4 = 68
    PE_ARM_REG_S5 = 69
    PE_ARM_REG_S6 = 70
    PE_ARM_REG_S7 = 71
    PE_ARM_REG_S8 = 72
    PE_ARM_REG_S9 = 73
    PE_ARM_REG_S10 = 74
    PE_ARM_REG_S11 = 75
    PE_ARM_REG_S12 = 76
    PE_ARM_REG_S13 = 77
    PE_ARM_REG_S14 = 78
    PE_ARM_REG_S15 = 79
    PE_ARM_REG_S16 = 80
    PE_ARM_REG_S17 = 81
    PE_ARM_REG_S18 = 82
    PE_ARM_REG_S19 = 83
    PE_ARM_REG_S20 = 84
    PE_ARM_REG_S21 = 85
    PE_ARM_REG_S22 = 86
    PE_ARM_REG_S23 = 87
    PE_ARM_REG_S24 = 88
    PE_ARM_REG_S25 = 89
    PE_ARM_REG_S26 = 90
    PE_ARM_REG_S27 = 91
    PE_ARM_REG_S28 = 92
    PE_ARM_REG_S29 = 93
    PE_ARM_REG_S30 = 94
    PE_ARM_REG_S31 = 95

    # MDM-AP Status Register
    PE_ARM_REG_MDM_AP = 1000

class PEMicroInterfaces(IntEnum):
    """Target interfaces for the PEMicro."""
    JTAG = 0
    SWD = 1

    @classmethod
    def get_str(cls, interface):
        """Gets the string version of PEMicro Interface.

        :param interface: The Interface in numeric format
        :return: String format of interface.
        """
        if not isinstance(interface, cls):
            return "Not selected"
        else:
            return "SWD" if interface is cls.SWD else "JTAG"
