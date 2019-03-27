# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

class Commands:    
    """!
    @brief STLink V2 and V3 commands.
    """
    
    # Common commands.
    GET_VERSION = 0xf1
    JTAG_COMMAND = 0xf2
    DFU_COMMAND = 0xf3
    SWIM_COMMAND = 0xf4
    GET_CURRENT_MODE = 0xf5
    GET_TARGET_VOLTAGE = 0xf7
    GET_VERSION_EXT = 0xfb

    # Modes returned by GET_CURRENT_MODE.
    DEV_DFU_MODE = 0x00
    DEV_MASS_MODE = 0x01
    DEV_JTAG_MODE = 0x02
    DEV_SWIM_MODE = 0x03

    # Commands to exit other modes.
    DFU_EXIT = 0x07
    SWIM_EXIT = 0x01

    # JTAG commands.
    JTAG_READMEM_32BIT = 0x07
    JTAG_WRITEMEM_32BIT = 0x08
    JTAG_READMEM_8BIT = 0x0c
    JTAG_WRITEMEM_8BIT = 0x0d
    JTAG_EXIT = 0x21
    JTAG_ENTER2 = 0x30
    JTAG_GETLASTRWSTATUS2 = 0x3e # From V2J15
    JTAG_DRIVE_NRST = 0x3c
    SWV_START_TRACE_RECEPTION = 0x40
    SWV_STOP_TRACE_RECEPTION = 0x41
    SWV_GET_TRACE_NEW_RECORD_NB = 0x42
    SWD_SET_FREQ = 0x43 # From V2J20
    JTAG_SET_FREQ = 0x44 # From V2J24
    JTAG_READ_DAP_REG = 0x45 # From V2J24
    JTAG_WRITE_DAP_REG = 0x46 # From V2J24
    JTAG_READMEM_16BIT = 0x47 # From V2J26
    JTAG_WRITEMEM_16BIT = 0x48 # From V2J26
    JTAG_INIT_AP = 0x4b # From V2J28
    JTAG_CLOSE_AP_DBG = 0x4c # From V2J28
    SET_COM_FREQ = 0x61 # V3 only, replaces SWD/JTAG_SET_FREQ
    GET_COM_FREQ = 0x62 # V3 only
    
    # Parameters for JTAG_ENTER2.
    JTAG_ENTER_SWD = 0xa3
    JTAG_ENTER_JTAG_NO_CORE_RESET = 0xa3

    # Parameters for JTAG_DRIVE_NRST.
    JTAG_DRIVE_NRST_LOW = 0x00
    JTAG_DRIVE_NRST_HIGH = 0x01
    JTAG_DRIVE_NRST_PULSE = 0x02
    
    # Parameters for JTAG_INIT_AP and JTAG_CLOSE_AP_DBG.
    JTAG_AP_NO_CORE = 0x00
    JTAG_AP_CORTEXM_CORE = 0x01
    
    # Parameters for SET_COM_FREQ and GET_COM_FREQ.
    JTAG_STLINK_SWD_COM = 0x00
    JTAG_STLINK_JTAG_COM = 0x01
    
class Status(object):
    """!
    @brief STLink status codes and messages.
    """
    # Status codes.
    JTAG_OK = 0x80
    JTAG_UNKNOWN_ERROR = 0x01
    JTAG_SPI_ERROR = 0x02
    JTAG_DMA_ERROR = 0x03
    JTAG_UNKNOWN_JTAG_CHAIN = 0x04
    JTAG_NO_DEVICE_CONNECTED = 0x05
    JTAG_INTERNAL_ERROR = 0x06
    JTAG_CMD_WAIT = 0x07
    JTAG_CMD_ERROR = 0x08
    JTAG_GET_IDCODE_ERROR = 0x09
    JTAG_ALIGNMENT_ERROR = 0x0a
    JTAG_DBG_POWER_ERROR = 0x0b
    JTAG_WRITE_ERROR = 0x0c
    JTAG_WRITE_VERIF_ERROR = 0x0d
    JTAG_ALREADY_OPENED_IN_OTHER_MODE = 0x0e
    SWD_AP_WAIT = 0x10
    SWD_AP_FAULT = 0x11
    SWD_AP_ERROR = 0x12
    SWD_AP_PARITY_ERROR = 0x13
    SWD_DP_WAIT = 0x14
    SWD_DP_FAULT = 0x15
    SWD_DP_ERROR = 0x16
    SWD_DP_PARITY_ERROR = 0x17
    SWD_AP_WDATA_ERROR = 0x18
    SWD_AP_STICKY_ERROR = 0x19
    SWD_AP_STICKYORUN_ERROR = 0x1a
    SWV_NOT_AVAILABLE = 0x20
    JTAG_FREQ_NOT_SUPPORTED = 0x41
    JTAG_UNKNOWN_CMD = 0x42
    
    ## Map from status code to error message.
    MESSAGES = {
        JTAG_UNKNOWN_ERROR : "Unknown error",
        JTAG_SPI_ERROR : "SPI error",
        JTAG_DMA_ERROR : "DMA error",
        JTAG_UNKNOWN_JTAG_CHAIN : "Unknown JTAG chain",
        JTAG_NO_DEVICE_CONNECTED : "No device connected",
        JTAG_INTERNAL_ERROR : "Internal error",
        JTAG_CMD_WAIT : "Command wait",
        JTAG_CMD_ERROR : "Command error",
        JTAG_GET_IDCODE_ERROR : "Get IDCODE error",
        JTAG_ALIGNMENT_ERROR : "Alignment error",
        JTAG_DBG_POWER_ERROR : "Debug power error",
        JTAG_WRITE_ERROR : "Write error",
        JTAG_WRITE_VERIF_ERROR : "Write verification error",
        JTAG_ALREADY_OPENED_IN_OTHER_MODE : "Already opened in another mode",
        SWD_AP_WAIT : "AP wait",
        SWD_AP_FAULT : "AP fault",
        SWD_AP_ERROR : "AP error",
        SWD_AP_PARITY_ERROR : "AP parity error",
        SWD_DP_WAIT : "DP wait",
        SWD_DP_FAULT : "DP fault",
        SWD_DP_ERROR : "DP error",
        SWD_DP_PARITY_ERROR : "DP parity error",
        SWD_AP_WDATA_ERROR : "AP WDATA error",
        SWD_AP_STICKY_ERROR : "AP sticky error",
        SWD_AP_STICKYORUN_ERROR : "AP sticky overrun error",
        SWV_NOT_AVAILABLE : "SWV not available",
        JTAG_FREQ_NOT_SUPPORTED : "Frequency not supported",
        JTAG_UNKNOWN_CMD : "Unknown command",
    }
    
    @staticmethod
    def get_error_message(status):
        return "STLink error ({}): {}".format(status, Status.MESSAGES.get(status, "Unknown error"))

## Map from SWD frequency in Hertz to delay loop count.
SWD_FREQ_MAP = {
    4600000 :   0,
    1800000 :   1, # Default
    1200000 :   2,
    950000 :    3,
    650000 :    5,
    480000 :    7,
    400000 :    9,
    360000 :    10,
    240000 :    15,
    150000 :    25,
    125000 :    31,
    100000 :    40,
}

## Map from JTAG frequency in Hertz to frequency divider.
JTAG_FREQ_MAP = {
    18000000 :  2,
    9000000 :   4,
    4500000 :   8,
    2250000 :   16,
    1120000 :   32, # Default
    560000 :    64,
    280000 :    128,
    140000 :    256,
}

