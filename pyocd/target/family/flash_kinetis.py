# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
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

from ...flash.flash import Flash
import logging

LOG = logging.getLogger(__name__)

# Kinetis security values and addresses
SECURITY_START = 0x400
SECURITY_SIZE = 16
FPROT_ADDR = 0x408
FPROT_ADDR_END = 0x40c
FPROT_SIZE = 4
FSEC_ADDR = 0x40c
FSEC_VAL = 0xFE
FOPT_ADDR = 0x40d
FOPT_VAL = 0xFF
FEPROT_ADDR = 0x40e
FEPROT_VAL = 0xFF
FDPROT_ADDR = 0x40f
FDPROT_VAL = 0xFF

class Flash_Kinetis(Flash):
    """! @brief Base flash algorithm class for Freescale Kinetis devices."""

    def override_security_bits(self, address, data):
        """! @brief Check security bytes.
        
        Override Flash Configuration Field bytes at address 0x400-0x40f to ensure that flash security
        won't be enabled. If flash security is enabled, then the chip is inaccessible via SWD.
        
        FCF bytes:
        [0x0-0x7]=backdoor key
        [0x8-0xb]=flash protection bytes
        [0xc]=FSEC:
             [7:6]=KEYEN (2'b10 is backdoor key enabled, all others backdoor key disabled)
             [5:4]=MEEN (2'b10 mass erase disabled, all other mass erase enabled)
             [3:2]=FSLACC (2'b00 and 2'b11 factory access enabled, 2'b01 and 2'b10 factory access disabled)
             [1:0]=SEC (2'b10 flash security disabled, all other flash security enabled)
        [0xd]=FOPT
        [0xe]=EEPROM protection bytes (FlexNVM devices only)
        [0xf]=data flash protection bytes (FlexNVM devices only)
        
        This function enforces that:
        - 0x8-0xb==0xff
        - 0xe-0xf==0xff
        - FSEC=0xfe
        
        FOPT can be set to any value except 0x00.
        
        @retval Data with modified security bits
        """
        # Check if the data passed in contains the security bits
        if (address <= SECURITY_START and address + len(data) >= SECURITY_START + SECURITY_SIZE):

            # convert data to a list so it can be modified
            data = list(data)

            # FPROT must be 0xff (erase protection disabled)
            for i in range(FPROT_ADDR, FPROT_ADDR_END):
                if (data[i - address] != 0xff):
                    data[i - address] = 0xff
                    LOG.debug("FCF[%d] at addr 0x%X changed to 0x%X", i - FPROT_ADDR, i, data[i - address])

            # FSEC must be 0xff
            if data[FSEC_ADDR - address] != FSEC_VAL:
                data[FSEC_ADDR - address] = FSEC_VAL
                LOG.debug("FSEC at addr 0x%X changed to 0x%X", FSEC_ADDR, FSEC_VAL)

            # FOPT must not be 0x00, any other value is acceptable.
            if data[FOPT_ADDR - address] == 0x00:
                LOG.debug("FOPT is restricted value 0x00")

            # FEPROT must be 0xff
            if data[FEPROT_ADDR - address] != FEPROT_VAL:
                data[FEPROT_ADDR - address] = FEPROT_VAL
                LOG.debug("FEPROT at addr 0x%X changed to 0x%X", FEPROT_ADDR, FEPROT_VAL)

            # FDPROT must be 0xff
            if data[FDPROT_ADDR - address] != FDPROT_VAL:
                data[FDPROT_ADDR - address] = FDPROT_VAL
                LOG.debug("FDPROT at addr 0x%X changed to 0x%X", FDPROT_ADDR, FDPROT_VAL)

            # convert back to tuple
            data = tuple(data)

        return data
