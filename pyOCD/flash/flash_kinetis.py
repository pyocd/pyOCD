"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from flash import Flash
import logging

# @brief Base flash algorithm class for Freescale Kinetis devices.
class Flash_Kinetis(Flash):

    # @brief Check security bytes.
    #
    # Check Flash Configuration Field bytes at address 0x400-0x40f to ensure that flash security
    # won't be enabled. If flash security is enabled, then the chip is inaccessible via SWD.
    #
    # FCF bytes:
    # [0x0-0x7]=backdoor key
    # [0x8-0xb]=flash protection bytes
    # [0xc]=FSEC:
    #      [7:6]=KEYEN (2'b10 is backdoor key enabled, all others backdoor key disabled)
    #      [5:4]=MEEN (2'b10 mass erase disabled, all other mass erase enabled)
    #      [3:2]=FSLACC (2'b00 and 2'b11 factory access enabled, 2'b01 and 2'b10 factory access disabled)
    #      [1:0]=SEC (2'b10 flash security disabled, all other flash security enabled)
    # [0xd]=FOPT
    # [0xe]=EEPROM protection bytes (FlexNVM devices only)
    # [0xf]=data flash protection bytes (FlexNVM devices only)
    #
    # This function checks that:
    # - 0x0-0xb==0xff
    # - 0xe-0xf==0xff
    # - FSEC=0xfe
    #
    # FOPT can be set to any value except 0x00.
    #
    # @retval 0 The security check failed. In other words, security would be enabled and the chip
    #       locked from debugging if these bytes were written.
    # @retval 1 Security check passed.
    def checkSecurityBits(self, address, data):
        #error if security bits have unexpected values
        if (address == 0x400):
            for i in range(12):
                logging.debug("FCF[%d] at addr 0x%X: 0x%X", i, i, data[i])
                if (data[i] != 0xff):
                    return 0

            # FOPT must not be 0x00, any other value is acceptable.
            if data[0xd] == 0x00:
                return 0

            logging.debug("FCF[%d] at addr 0x%X: 0x%X", i+3, i+3, data[i+3])
            logging.debug("FCF[%d] at addr 0x%X: 0x%X", i+4, i+4, data[i+4])
            if ((data[0xe] != 0xff) or (data[0xf] != 0xff)):
                return 0

        return 1
