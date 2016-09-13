"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

from flash_cortex_m import Flash_cortex_m
from flash_klxx import Flash_klxx
from flash_ke15z7 import Flash_ke15z7
from flash_ke18f16 import Flash_ke18f16
from flash_kl27z4 import Flash_kl27z4
from flash_kl28z import Flash_kl28z
from flash_kl43z4 import Flash_kl43z4
from flash_kv10z7 import Flash_kv10z7
from flash_kv11z7 import Flash_kv11z7
from flash_kw01z4 import Flash_kw01z4
from flash_kw40z4 import Flash_kw40z4
from flash_k20d50m import Flash_k20d50m
from flash_k22f import Flash_k22f
from flash_k64f import Flash_k64f
from flash_k66f18 import Flash_k66f18
from flash_k82f25615 import Flash_k82f25615
from flash_lpc800 import Flash_lpc800
from flash_lpc11u24 import Flash_lpc11u24
from flash_lpc1768 import Flash_lpc1768
from flash_lpc4330 import Flash_lpc4330
from flash_nrf51 import Flash_nrf51
from flash_nrf52 import Flash_nrf52
from flash_stm32f103rc import Flash_stm32f103rc
from flash_stm32f051 import Flash_stm32f051
from flash_maxwsnenv import Flash_maxwsnenv
from flash_max32600mbed import Flash_max32600mbed
from flash_w7500 import Flash_w7500
from flash_lpc11xx_32 import Flash_lpc11xx_32
from flash_lpc824 import Flash_lpc824
from flash_lpc4088 import Flash_lpc4088
from flash_ncs36510 import Flash_ncs36510
from flash_lpc4088qsb_dm import Flash_lpc4088qsb_dm

FLASH = {
         'cortex_m': Flash_cortex_m,
         'kinetis': Flash_cortex_m,
         'ke15z7': Flash_ke15z7,
         'ke18f16': Flash_ke18f16,
         'kl02z': Flash_klxx,
         'kl05z': Flash_klxx,
         'kl25z': Flash_klxx,
         'kl26z': Flash_klxx,
         'kl27z4': Flash_kl27z4,
         'kl28z': Flash_kl28z,
         'kl43z4': Flash_kl43z4,
         'kl46z': Flash_klxx,
         'kv10z7': Flash_kv10z7,
         'kv11z7': Flash_kv11z7,
         'kw01z4': Flash_kw01z4,
         'kw40z4': Flash_kw40z4,
         'k20d50m': Flash_k20d50m,
         'k22f': Flash_k22f,
         'k64f': Flash_k64f,
         'k66f18': Flash_k66f18,
         'k82f25615': Flash_k82f25615,
         'lpc800': Flash_lpc800,
         'lpc11u24': Flash_lpc11u24,
         'lpc1768':  Flash_lpc1768,
         'lpc4330':  Flash_lpc4330,
         'nrf51': Flash_nrf51,
         'nrf52': Flash_nrf52,
         'stm32f103rc': Flash_stm32f103rc,
         'stm32f051': Flash_stm32f051,
         'maxwsnenv': Flash_maxwsnenv,
         'max32600mbed': Flash_max32600mbed,
         'w7500': Flash_w7500,
         'lpc11xx_32': Flash_lpc11xx_32,
         'lpc824': Flash_lpc824,
         'lpc4088': Flash_lpc4088,
         'ncs36510': Flash_ncs36510, 
         'lpc4088qsb': Flash_lpc4088qsb_dm,
         'lpc4088dm': Flash_lpc4088qsb_dm,
         }
