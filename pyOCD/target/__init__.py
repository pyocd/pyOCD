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

from ..core.coresight_target import CoreSightTarget
from .family import (target_kinetis, flash_cortex_m)
import target_MKE15Z256xxx7
import target_MKE18F256xxx16
import target_MKL02Z32xxx4
import target_MKL05Z32xxx4
import target_MKL25Z128xxx4
import target_MKL26Z256xxx4
import target_MKL27Z256xxx4
import target_MKL28Z512xxx7
import target_MKL43Z256xxx4
import target_MKL46Z256xxx4
import target_MKL82Z128xxx7
import target_MKV10Z128xxx7
import target_MKV11Z128xxx7
import target_MKW01Z128xxx4
import target_MKW40Z160xxx4
import target_MKW41Z512xxx4
import target_MK22FN1M0Axxx12
import target_MK22FN512xxx12
import target_MK28FN2M0xxx15
import target_MK64FN1M0xxx12
import target_MK66FN2M0xxx18
import target_MK82FN256xxx15
import target_MK20DX128xxx5
import target_lpc800
import target_LPC11U24FBD64_401
import target_LPC1768
import target_LPC4330
import target_nRF51822_xxAA
import target_nRF52832_xxAA
import target_nRF52840_xxAA
import target_STM32F103RC
import target_STM32F051T8
import target_maxwsnenv
import target_max32600mbed
import target_w7500
import target_LPC1114FN28_102
import target_LPC824M201JHI33
import target_LPC54114J256BD64
import target_ncs36510
import target_LPC4088FBD144
import target_lpc4088qsb
import target_lpc4088dm
import target_RTL8195AM

TARGET = {
          'cortex_m': CoreSightTarget,
          'kinetis': target_kinetis.Kinetis,
          'ke15z7': target_MKE15Z256xxx7.KE15Z7,
          'ke18f16': target_MKE18F256xxx16.KE18F16,
          'kl02z': target_MKL02Z32xxx4.KL02Z,
          'kl05z': target_MKL05Z32xxx4.KL05Z,
          'kl25z': target_MKL25Z128xxx4.KL25Z,
          'kl26z': target_MKL26Z256xxx4.KL26Z,
          'kl27z4': target_MKL27Z256xxx4.KL27Z4,
          'kl28z': target_MKL28Z512xxx7.KL28x,
          'kl43z4': target_MKL43Z256xxx4.KL43Z4,
          'kl46z': target_MKL46Z256xxx4.KL46Z,
          'kl82z7': target_MKL82Z128xxx7.KL82Z7,
          'kv10z7': target_MKV10Z128xxx7.KV10Z7,
          'kv11z7': target_MKV11Z128xxx7.KV11Z7,
          'kw01z4': target_MKW01Z128xxx4.KW01Z4,
          'kw40z4': target_MKW40Z160xxx4.KW40Z4,
          'kw41z4': target_MKW41Z512xxx4.KW41Z4,
          'k20d50m': target_MK20DX128xxx5.K20D50M,
          'k22fa12': target_MK22FN1M0Axxx12.K22FA12,
          'k22f': target_MK22FN512xxx12.K22F,
          'k28f15': target_MK28FN2M0xxx15.K28F15,
          'k64f': target_MK64FN1M0xxx12.K64F,
          'k66f18': target_MK66FN2M0xxx18.K66F18,
          'k82f25615': target_MK82FN256xxx15.K82F25615,
          'lpc800': target_lpc800.LPC800,
          'lpc11u24': target_LPC11U24FBD64_401.LPC11U24,
          'lpc1768': target_LPC1768.LPC1768,
          'lpc4330': target_LPC4330.LPC4330,
          'nrf51': target_nRF51822_xxAA.NRF51,
          'nrf52' : target_nRF52832_xxAA.NRF52,
          'nrf52840' : target_nRF52840_xxAA.NRF52840,
          'stm32f103rc': target_STM32F103RC.STM32F103RC,
          'stm32f051': target_STM32F051T8.STM32F051,
          'maxwsnenv': target_maxwsnenv.MAXWSNENV,
          'max32600mbed': target_max32600mbed.MAX32600MBED,
          'w7500': target_w7500.W7500,
          'lpc11xx_32': target_LPC1114FN28_102.LPC11XX_32,
          'lpc824': target_LPC824M201JHI33.LPC824,
          'lpc54114': target_LPC54114J256BD64.LPC54114,
          'lpc4088': target_LPC4088FBD144.LPC4088,
          'ncs36510': target_ncs36510.NCS36510,
          'lpc4088qsb': target_lpc4088qsb.LPC4088qsb,
          'lpc4088dm': target_lpc4088dm.LPC4088dm,
          'rtl8195am': target_RTL8195AM.RTL8195AM,
         }

FLASH = {
         'cortex_m': flash_cortex_m.Flash_cortex_m,
         'kinetis': flash_cortex_m.Flash_cortex_m,
         'ke15z7': target_MKE15Z256xxx7.Flash_ke15z7,
         'ke18f16': target_MKE18F256xxx16.Flash_ke18f16,
         'kl02z': target_MKL02Z32xxx4.Flash_kl02z,
         'kl05z': target_MKL05Z32xxx4.Flash_kl05z,
         'kl25z': target_MKL25Z128xxx4.Flash_kl25z,
         'kl26z': target_MKL26Z256xxx4.Flash_kl26z,
         'kl27z4': target_MKL27Z256xxx4.Flash_kl27z4,
         'kl28z': target_MKL28Z512xxx7.Flash_kl28z,
         'kl43z4': target_MKL43Z256xxx4.Flash_kl43z4,
         'kl46z': target_MKL46Z256xxx4.Flash_kl46z,
         'kl82z7': target_MKL82Z128xxx7.Flash_mkl82z7,
         'kv10z7': target_MKV10Z128xxx7.Flash_kv10z7,
         'kv11z7': target_MKV11Z128xxx7.Flash_kv11z7,
         'kw01z4': target_MKW01Z128xxx4.Flash_kw01z4,
         'kw40z4': target_MKW40Z160xxx4.Flash_kw40z4,
         'kw41z4': target_MKW41Z512xxx4.Flash_kw41z4,
         'k20d50m': target_MK20DX128xxx5.Flash_k20d50m,
         'k22fa12': target_MK22FN1M0Axxx12.Flash_k22fa12,
         'k22f': target_MK22FN512xxx12.Flash_k22f,
         'k28f15': target_MK28FN2M0xxx15.Flash_k28f15,
         'k64f': target_MK64FN1M0xxx12.Flash_k64f,
         'k66f18': target_MK66FN2M0xxx18.Flash_k66f18,
         'k82f25615': target_MK82FN256xxx15.Flash_k82f25615,
         'lpc800': target_lpc800.Flash_lpc800,
         'lpc11u24': target_LPC11U24FBD64_401.Flash_lpc11u24,
         'lpc1768':  target_LPC1768.Flash_lpc1768,
         'lpc4330':  target_LPC4330.Flash_lpc4330,
         'nrf51': target_nRF51822_xxAA.Flash_nrf51,
         'nrf52': target_nRF52832_xxAA.Flash_nrf52,
         'nrf52840': target_nRF52840_xxAA.Flash_nrf52840,
         'stm32f103rc': target_STM32F103RC.Flash_stm32f103rc,
         'stm32f051': target_STM32F051T8.Flash_stm32f051,
         'maxwsnenv': target_maxwsnenv.Flash_maxwsnenv,
         'max32600mbed': target_max32600mbed.Flash_max32600mbed,
         'w7500': target_w7500.Flash_w7500,
         'lpc11xx_32': target_LPC1114FN28_102.Flash_lpc11xx_32,
         'lpc824': target_LPC824M201JHI33.Flash_lpc824,
         'lpc4088': target_LPC4088FBD144.Flash_lpc4088,
         'lpc54114': target_LPC54114J256BD64.Flash_lpc54114,
         'ncs36510': target_ncs36510.Flash_ncs36510,
         'lpc4088qsb': target_lpc4088qsb.Flash_lpc4088qsb_dm,
         'lpc4088dm': target_lpc4088dm.Flash_lpc4088qsb_dm,
         'rtl8195am': target_RTL8195AM.Flash_rtl8195am,
         }
