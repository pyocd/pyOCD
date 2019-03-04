# pyOCD debugger
# Copyright (c) 2013-2019 Arm Limited
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

from ...core.coresight_target import CoreSightTarget
from ..family import target_kinetis
from . import target_MIMXRT1021xxxxx
from . import target_MIMXRT1052xxxxB
from . import target_MKE15Z256xxx7
from . import target_MKE18F256xxx16
from . import target_MKL02Z32xxx4
from . import target_MKL05Z32xxx4
from . import target_MKL25Z128xxx4
from . import target_MKL26Z256xxx4
from . import target_MKL27Z256xxx4
from . import target_MKL28Z512xxx7
from . import target_MKL43Z256xxx4
from . import target_MKL46Z256xxx4
from . import target_MKL82Z128xxx7
from . import target_MKV10Z128xxx7
from . import target_MKV11Z128xxx7
from . import target_MKW01Z128xxx4
from . import target_MKW24D512xxx5
from . import target_MKW36Z512xxx4
from . import target_MKW40Z160xxx4
from . import target_MKW41Z512xxx4
from . import target_MK22FN1M0Axxx12
from . import target_MK22FN512xxx12
from . import target_MK28FN2M0xxx15
from . import target_MK64FN1M0xxx12
from . import target_MK66FN2M0xxx18
from . import target_MK82FN256xxx15
from . import target_MK20DX128xxx5
from . import target_K32W042S1M2xxx
from . import target_lpc800
from . import target_LPC11U24FBD64_401
from . import target_LPC1768
from . import target_LPC4330
from . import target_nRF51822_xxAA
from . import target_nRF52832_xxAA
from . import target_nRF52840_xxAA
from . import target_STM32F103RC
from . import target_STM32F051T8
from . import target_STM32F412xx
from . import target_STM32F429xx
from . import target_STM32F439xx
from . import target_STM32L475xx
from . import target_STM32L031x6
from . import target_MAX32600
from . import target_MAX32620
from . import target_MAX32625
from . import target_MAX32630
from . import target_w7500
from . import target_LPC1114FN28_102
from . import target_LPC824M201JHI33
from . import target_LPC54114J256BD64
from . import target_LPC54608J512ET180
from . import target_ncs36510
from . import target_LPC4088FBD144
from . import target_lpc4088qsb
from . import target_lpc4088dm
from . import target_RTL8195AM
from . import target_CC3220SF
from . import target_CC3220SF
from . import target_CY8C6xxA
from . import target_CY8C6xx7
from . import target_musca_a1
from . import target_musca_b1
from . import target_LPC55S69JBD100

## @brief Dictionary of all builtin targets.
BUILTIN_TARGETS = {
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
          'kw24d5': target_MKW24D512xxx5.KW24D5,
          'kw36z4': target_MKW36Z512xxx4.KW36Z4,
          'kw40z4': target_MKW40Z160xxx4.KW40Z4,
          'kw41z4': target_MKW41Z512xxx4.KW41Z4,
          'k20d50m': target_MK20DX128xxx5.K20D50M,
          'k22fa12': target_MK22FN1M0Axxx12.K22FA12,
          'k22f': target_MK22FN512xxx12.K22F,
          'k28f15': target_MK28FN2M0xxx15.K28F15,
          'k64f': target_MK64FN1M0xxx12.K64F,
          'k66f18': target_MK66FN2M0xxx18.K66F18,
          'k82f25615': target_MK82FN256xxx15.K82F25615,
          'k32w042s': target_K32W042S1M2xxx.K32W042S,
          'lpc800': target_lpc800.LPC800,
          'lpc11u24': target_LPC11U24FBD64_401.LPC11U24,
          'lpc1768': target_LPC1768.LPC1768,
          'lpc4330': target_LPC4330.LPC4330,
          'max32600': target_MAX32600.MAX32600,
          'max32620': target_MAX32620.MAX32620,
          'max32625': target_MAX32625.MAX32625,
          'max32630': target_MAX32630.MAX32630,
          'mimxrt1020': target_MIMXRT1021xxxxx.MIMXRT1021xxxxx,
          'mimxrt1050_quadspi': target_MIMXRT1052xxxxB.MIMXRT1052xxxxB_quadspi,
          'mimxrt1050_hyperflash': target_MIMXRT1052xxxxB.MIMXRT1052xxxxB_hyperflash,
          'mimxrt1050': target_MIMXRT1052xxxxB.MIMXRT1052xxxxB_hyperflash, # Alias for default external flash.
          'nrf51': target_nRF51822_xxAA.NRF51,
          'nrf52' : target_nRF52832_xxAA.NRF52,
          'nrf52840' : target_nRF52840_xxAA.NRF52840,
          'stm32f103rc': target_STM32F103RC.STM32F103RC,
          'stm32f051': target_STM32F051T8.STM32F051,
          'stm32f412xe' : target_STM32F412xx.STM32F412xE,
          'stm32f412xg' : target_STM32F412xx.STM32F412xG,
          'stm32f429xg' : target_STM32F429xx.STM32F429xG,
          'stm32f429xi' : target_STM32F429xx.STM32F429xI,
          'stm32f439xg' : target_STM32F439xx.STM32F439xG,
          'stm32f439xi' : target_STM32F439xx.STM32F439xI,
          'stm32l475xc' : target_STM32L475xx.STM32L475xC,
          'stm32l475xe' : target_STM32L475xx.STM32L475xE,
          'stm32l475xg' : target_STM32L475xx.STM32L475xG,
          'stm32l031x6' : target_STM32L031x6.STM32L031x6,
          'w7500': target_w7500.W7500,
          'lpc11xx_32': target_LPC1114FN28_102.LPC11XX_32,
          'lpc824': target_LPC824M201JHI33.LPC824,
          'lpc54114': target_LPC54114J256BD64.LPC54114,
          'lpc54608': target_LPC54608J512ET180.LPC54608,
          'lpc4088': target_LPC4088FBD144.LPC4088,
          'ncs36510': target_ncs36510.NCS36510,
          'lpc4088qsb': target_lpc4088qsb.LPC4088qsb,
          'lpc4088dm': target_lpc4088dm.LPC4088dm,
          'rtl8195am': target_RTL8195AM.RTL8195AM,
          'cc3220sf': target_CC3220SF.CC3220SF,
          'cy8c6xxa': target_CY8C6xxA.CY8C6xxA,
          'cy8c6xx7': target_CY8C6xx7.CY8C6xx7,
          'musca_a1' : target_musca_a1.MuscaA1,
          'musca_b1' : target_musca_b1.MuscaB1,
          'lpc55s69' : target_LPC55S69JBD100.LPC55S69JBD100,
         }
