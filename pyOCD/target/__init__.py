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

import cortex_m
import target_kinetis
import target_kl02z
import target_kl05z
import target_kl25z
import target_kl26z
import target_kl28z
import target_kl46z
import target_k22f
import target_k64f
import target_k20d50m
import target_lpc800
import target_lpc11u24
import target_lpc1768
import target_lpc4330
import target_nrf51
import target_nrf52
import target_stm32f103rc
import target_stm32f051
import target_maxwsnenv
import target_max32600mbed
import target_w7500
import target_lpc11xx_32
import target_lpc824
import semihost

TARGET = {
          'cortex_m': cortex_m.CortexM,
          'kinetis': target_kinetis.Kinetis,
          'kl02z': target_kl02z.KL02Z,
          'kl05z': target_kl05z.KL05Z,
          'kl25z': target_kl25z.KL25Z,
          'kl26z': target_kl26z.KL26Z,
          'kl28z': target_kl28z.KL28x,
          'kl46z': target_kl46z.KL46Z,
          'k20d50m': target_k20d50m.K20D50M,
          'k22f': target_k22f.K22F,
          'k64f': target_k64f.K64F,
          'lpc800': target_lpc800.LPC800,
          'lpc11u24': target_lpc11u24.LPC11U24,
          'lpc1768': target_lpc1768.LPC1768,
          'lpc4330': target_lpc4330.LPC4330,
          'nrf51': target_nrf51.NRF51,
          'nrf52' : target_nrf52.NRF52,
          'stm32f103rc': target_stm32f103rc.STM32F103RC,
          'stm32f051': target_stm32f051.STM32F051,
          'maxwsnenv': target_maxwsnenv.MAXWSNENV,
          'max32600mbed': target_max32600mbed.MAX32600MBED,
          'w7500': target_w7500.W7500,
          'lpc11xx_32': target_lpc11xx_32.LPC11XX_32,
          'lpc824': target_lpc824.LPC824,
         }
