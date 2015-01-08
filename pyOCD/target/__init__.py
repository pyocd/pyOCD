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
import target_kl46z
import target_k22f
import target_k64f
import target_k20d50m
import target_lpc800
import target_lpc11u24
import target_lpc1768
import target_lpc4330
import target_nrf51822
import target_stm32f103rc
import target_stm32f051

TARGET = {
          'cortex_m': cortex_m.CortexM,
          'target_kinetis': target_kinetis.Kinetis,
          'target_kl02z': target_kl02z.KL02Z,
          'target_kl05z': target_kl05z.KL05Z,
          'target_kl25z': target_kl25z.KL25Z,
          'target_kl26z': target_kl26z.KL26Z,
          'target_kl46z': target_kl46z.KL46Z,
          'target_k20d50m': target_k20d50m.K20D50M,
          'target_k22f': target_k22f.K22F,
          'target_k64f': target_k64f.K64F,
          'target_lpc800': target_lpc800.LPC800,
          'target_lpc11u24': target_lpc11u24.LPC11U24,
          'target_lpc1768': target_lpc1768.LPC1768,
          'target_lpc4330': target_lpc4330.LPC4330,
          'target_nrf51822': target_nrf51822.NRF51822,
          'target_stm32f103rc': target_stm32f103rc.STM32F103RC,
          'target_stm32f051': target_stm32f051.STM32F051,          
         }
