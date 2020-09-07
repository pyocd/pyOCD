# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

from time import sleep
import logging

from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from ...coresight.cortex_m import CortexM
from ...coresight.cortex_m_v8m import CortexM_v8M
from ...debug.svd.loader import SVDFile
from ...utility import timeout

FPB_CTRL                = 0xE0002000
FPB_COMP0               = 0xE0002008
DWT_COMP0               = 0xE0001020
DWT_FUNCTION0           = 0xE0001028
DWT_FUNCTION_MATCH      = 0x4 << 0   # Instruction address.
DWT_FUNCTION_ACTION     = 0x1 << 4   # Generate debug event.
DWT_FUNCTION_DATAVSIZE  = 0x2 << 10  # 4 bytes.

PERIPHERAL_BASE_NS = 0x40000000
PERIPHERAL_BASE_S  = 0x50000000

FLASH_CMD               = 0x00034000
FLASH_STARTA            = 0x00034010
FLASH_STOPA             = 0x00034014
FLASH_DATAW0            = 0x00034080
FLASH_INT_STATUS        = 0x00034FE0
FLASH_INT_CLR_STATUS    = 0x00034FE8
FLASH_CMD_READ_SINGLE_WORD = 0x3

BOOTROM_MAGIC_ADDR      = 0x50000040

LOG = logging.getLogger(__name__)

class LPC5500Family(CoreSightTarget):

    VENDOR = "NXP"

    def create_init_sequence(self):
        seq = super(LPC5500Family, self).create_init_sequence()
        
        seq.wrap_task('discovery',
            lambda seq: seq
                    .wrap_task('find_components', self._modify_ap1) \
                    .replace_task('create_cores', self.create_lpc55xx_cores) \
                    .insert_before('create_components',
                        ('enable_traceclk', self._enable_traceclk),
                        )
            )
        
        return seq
    
    def _modify_ap1(self, seq):
        # If AP#1 exists we need to adjust it before we can read the ROM.
        if seq.has_task('init_ap.1'):
            seq.insert_before('init_ap.1',
                ('set_ap1_nonsec',        self._set_ap1_nonsec),
                )
        
        return seq

    def _set_ap1_nonsec(self):
        # Make AP#1 transactions non-secure so transfers will succeed.
        self.aps[1].hnonsec = 1

    def create_lpc55xx_cores(self):
        # Make sure AP#0 was detected.
        if 0 not in self.aps:
            LOG.error("AP#0 was not found, unable to create core 0")
            return

        # Create core 0 with a custom class.
        core0 = CortexM_LPC5500(self.session, self.aps[0], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[0].core = core0
        core0.init()
        self.add_core(core0)
        
        # Create core 1 if the AP is present. It uses the standard Cortex-M core class for v8-M.
        if 1 in self.aps:
            core1 = CortexM_v8M(self.session, self.aps[1], self.memory_map, 1)
            core1.default_reset_type = self.ResetType.SW_SYSRESETREQ
            self.aps[1].core = core1
            core1.init()
            self.add_core(core1)
    
    def _enable_traceclk(self):
        # Don't make it worse if no APs were found.
        if 0 not in self.aps:
            return
        
        SYSCON_NS_Base_Addr = 0x40000000
        IOCON_NS_Base_Addr  = 0x40001000
        TRACECLKSEL_Addr    = SYSCON_NS_Base_Addr + 0x268
        TRACECLKDIV_Addr    = SYSCON_NS_Base_Addr + 0x308
        AHBCLKCTRLSET0_Addr = IOCON_NS_Base_Addr  + 0x220
        
        clksel = self.read32(TRACECLKSEL_Addr)  # Read current TRACECLKSEL value
        if clksel > 2:
            self.write32(TRACECLKSEL_Addr, 0x0) # Select Trace divided clock
        
        clkdiv = self.read32(TRACECLKDIV_Addr) & 0xFF # Read current TRACECLKDIV value, preserve divider but clear rest to enable
        self.write32(TRACECLKDIV_Addr, clkdiv)

        self.write32(AHBCLKCTRLSET0_Addr, (1 << 13)) # Enable IOCON clock

    def trace_start(self):
        # Configure PIO0_10: FUNC - 6, MODE - 0, SLEW - 1, INVERT - 0, DIGMODE - 0, OD - 0
        self.write32(0x40001028, 0x00000046)
        
        self.call_delegate('trace_start', target=self, mode=0)

        # On a reset when ITM is enabled, TRACECLKDIV/TRACECLKSEL will be reset
        # even though ITM will remain enabled -- which will cause ITM stimulus
        # writes to hang in the target because the FIFO will never appear ready.
        # To prevent this, we explicitly (re)enable traceclk.
        self._enable_traceclk()

class CortexM_LPC5500(CortexM_v8M):

    def reset_and_halt(self, reset_type=None):
        """! @brief Perform a reset and stop the core on the reset handler. """
        
        catch_mode = 0
        
        delegateResult = self.call_delegate('set_reset_catch', core=self, reset_type=reset_type)
        
        # Save CortexM.DEMCR
        demcr = self.read_memory(CortexM.DEMCR)

        # enable the vector catch
        if not delegateResult:
            # This sequence is copied from the NXP LPC55S69_DFP debug sequence.
            reset_vector = 0xFFFFFFFF
            
            # Clear reset vector catch.
            self.write32(CortexM.DEMCR, demcr & ~CortexM.DEMCR_VC_CORERESET)
            
            # If the processor is in Secure state, we have to access the flash controller
            # through the secure alias.
            if self.get_security_state() == Target.SecurityState.SECURE:
                base = PERIPHERAL_BASE_S
            else:
                base = PERIPHERAL_BASE_NS
            
            # Use the flash programming model to check if the first flash page is readable, since
            # attempted accesses to erased pages result in bus faults. The start and stop address
            # are both set to 0x0 to probe the sector containing the reset vector.
            self.write32(base + FLASH_STARTA, 0x00000000) # Program flash word start address to 0x0
            self.write32(base + FLASH_STOPA, 0x00000000) # Program flash word stop address to 0x0
            self.write_memory_block32(base + FLASH_DATAW0, [0x00000000] * 8) # Prepare for read
            self.write32(base + FLASH_INT_CLR_STATUS, 0x0000000F) # Clear Flash controller status
            self.write32(base + FLASH_CMD, FLASH_CMD_READ_SINGLE_WORD) # Read single flash word

            # Wait for flash word read to finish.
            with timeout.Timeout(5.0) as t_o:
                while t_o.check():
                    if (self.read32(base + FLASH_INT_STATUS) & 0x00000004) != 0:
                        break
                    sleep(0.01)
            
            # Check for error reading flash word.
            if (self.read32(base + FLASH_INT_STATUS) & 0xB) == 0:
                 # Read the reset vector address.
                reset_vector = self.read32(0x00000004)

            # Break on user application reset vector if we have a valid breakpoint address.
            if reset_vector != 0xFFFFFFFF:
                catch_mode = 1
                self.write32(FPB_COMP0, reset_vector|1) # Program FPB Comparator 0 with reset handler address
                self.write32(FPB_CTRL, 0x00000003)    # Enable FPB
            # No valid user application so use watchpoint to break at end of boot ROM. The ROM
            # writes a special address to signal when it's done.
            else:
                catch_mode = 2
                self.write32(DWT_FUNCTION0, 0)
                self.write32(DWT_COMP0, BOOTROM_MAGIC_ADDR)
                self.write32(DWT_FUNCTION0, (DWT_FUNCTION_MATCH | DWT_FUNCTION_ACTION | DWT_FUNCTION_DATAVSIZE))

            # Read DHCSR to clear potentially set DHCSR.S_RESET_ST bit
            self.read32(CortexM.DHCSR)

        self.reset(reset_type)

        # wait until the unit resets
        with timeout.Timeout(2.0) as t_o:
            while t_o.check():
                if self.get_state() not in (Target.State.RESET, Target.State.RUNNING):
                    break
                sleep(0.01)

        # Make sure the thumb bit is set in XPSR in case the reset handler
        # points to an invalid address.
        xpsr = self.read_core_register('xpsr')
        if xpsr is not None and xpsr & self.XPSR_THUMB == 0:
            self.write_core_register('xpsr', xpsr | self.XPSR_THUMB)

        self.call_delegate('clear_reset_catch', core=self, reset_type=reset_type)

        # Clear breakpoint or watchpoint.
        if catch_mode == 1:
            self.write32(0xE0002008, 0)
        elif catch_mode == 2:
            self.write32(DWT_COMP0, 0)
            self.write32(DWT_FUNCTION0, 0)

        # restore vector catch setting
        self.write_memory(CortexM.DEMCR, demcr)
