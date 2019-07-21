# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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

from ...core.target import Target
from ...core.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, RomRegion, MemoryMap)
from ...coresight.cortex_m import CortexM
from ...coresight.cortex_m_v8m import CortexM_v8M
from ...debug.svd.loader import SVDFile
from ...utility import timeout

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0xf240b580, 0xf2c00004, 0xf6420000, 0xf84961e0, 0xf2401000, 0xf2c52000, 0x21000000, 0x1080f8c0,
    0x1084f8c0, 0x1180f8c0, 0x71fbf647, 0xf6406001, 0x21ff6004, 0x0000f2c5, 0x01def2cc, 0xf04f6001,
    0x210240a0, 0xf2407001, 0xf2c0000c, 0x44480000, 0xf876f000, 0xbf182800, 0xbd802001, 0x47702000,
    0xf240b580, 0xf2c0000c, 0xf2460000, 0x4448636c, 0x3365f6c6, 0xf44f2100, 0xf0002218, 0x2800f883,
    0x2001bf18, 0xbf00bd80, 0xf020b580, 0xf2404170, 0xf2c0000c, 0xf2460000, 0x4448636c, 0x3365f6c6,
    0x4200f44f, 0xf86ef000, 0xbf182800, 0xbd802001, 0x460db570, 0x71fff647, 0x42084614, 0x4670f020,
    0xf240d10d, 0xf2c0000c, 0xf2460000, 0x4448636c, 0x3365f6c6, 0x4200f44f, 0xf0004631, 0xf5b5f853,
    0xf2407f00, 0xbf98000c, 0x7500f44f, 0xf2c04631, 0x44480000, 0x462b4622, 0xf86cf000, 0xbf182800,
    0xbd702001, 0x460cb5b0, 0xf0204605, 0x46114070, 0xf0004622, 0x2800f9e9, 0x4425bf08, 0xbdb04628,
    0x460ab580, 0x4170f020, 0x000cf240, 0x0000f2c0, 0xf0004448, 0x2800f877, 0x2001bf18, 0x0000bd80,
    0x1100f241, 0x3100f2c1, 0x29006809, 0xf240d00d, 0xf2c00208, 0x23000200, 0x3002f849, 0xf3c3680b,
    0xf8492307, 0x68493002, 0xf2404708, 0xf2c04084, 0xf2400000, 0xf2c04191, 0x44780100, 0x226d4479,
    0xf972f000, 0x0c08f240, 0x0c00f2c0, 0xc00cf859, 0x0f00f1bc, 0xf241d00b, 0xf2c11c00, 0xf8dc3c00,
    0xf1bcc000, 0xd0070f00, 0xc008f8dc, 0xf2444760, 0xf2c11c3b, 0x47603c00, 0x4036f240, 0x0000f2c0,
    0x4143f240, 0x0100f2c0, 0x44794478, 0xf000227d, 0xbf00f94b, 0x0c08f240, 0x0c00f2c0, 0xc00cf859,
    0x0f00f1bc, 0xf241d00b, 0xf2c11c00, 0xf8dc3c00, 0xf1bcc000, 0xd0070f00, 0xc00cf8dc, 0xf2444760,
    0xf2c11c9d, 0x47603c00, 0x30e6f240, 0x0000f2c0, 0x31f3f240, 0x0100f2c0, 0x44794478, 0xf000228c,
    0xbf00f923, 0x1300f241, 0x3300f2c1, 0x2b00681b, 0x691bd001, 0xf2404718, 0xf2c030b8, 0xf2400000,
    0xf2c031c5, 0x44780100, 0x22954479, 0xf90cf000, 0x0c08f240, 0x0c00f2c0, 0xc00cf859, 0x0f00f1bc,
    0xf241d00b, 0xf2c11c00, 0xf8dc3c00, 0xf1bcc000, 0xd0070f00, 0xc014f8dc, 0xf2444760, 0xf2c12c7d,
    0x47603c00, 0x306af240, 0x0000f2c0, 0x3177f240, 0x0100f2c0, 0x44794478, 0xf00022a8, 0xbf00f8e5,
    0x1300f241, 0x3300f2c1, 0x2b00681b, 0x699bd001, 0xf2404718, 0xf2c0303c, 0xf2400000, 0xf2c03149,
    0x44780100, 0x22b24479, 0xf8cef000, 0x1100f241, 0x3100f2c1, 0x29006809, 0x69c9d001, 0xf2404708,
    0xf2c03010, 0xf2400000, 0xf2c0311d, 0x44780100, 0x22bc4479, 0xf8b8f000, 0x1100f241, 0x3100f2c1,
    0x29006809, 0x6a09d001, 0xf2404708, 0xf2c020e4, 0xf2400000, 0xf2c021f1, 0x44780100, 0x22c34479,
    0xf8a2f000, 0x1300f241, 0x3300f2c1, 0x2b00681b, 0x6a5bd001, 0xf2404718, 0xf2c020b8, 0xf2400000,
    0xf2c021c5, 0x44780100, 0x22ca4479, 0xf88cf000, 0x1c00f241, 0x3c00f2c1, 0xc000f8dc, 0x0f00f1bc,
    0xf8dcd002, 0x4760c02c, 0x2086f240, 0x0000f2c0, 0x2193f240, 0x0100f2c0, 0x44794478, 0xf00022d1,
    0xbf00f873, 0x1200f241, 0x3200f2c1, 0x2a006812, 0x6b12d001, 0xf2404710, 0xf2c02058, 0xf2400000,
    0xf2c02165, 0x44780100, 0x22d84479, 0xf85cf000, 0x1200f241, 0x3200f2c1, 0x2a006812, 0x6b52d001,
    0xf2404710, 0xf2c0202c, 0xf2400000, 0xf2c02139, 0x44780100, 0x22df4479, 0xf846f000, 0x1300f241,
    0x3300f2c1, 0x2b00681b, 0x6b9bd001, 0xf2404718, 0xf2c02000, 0xf2400000, 0xf2c0210d, 0x44780100,
    0x22e64479, 0xf830f000, 0x1200f241, 0x3200f2c1, 0x2a006812, 0x6a92d001, 0xf2404710, 0xf2c010d4,
    0xf2400000, 0xf2c011e1, 0x44780100, 0x22ed4479, 0xf81af000, 0x1c00f241, 0x3c00f2c1, 0xc000f8dc,
    0x0f00f1bc, 0xf8dcd002, 0x4760c040, 0x10a2f240, 0x0000f2c0, 0x11aff240, 0x0100f2c0, 0x44794478,
    0xf00022f4, 0x0000f801, 0x4605b50e, 0x460e4614, 0xf000a013, 0x4628f870, 0xf86df000, 0xf000a016,
    0x4630f86a, 0xf867f000, 0xf000a015, 0x2100f864, 0x100bf88d, 0xf10d210a, 0xf88d000a, 0xe008100a,
    0xf2f1fb94, 0x4212fb01, 0xf4f1fb94, 0xf8003230, 0x2c002d01, 0xf000dcf4, 0xf000f84e, 0x0000f841,
    0x202a2a2a, 0x65737361, 0x6f697472, 0x6166206e, 0x64656c69, 0x0000203a, 0x6966202c, 0x0020656c,
    0x696c202c, 0x0020656e, 0x0301ea40, 0x079bb510, 0x2a04d10f, 0xc810d30d, 0x1f12c908, 0xd0f8429c,
    0xba19ba20, 0xd9014288, 0xbd102001, 0x30fff04f, 0xb11abd10, 0xd00307d3, 0xe0071c52, 0xbd102000,
    0x3b01f810, 0x4b01f811, 0xd1071b1b, 0x3b01f810, 0x4b01f811, 0xd1011b1b, 0xd1f11e92, 0xbd104618,
    0x2000b510, 0xf81ef000, 0x8000f3af, 0x4010e8bd, 0xf0002001, 0xb510b811, 0xe0024604, 0xf0001c64,
    0x7820f804, 0xd1f92800, 0xb508bd10, 0xf88d4669, 0x20030000, 0xbd08beab, 0x20184901, 0xe7febeab,
    0x00020026, 0xf000b510, 0xe8bdf80b, 0xf0004010, 0x4770b801, 0xd0012800, 0xbfeef7ff, 0x00004770,
    0x2100b510, 0xf000a002, 0x2001f813, 0x0000bd10, 0x41474953, 0x3a545242, 0x6e624120, 0x616d726f,
    0x6574206c, 0x6e696d72, 0x6f697461, 0x0000006e, 0x4605b570, 0x200a460c, 0x1c6de000, 0xffc5f7ff,
    0x7828b135, 0xd1f82800, 0x1c64e002, 0xffbdf7ff, 0x7820b114, 0xd1f82800, 0x4070e8bd, 0xf7ff200a,
    0x4c46bfb4, 0x5f485341, 0x5f495041, 0x45455254, 0x70616900, 0x73662f31, 0x61695f6c, 0x632e3170,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000021,
    'pc_unInit': 0x2000007d,
    'pc_program_page': 0x200000d1,
    'pc_erase_sector': 0x200000a9,
    'pc_eraseAll': 0x20000081,

    'static_base' : 0x20000000 + 0x00000020 + 0x00000624,
    'begin_stack' : 0x20000900,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x200,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001200],   # Enable double buffering
    'min_program_length' : 0x200,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x98000,
    'sector_sizes': (
        (0x0, 0x8000),
    )
}

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

class LPC55S69JBD100(CoreSightTarget):

    memoryMap = MemoryMap(
        FlashRegion(name='nsflash',     start=0x00000000, length=0x00098000, access='rx',
            blocksize=0x200,
            is_boot_memory=True,
            are_erased_sectors_readable=False,
            algo=FLASH_ALGO),
        RomRegion(  name='nsrom',       start=0x03000000, length=0x00020000, access='rx'),
        RamRegion(  name='nscoderam',   start=0x04000000, length=0x00008000, access='rwx'),
        FlashRegion(name='sflash',      start=0x10000000, length=0x00098000, access='rx',
            blocksize=0x200,
            is_boot_memory=True,
            are_erased_sectors_readable=False,
            algo=FLASH_ALGO,
            alias='nsflash'),
        RomRegion(  name='srom',        start=0x13000000, length=0x00020000, access='srx',
            alias='nsrom'),
        RamRegion(  name='scoderam',    start=0x14000000, length=0x00008000, access='srwx',
            alias='nscoderam'),
        RamRegion(  name='nsram',       start=0x20000000, length=0x00044000, access='rwx'),
        RamRegion(  name='sram',        start=0x30000000, length=0x00044000, access='srwx',
            alias='nsram'),
        )

    def __init__(self, link):
        super(LPC55S69JBD100, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile.from_builtin("LPC55S69_cm33_core0.xml")

    def create_init_sequence(self):
        seq = super(LPC55S69JBD100, self).create_init_sequence()
        
        seq.wrap_task('init_ap_roms', self._modify_ap1)
        seq.replace_task('create_cores', self.create_lpc55s69_cores)
        seq.insert_before('create_components',
            ('enable_traceclk',        self._enable_traceclk),
            )
        
        return seq
    
    def _modify_ap1(self, seq):
        seq.insert_before('init_ap.1',
            ('set_ap1_nonsec',        self._set_ap1_nonsec),
            )
        
        return seq

    def _set_ap1_nonsec(self):
        self.aps[1].hnonsec = 1

    def create_lpc55s69_cores(self):
        # Create core 0 with a custom class.
        core0 = CortexM_LPC55S69(self.session, self.aps[0], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[0].core = core0
        core0.init()
        self.add_core(core0)
        
        core1 = CortexM_v8M(self.session, self.aps[1], self.memory_map, 1)
        core1.default_reset_type = self.ResetType.SW_SYSRESETREQ
        self.aps[1].core = core1
        core1.init()
        self.add_core(core1)
    
    def _enable_traceclk(self):
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

class CortexM_LPC55S69(CortexM_v8M):

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
                if self.get_state() not in (Target.TARGET_RESET, Target.TARGET_RUNNING):
                    break
                sleep(0.01)

        # Make sure the thumb bit is set in XPSR in case the reset handler
        # points to an invalid address.
        xpsr = self.read_core_register('xpsr')
        if xpsr & self.XPSR_THUMB == 0:
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
