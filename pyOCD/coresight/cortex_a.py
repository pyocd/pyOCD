"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2017 ARM Limited

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
from ..core.target import Target
from .cortex_target import CortexTarget
import time

def MCR(cp, opc1, core_reg, cp_reg_n, cp_reg_m, opc_2=0):
    """
    Assemble a MCR instruction (move from core register to coprocessor
    register) for ARMv7.

    See ARMv7 A/R Architecture Manual A8.8.98 
    """
    inst =  (cp & 0xf) << 8
    inst |= (opc1 & 0x7) << 21
    inst |= (core_reg & 0xf) << 12
    inst |= (cp_reg_n & 0xf) << 16
    inst |= (cp_reg_m & 0xf) << 0
    inst |= (opc_2 & 0x7) << 21
    inst |= 0xEE << 24
    inst |= 1 << 4

    return inst

class CortexA(CortexTarget):
    
    DEBUG_BASE = 0x30070000

    # Debug run control register
    DRCR = 0x090
    DRCR_HALT_MASK = 0x1

    # Debug status and control register
    DSCR = 0x088

    DSCR_HALTED_MASK = 0x1
    DSCR_RESTARTED_MASK = 0x1 << 1

    DSCR_MOE_SHIFT = 2
    DSCR_MOE_MASK = 0xF << DSCR_MOE_SHIFT

    DSCR_STICKY_PRECISE_ABORT_MASK = 0x1 << 6
    DSCR_STICKY_IMPRECISE_ABORT_MASK = 0x1 << 7
    DSCR_STICKY_UNDEFINED_MASK = 0x1 << 8

    DSCR_DBG_ACK_MASK = 0x1 << 10
    DSCR_INTERRUPT_DISABLE_MASK = 0x1 << 11
    DSCR_CP14_USER_ACCESS_DISABLE_MASK = 0x1 << 12
    DSCR_EXECUTE_INSTRUCTION_ENABLE_MASK = 0x1 << 13
    DSCR_HALTING_DEBUG_MODE_MASK = 0x1 << 14
    DSCR_MONITOR_DEBUG_MODE_MASK = 0x1 << 15
    
    DSCR_SECURE_PRIVILEGED_INVASIVE_DEBUG_DISABLED_MASK = 0x1 << 16
    DSCR_SECURE_PRIVILEGED_NONINVASIVE_DEBUG_DISABLED_MASK = 0x1 << 17

    DSCR_NONSECURE_STATE_STATUS_MASK = 0x1 << 18
    DSCR_DISCARD_IMPRECISE_ABORT_MASK = 0x1 << 19

    DSCR_DTR_ACCESS_SHIFT = 20
    DSCR_DTR_ACCESS_MODE_MASK = 0x3 << DSCR_DTR_ACCESS_SHIFT

    DSCR_INSTRCOMPL_MASK = 0x1 << 24
    DSCR_STICKY_PIPELINE_ADVANCE = 0x1 << 25

    DSCR_DTRTXFULL_LATCHED_MASK = 0x1 << 26
    DSCR_DTRRXFULL_LATCHED_MASK = 0x1 << 27

    DSCR_DTRTXFULL_MASK = 0x1 << 29
    DSCR_DTRRXFULL_MASK = 0x1 << 30

    # Debug ITR and DTR registers
    ITR = 0x084

    # TX: target->host, RX: host->target
    DTRTX = 0x08c
    DTRRX = 0x080

    LAR = 0xfb0

    PRSR = 0x314
    PRSR_RESET_MASK = 0x1 << 2
    PRSR_HALTED_MASK = 0x1 << 4

    DSCCR = 0x028
    DSCCR_FORCE_WRITE_THROUGH = 0x1 << 2
    DSCCR_INSTRUCTION_LINEFILL_EVICTION = 0x1 << 1
    DSCCR_DATA_CACHE_LINEFILL_EVICTION = 0x1 << 0

    DSMCR = 0x02C
    OSLSR = 0x304
    OSLAR = 0x300

    def __init__(self, link, dp, ap, memoryMap=None, core_num=0):
        super(CortexA, self).__init__(link, dp, ap, memoryMap, core_num)

    def init(self):
        """
        Writing to LAR allows us to write to debug registers (including halting
        the core in CortexA.halt).
        """
        # Check whether OS Lock is enabled
        oslsr = self.read32(self.DEBUG_BASE + CortexA.OSLSR)
        
        if oslsr & 0x2:
            # Disable OS Lock
            self.write32(self.DEBUG_BASE + CortexA.OSLAR, 0)
            oslsr = self.read32(self.DEBUG_BASE + CortexA.OSLSR)

        # Acquire write lock to debug registers
        self.write32(self.DEBUG_BASE + CortexA.LAR, 0xC5ACCE55)
        
        # Enable Halting Debug Mode
        dscr = self.read32(self.DEBUG_BASE + CortexA.DSCR)
        dscr |= CortexA.DSCR_HALTING_DEBUG_MODE_MASK
        self.write32(self.DEBUG_BASE + CortexA.DSCR, dscr)

        self.halt()

    def halt(self):
        """
        Halt the CPU core

        C11.11.17: Set DBGDRCR.HRQ to 1
        """
        self.write32(self.DEBUG_BASE + CortexA.DRCR, 1)
        dscr = self.read32(self.DEBUG_BASE + CortexA.DSCR)

        if not (dscr & 0x1):
            raise RuntimeError("Unable to halt core.")

    def getState(self):
        """
        See ARMv7 A/R Architecture Manual section C11.11.20: DBGDSCR, Debug
        Status and Control Register.

        TODO: read more detail from the core to give a better response to the
        state of the CPU.
        """
        prsr = self.read32(self.DEBUG_BASE + CortexA.PRSR)

        if prsr & CortexA.PRSR_HALTED_MASK:
            return Target.TARGET_HALTED
        elif prsr & CortexA.PRSR_RESET_MASK:
            return Target.TARGET_RESET
        else:
            return Target.TARGET_RUNNING

    def executeInstruction(self, instr):
        """
        Execute an assembled instruction on the CPU core using the instruction
        transfer register (ITR).

        See ARMv7 A/R architecture manual sections C8.3.4 and C11.11.27.
        
        NOTE: Access to ITR is apparently implementation-defined, so this might
        need overriding for specific targets.
        """
        dscr = self.read32(self.DEBUG_BASE + CortexA.DSCR)

        complete = dscr & CortexA.DSCR_INSTRCOMPL_MASK
        itren = dscr & CortexA.DSCR_EXECUTE_INSTRUCTION_ENABLE_MASK
        
        count = 0
        while not complete:
            if count == 10:
                raise RuntimeError("Register read timed out")
            complete = dscr & CortexA.DSCR_INSTRCOMPL_MASK
            time.sleep(0.5)
            count += 1
        
        if not itren:
            # Enable instruction execution
            dscr |= CortexA.DSCR_EXECUTE_INSTRUCTION_ENABLE_MASK
            self.write32(self.DEBUG_BASE + CortexA.DSCR, dscr)
        
        # Write the instruction to ITR
        self.write32(self.DEBUG_BASE + CortexA.ITR, instr)

        # Read DSCR repeatedly until the instruction is complete
        complete = self.read32(self.DEBUG_BASE, CortexA.DSCR) & CortexA.DSCR_INSTRCOMPL_MASK

        while not complete:
            complete = self.read32(self.DEBUG_BASE, CortexA.DSCR) & CortexA.DSCR_INSTRCOMPL_MASK
            
    def readCoreRegister(self, reg):
        """
        Read a core register from the CPU: move the register value to the
        DBGDTRTX register using a move core register to coprocessor register
        (MCR) instruction.

        See ARMv7 A/R Architecture Manual section C6.4.3.

        - Works by executing the following instruction
        - MCR p14, 0, r<reg>, c0, c5, 0
        """
        # Compute the instruction we're using.
        rIndex = self.registerNameToIndex(reg)
        instruction = MCR(14, 0, rIndex, 0, 5, 0)

        assert ((instruction & 0x0000f000) >> 12) == rIndex
        assert (instruction &  0xffff0fff) == 0xEE000E15

        self.executeInstruction(instruction)

        dscr = self.read32(self.DEBUG_BASE + CortexA.DSCR)
        if not(dscr & CortexA.DSCR_DTRTXFULL_MASK):
            raise RuntimeError("Unable to read register")

        return self.read32(self.DEBUG_BASE + CortexA.DTRTX)
