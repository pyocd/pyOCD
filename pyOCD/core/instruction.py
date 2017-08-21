"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2017 ARM Limited

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

thumb16_decoder_registry = {}
def thumb16_decoder(cls):
    thumb16_decoder_registry[cls.group] = cls
    return cls

@thumb16_decoder
class thumb16_decode_0(object):
    group = 0
    def decode(self, instr):
        rd = instr.instruction & 0x7
        instr.append_reg(rd)

@thumb16_decoder
class thumb16_decode_1(object):
    group = 1
    def decode(self, instr):
        opcode = (instr.instruction >> 11) & 0x3
        if opcode == 1:  # CMP(1)
            pass
        else:  # MOV(1), ADD(2), SUB(2)
            rd = (instr.instruction >> 8) & 0x7
            instr.append_reg(rd)

@thumb16_decoder
class thumb16_decode_2(object):
    group = 2
    def decode(self, instr):
        instruction = instr.instruction
        opcode = (instruction >> 11) & 0x3
        if opcode == 0:
            branch_op = (instruction >> 7) & 0xF
            if branch_op == 0xF:     # BLX
                instr.append_reg('lr')
            else:
                rd = instruction & 0x7
                instr.append_reg(rd)
        elif opcode == 1:
            rt = (instruction >> 8) & 0x7
            instr.append_reg(rt)
        elif opcode == 2:
            subopcode = (instruction >> 9) & 0x3
            if subopcode == 3:
                rt = instruction & 0x7
                instr.append_reg(rt)
            else:
                rm = (instruction >> 6) & 0x7
                rn = (instruction >> 3) & 0x7
                rm_value = instr.core.readCoreRegisterRaw(rm)
                rn_value = instr.core.readCoreRegisterRaw(rn)
                address = rn_value + rm_value
                if subopcode == 0:  # STR(reg)
                    instr.append_mem(address, 32)
                elif subopcode == 1:  # STRH(reg)
                    instr.append_mem(address, 16)
                elif subopcode == 2:  # STRB(reg)
                    instr.append_mem(address, 8)
        elif opcode == 3:
            rt = instruction & 0x7
            instr.append_reg(rt)

@thumb16_decoder
class thumb16_decode_3(object):
    group = 3
    def decode(self, instr):
        instruction = instr.instruction
        opcode = (instruction >> 11) & 0x3
        if opcode == 0:  # STR
            imm = ((instruction >> 6) & 0x1F) << 2
            rn = (instruction >> 3) & 0x7
            rn_value = instr.core.readCoreRegisterRaw(rn)
            address = rn_value + imm
            instr.append_mem(address, 32)
        elif opcode == 2:  # STRB
            imm = (instruction >> 6) & 0x1F
            rn = (instruction >> 3) & 0x7
            rn_value = instr.core.readCoreRegisterRaw(rn)
            address = rn_value + imm
            instr.append_mem(address, 8)
        else:  # LDR or LDRB
            rt = instruction & 0x7
            instr.append_reg(rt)

@thumb16_decoder
class thumb16_decode_4(object):
    group = 4
    def decode(self, instr):
        instruction = instr.instruction
        opcode = (instruction >> 11) & 0x3
        if opcode == 0:    # STRH
            imm = ((instruction >> 6) & 0x1F) << 1
            rn = (instruction >> 3) & 0x7
            rn_value = instr.core.readCoreRegisterRaw(rn)
            address = rn_value + imm
            instr.append_mem(address, 16)
        elif opcode == 1:  # LDRH
            rt = instruction & 0x7
            instr.append_reg(rt)
        elif opcode == 2:  # STR
            imm = (instruction & 0xFF) << 2
            rn_value = instr.core.readCoreRegister('sp')
            address = rn_value + imm
            instr.append_mem(address, 32)
        else:              # LDR
            rt = (instruction >> 8) & 0x7
            instr.append_reg(rt)

@thumb16_decoder
class thumb16_decode_5(object):
    group = 5
    def decode(self, instr):
        instruction = instr.instruction
        opcode = (instruction >> 11) & 0x3
        if opcode == 0 or opcode == 1:
            rd = (instruction >> 8) & 0x7
            instr.append_reg(rd)
        else:
            subopcode = (instruction >> 8) & 0x1F
            if subopcode == 0b10110:  # CPS
                instr.append_reg('primask')
                instr.append_reg('faultmask')
            elif subopcode == 0b10000:  # ADD(sp+imm) SUB(sp-imm)
                instr.append_reg('sp')
            elif subopcode == 0b10010 or subopcode == 0b11010:
                rd = instruction & 0x7
                instr.append_reg(rd)
            else:
                subopcode = (instruction >> 9) & 0xF
                if subopcode == 0b1010:  # PUSH
                    sp_value = instr.core.readCoreRegisterRaw('sp')
                    register_list = instruction & 0x1FF
                    bit_count = 0
                    while register_list != 0:
                        if register_list & 0x1:
                            bit_count = bit_count + 1
                            instr.append_mem(sp_value - 4 * bit_count, 32)
                        register_list = register_list >> 1
                elif subopcode == 0b1110: # POP
                    register_list = instruction & 0xFF
                    reg_no = 0
                    while register_list != 0:
                        if register_list & 0x1:
                            instr.append_reg(reg_no)
                        reg_no = reg_no + 1
                        register_list = register_list >> 1

@thumb16_decoder
class thumb16_decode_6(object):
    group = 6
    def decode(self, instr):
        instruction = instr.instruction
        opcode = (instruction >> 11) & 0x3
        if opcode == 0: # STM, STMIA, STMEA
            rn = (instruction >> 8) & 0x7
            register_list = instruction & 0xFF
            address = instr.core.readCoreRegisterRaw(rn)
            bit_count = 0
            while register_list != 0:
                if register_list & 0x1:
                    instr.append_mem(address + 4 * bit_count, 32)
                    bit_count = bit_count + 1
                register_list = register_list >> 1

            instr.append(rn)
        elif opcode == 1: # LDM, LDMIA, LDMFD
            rn = (instruction >> 8) & 0x7
            register_list = instruction & 0xFF
            reg_no = 0
            wback = 1
            while register_list != 0:
                if register_list & 0x1:
                    instr.append_reg(reg_no)
                    if reg_no == rn:
                        wback = 0
                reg_no = reg_no + 1
                register_list = register_list >> 1

            if wback:
                instr.append_reg(rn)
        else:
            cond = (instruction >> 8) & 0xF
            if cond == 0b1110 or cond == 0b1111:  # UDF or SVC
                pass
            else:  # B
                pass

@thumb16_decoder
class thumb16_decode_7(object):
    group = 7
    def decode(self, instr):
        pass

class Instruction(object):
    class RegisterAccess(object):
        def __init__(self, reg_no, value):
            self.reg_no = reg_no
            self.value = value

    class MemoryAccess(object):
        def __init__(self, address, size, value):
            self.address = address
            self.size = size
            self.value = value

    def __init__(self, instruction, core):
        self.core = core 
        self.instruction = instruction
        group_id = (self.instruction >> 13) & 0x7
        self.decoder = thumb16_decoder_registry[group_id]()
        self.registers = []
        self.memory_access = []

        # Always push pc and xpsr into registers[].
        for reg in ['pc', 'xpsr']:
            self.append_reg(reg)

    def restore(self):
        # Restore register values.
        for reg in self.registers:
            self.core.writeCoreRegister(reg.reg_no, reg.value)
        # Restore memory values.
        for mem_access in self.memory_access:
            self.core.writeMemory(mem_access.address, mem_access.value, mem_access.size)

    def decode(self):
        self.decoder.decode(self)

    def append_reg(self, reg):
        reg_no = self.core.registerNameToIndex(reg)
        value = self.core.readCoreRegisterRaw(reg_no)
        self.registers.append(self.RegisterAccess(reg_no, value))

    def append_mem(self, address, size):
        value = self.core.readMemory(address, size)
        self.memory_access.append(self.MemoryAccess(address, size, value))
