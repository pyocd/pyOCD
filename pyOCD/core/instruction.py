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
decoder_registry = {}
def decoder(cls):
    decoder_registry[cls.group] = cls
    return cls

@decoder
class thumb16_decode_0(object):
    group = 0
    def decode(self, instr):
        rd = instr.instruction & 0x7
        instr.append_reg(rd)

@decoder
class thumb16_decode_1(object):
    group = 1
    def decode(self, instr):
        opcode = (instr.instruction >> 11) & 0x3
        if opcode == 1:  # CMP(1)
            pass
        else:  # MOV(1), ADD(2), SUB(2)
            rd = (instr.instruction >> 8) & 0x7
            instr.append_reg(rd)

@decoder
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

@decoder
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

@decoder
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

@decoder
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

@decoder
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

@decoder
class thumb16_decode_7(object):
    group = 7
    def decode(self, instr):
        pass

@decoder
class thumb32_decode_1(object):
    group = 8
    def decode(self, instr):
        instruction = instr.instruction
        opcode_9_10 = (instruction >> 9) & 0x3
        if opcode_9_10 == 0:
            opcode_6_8 = (instruction >> 6) & 0x7
            opcode_4_8 = (instruction >> 4) & 0x1F
            if opcode_6_8 == 0x2:  # STM, LDM, POP
                rn = instruction & 0xF
                register_list = (instruction >> 16) & 0xFFFF
                if (instruction >> 4) & 0x1:  # POP, LDM
                    reg_no = 0
                    while register_list != 0:
                        if register_list & 0x1:
                            instr.append_reg(reg_no)
                        reg_no = reg_no + 1
                        register_list = register_list >> 1
                    instr.append_reg(rn)
                else:  # STM
                    address = instr.core.readCoreRegisterRaw(rn)
                    bit_count = 0
                    while register_list != 0:
                        if register_list & 0x1:
                            instr.append_mem(address + 4 * bit_count, 32)
                            bit_count = bit_count + 1
                        register_list = register_list >> 1
                    instr.append(rn)
            elif opcode_6_8 == 0x4:  # STMDB, PUSH, LDMDB
                rn = instruction & 0xF
                register_list = (instruction >> 16) & 0xFFFF
                if (instruction >> 4) & 0x1:  # LDMDB
                    reg_no = 0
                    while register_list != 0:
                        if register_list & 0x1:
                            instr.append_reg(reg_no)
                        reg_no = reg_no + 1
                        register_list = register_list >> 1
                else:  # PUSH, STMDB
                    address = instr.core.readCoreRegisterRaw(rn)
                    bit_count = 0
                    while register_list != 0:
                        if register_list & 0x1:
                            bit_count = bit_count + 1
                            instr.append_mem(address - 4 * bit_count, 32)
                        register_list = register_list >> 1
                    instr.append_reg(rn)
            elif opcode_4_8 == 0x4:   # STREX
                imm = (instruction >> 16) & 0xFF
                rd = (instruction >> 24) & 0xF
                rn = instruction & 0xF
                rn_value = instr.core.readCoreRegisterRaw(rn)
                address = rn_value + (imm << 2)
                instr.append_mem(address, 32)
                instr.append_reg(rd)
            elif opcode_4_8 == 0x5:   # LDREX
                rt = (instruction >> 28) & 0xF
                instr.append_reg(rt)
            elif opcode_4_8 == 0xC:  # STREXB, STREXH
                rn = instruction & 0xF
                address = instr.core.readCoreRegisterRaw(rn)
                op3 = (instruction >> 20) & 0xF
                if op3 == 0b0100:  # STREXB
                    instr.append_mem(address, 8)
                elif op3 == 0b0101:  # STREXH
                    instr.append_mem(address, 16)

                rd = (instruction >> 16) & 0xF
                instr.append_reg(rd)
            elif opcode_4_8 == 0xD:  # TBB, LDREXB, LDREXH
                rt = (instruction >> 28) & 0xF
                if rt != 0xF:  #  LDREXB, LDREXH
                    instr.append_reg(rt)
            else:
                if (instruction >> 4) & 0x1:  # LDRD
                    rn = instruction & 0xF
                    rt = (instruction >> 28) & 0xF
                    rt2 = (instruction >> 24) & 0xF
                    instr.append_reg(rn)
                    instr.append_reg(rt)
                    instr.append_reg(rt2)
                else:  # STRD
                    index = (instruction >> 8) & 0x1
                    add = (instruction >> 7) & 0x1
                    rn = instruction & 0xF
                    rn_value = instr.core.readCoreRegisterRaw(rn)
                    imm = (instruction >> 16) & 0xFF

                    offset = 0
                    if add:
                        offset = rn_value + (imm << 2)
                    else:
                        offset = rn_value - (imm << 2)

                    address = 0
                    if index:
                        address = offset
                    else:
                        address = rn_value

                    instr.append_mem(address, 32)
                    instr.append_mem(address + 4, 32)
                    instr.append_reg(rn)
        elif opcode_9_10 == 1:
            rd = (instruction >> 24) & 0xF
            if rd != 0xF:
                instr.append_reg(rd)
        elif opcode_9_10 == 2 or opcode_9_10 == 3:  # Coprocessor instructions
            pass

@decoder
class thumb32_decode_2(object):
    group = 9
    def decode(self, instr):
        instruction = instr.instruction
        if (instruction >> 31) & 0x1:
            if ((instruction >> 28) & 0x1) and ((instruction >> 30) & 0x1):  # BL
                instr.append_reg('lr')
        else:
            opcode = (instruction >> 4) & 0x3F
            rd = (instruction >> 24) & 0xF
            if (opcode == 0x1) and (rd == 0xF):     # TST(imm)
                return
            elif (opcode == 0x9) and (rd == 0xF):   # TEQ(imm)
                return
            elif (opcode == 0x11) and (rd == 0xF):  # CMN(imm)
                return
            elif (opcode == 0x1B) and (rd == 0xF):  # CMP(imm)
                return

            instr.append_reg(rd)

@decoder
class thumb32_decode_3(object):
    group = 10
    def decode(self, instr):
        instruction = instr.instruction
        opcode = (instruction >> 9) & 0x3
        if opcode == 0x0:
            if (instruction >> 4) & 0x1:
                rt = (instruction >> 28) & 0xF
                if rt != 0xF:
                    instr.append_reg(rt)
                    rn = instruction & 0xF
                    if rn != 0xF:
                        instr.append_reg(rn)
            else:  # Store single data item.
                rn = instruction & 0xF
                rn_value = instr.core.readCoreRegisterRaw(rn)
                opcode_4_6 = (instruction >> 4) & 0x7
                if (instruction >> 7) & 0x1:  # STRB(imm)(2), STRH(imm)(2), STR(imm)(2)
                    imm = (instruction >> 16) & 0xFFF
                    address = rn_value + imm
                else:
                    if (instruction >> 27) & 0x1:  # STRB(imm)(3), STRH(imm)(3), STR(imm)(3)
                        index = (instruction >> 26) & 0x1
                        add = (instruction >> 25) & 0x1
                        imm = (instruction >> 16) & 0xFF
                        offset = 0
                        if add:
                            offset = rn_value + imm
                        else:
                            offset = rn_value - imm

                        address = 0
                        if index:
                            address = offset
                        else:
                            address = rn_value

                        instr.append_reg(rn)
                    else:  # STRB(reg), STRH(reg), STR(reg)
                        shift_n = (instruction >> 20) & 0x3
                        rm = (instruction >> 16) & 0xF
                        rm_value = instr.core.readCoreRegisterRaw(rm)
                        offset = rm_value << shift_n
                        address = rn_value + offset

                if opcode_4_6 == 0:
                    instr.append_mem(address, 8)
                elif opcode_4_6 == 2:
                    instr.append_mem(address, 16)
                elif opcode_4_6 == 4:
                    instr.append_mem(address, 32)
        elif opcode == 0x1:
            rd = (instruction >> 24) & 0xF
            instr.append_reg(rd)
            opcode_4_8 = (instruction >> 4) & 0x1F
            if ((opcode_4_8 == 0x18) or  # SMULL
                (opcode_4_8 == 0x1A) or  # UMULL
                (opcode_4_8 == 0x1C) or  # SMLAL, SMLALBB, SMLALD
                (opcode_4_8 == 0x1D) or  # SMLSLD
                (opcode_4_8 == 0x1E)):   # UMLAL, UMAAL
                rdlo = (instruction >> 28) & 0xF
                instr.append_reg(rdlo)
        elif (opcode == 0x2) or (opcode == 0x3):  # Coprocessor instructions.
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

    def __init__(self, instruction, size, core):
        self.core = core 
        self.instruction = instruction
        self.size = size
        group_id = (self.instruction >> 13) & 0x7
        if self.size == 32:
            op1 = (self.instruction >> 11) & 0x3
            group_id = group_id + op1
        self.decoder = decoder_registry[group_id]()
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

    @staticmethod
    def is_thumb16(instruction):
        opcode = (instruction >> 11) & 0x1F
        if (opcode == 0b11101) or (opcode == 0b11110) or (opcode == 0b11111):
            return False
        return True

    def append_reg(self, reg):
        reg_no = self.core.registerNameToIndex(reg)
        value = self.core.readCoreRegisterRaw(reg_no)
        self.registers.append(self.RegisterAccess(reg_no, value))

    def append_mem(self, address, size):
        value = self.core.readMemory(address, size)
        self.memory_access.append(self.MemoryAccess(address, size, value))
