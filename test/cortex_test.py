# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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
from __future__ import print_function

import argparse
import os
import sys
from time import (sleep, time)
from random import randrange
import math
import argparse
import traceback
import logging
from random import randrange

from pyocd.core.target import Target
from pyocd.coresight.cortex_m import CortexM
from pyocd.gdbserver.context_facade import GDBDebugContextFacade
from pyocd.core.helpers import ConnectHelper
from pyocd.utility.conversion import float32_to_u32, u32_to_float32
from pyocd.utility.mask import same
from pyocd.core import exceptions
from pyocd.core.memory_map import MemoryType
from pyocd.flash.file_programmer import FileProgrammer

from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    get_test_binary_path,
    )

TEST_COUNT = 20

class CortexTestResult(TestResult):
    METRICS = [
        "get_t_response",
        "step",
        "bp_add_remove",
        "get_reg_context",
        "set_reg_context",
        "run_halt",
        "gdb_step",
        ]
    
    def __init__(self):
        super(CortexTestResult, self).__init__(None, None, None)
        self.name = "cortex"
        self.times = {}
        for metric in self.METRICS:
            self.times[metric] = -1.0

class CortexTest(Test):
    def __init__(self):
        super(CortexTest, self).__init__("Cortex Test", cortex_test)

    def print_perf_info(self, result_list, output_file=None):
        result_list = filter(lambda x: isinstance(x, CortexTestResult), result_list)
        print("\n\n------ Cortex Test Performance ------", file=output_file)
        print("", file=output_file)
        for result in result_list:
            print("Target {}:".format(result.board), file=output_file)
            for metric in CortexTestResult.METRICS:
                print("    {:<20} = {: 8.3f} ms".format(metric, result.times[metric] * 1000), file=output_file)
        print("", file=output_file)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = CortexTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def float_compare(f1, f2):
    return abs(f1 - f2) < 0.0001

def test_function(session, function):
    session.probe.flush()
    start = time()
    for i in range(0, TEST_COUNT):
        function()
        session.probe.flush()
    stop = time()
    return (stop - start) / float(TEST_COUNT)

def cortex_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target_type = board.target_type

        binary_file = get_test_binary_path(board.test_binary)

        test_params = get_target_test_params(session)
        test_clock = test_params['test_clock']
        addr_invalid = 0x3E000000 # Last 16MB of ARM SRAM region - typically empty
        expect_invalid_access_to_fail = test_params['error_on_invalid_access']

        memory_map = board.target.get_memory_map()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)
        rom_region = memory_map.get_boot_memory()

        addr = ram_region.start
        size = 0x502
        addr_bin = rom_region.start

        target = board.target
        probe = session.probe

        probe.set_clock(test_clock)

        test_pass_count = 0
        test_count = 0
        result = CortexTestResult()

        debugContext = target.get_target_context()
        gdbFacade = GDBDebugContextFacade(debugContext)

        print("\n\n----- FLASH NEW BINARY BEFORE TEST -----")
        FileProgrammer(session).program(binary_file, base_address=addr_bin)
        # Let the target run for a bit so it
        # can initialize the watchdog if it needs to
        target.resume()
        sleep(0.2)
        target.halt()

        print("PROGRAMMING COMPLETE")


        print("\n\n----- TESTING CORTEX-M PERFORMANCE -----")
        test_time = test_function(session, gdbFacade.get_t_response)
        result.times["get_t_response"] = test_time
        print("Function get_t_response time:    %f" % test_time)

        # Step
        test_time = test_function(session, target.step)
        result.times["step"] = test_time
        print("Function step time:              %f" % test_time)

        # Breakpoint
        def set_remove_breakpoint():
            target.set_breakpoint(0)
            target.remove_breakpoint(0)
        test_time = test_function(session, set_remove_breakpoint)
        result.times["bp_add_remove"] = test_time
        print("Add and remove breakpoint:       %f" % test_time)

        # get_register_context
        test_time = test_function(session, gdbFacade.get_register_context)
        result.times["get_reg_context"] = test_time
        print("Function get_register_context:   %f" % test_time)

        # set_register_context
        context = gdbFacade.get_register_context()
        def set_register_context():
            gdbFacade.set_register_context(context)
        test_time = test_function(session, set_register_context)
        result.times["set_reg_context"] = test_time
        print("Function set_register_context:   %f" % test_time)

        # Run / Halt
        def run_halt():
            target.resume()
            target.halt()
        test_time = test_function(session, run_halt)
        result.times["run_halt"] = test_time
        print("Resume and halt:                 %f" % test_time)

        # GDB stepping
        def simulate_step():
            target.step()
            gdbFacade.get_t_response()
            target.set_breakpoint(0)
            target.resume()
            target.halt()
            gdbFacade.get_t_response()
            target.remove_breakpoint(0)
        test_time = test_function(session, simulate_step)
        result.times["gdb_step"] = test_time
        print("Simulated GDB step:              %f" % test_time)

        # Test passes if there are no exceptions
        test_pass_count += 1
        test_count += 1
        print("TEST PASSED")

        print("\n\n------ Testing Reset Types ------")
        def reset_methods(fnc):
            print("Hardware reset")
            fnc(reset_type=Target.ResetType.HW)
            print("Hardware reset (default=HW)")
            target.selected_core.default_reset_type = Target.ResetType.HW
            fnc(reset_type=None)
            print("Software reset (default=SYSRESETREQ)")
            target.selected_core.default_reset_type = Target.ResetType.SW_SYSRESETREQ
            fnc(reset_type=None)
            print("Software reset (default=VECTRESET)")
            target.selected_core.default_reset_type = Target.ResetType.SW_VECTRESET
            fnc(reset_type=None)
            print("Software reset (default=emulated)")
            target.selected_core.default_reset_type = Target.ResetType.SW_EMULATED
            fnc(reset_type=None)
            
            print("(Default) Software reset (SYSRESETREQ)")
            target.selected_core.default_software_reset_type = Target.ResetType.SW_SYSRESETREQ
            fnc(reset_type=Target.ResetType.SW)
            print("(Default) Software reset (VECTRESET)")
            target.selected_core.default_software_reset_type = Target.ResetType.SW_VECTRESET
            fnc(reset_type=Target.ResetType.SW)
            print("(Default) Software reset (emulated)")
            target.selected_core.default_software_reset_type = Target.ResetType.SW_EMULATED
            fnc(reset_type=Target.ResetType.SW)
            
            print("Software reset (option=default)")
            target.selected_core.default_reset_type = Target.ResetType.SW
            target.selected_core.default_software_reset_type = Target.ResetType.SW_SYSRESETREQ
            session.options['reset_type'] = 'default'
            fnc(reset_type=None)
            print("Software reset (option=hw)")
            session.options['reset_type'] = 'hw'
            fnc(reset_type=None)
            print("Software reset (option=sw)")
            session.options['reset_type'] = 'sw'
            fnc(reset_type=None)
            print("Software reset (option=sw_sysresetreq)")
            session.options['reset_type'] = 'sw_sysresetreq'
            fnc(reset_type=None)
            print("Software reset (option=sw_vectreset)")
            session.options['reset_type'] = 'sw_vectreset'
            fnc(reset_type=None)
            print("Software reset (option=sw_emulated)")
            session.options['reset_type'] = 'sw_emulated'
            fnc(reset_type=None)

        reset_methods(target.reset)
        
        # Test passes if there are no exceptions
        test_pass_count += 1
        test_count += 1
        print("TEST PASSED")


        print("\n\n------ Testing Reset Halt ------")
        reset_methods(target.reset_and_halt)

        # Test passes if there are no exceptions
        test_pass_count += 1
        test_count += 1
        print("TEST PASSED")


        print("\n\n------ Testing Register Read/Write ------")
        print("Reading r0")
        val = target.read_core_register('r0')
        origR0 = val
        rawVal = target.read_core_register_raw('r0')
        test_count += 1
        if val == rawVal:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")

        print("Writing r0")
        target.write_core_register('r0', 0x12345678)
        val = target.read_core_register('r0')
        rawVal = target.read_core_register_raw('r0')
        test_count += 1
        if val == 0x12345678 and rawVal == 0x12345678:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")

        print("Raw writing r0")
        target.write_core_register_raw('r0', 0x87654321)
        val = target.read_core_register('r0')
        rawVal = target.read_core_register_raw('r0')
        test_count += 1
        if val == 0x87654321 and rawVal == 0x87654321:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")

        print("Read/write r0, r1, r2, r3")
        origRegs = target.read_core_registers_raw(['r0', 'r1', 'r2', 'r3'])
        target.write_core_registers_raw(['r0', 'r1', 'r2', 'r3'], [1, 2, 3, 4])
        vals = target.read_core_registers_raw(['r0', 'r1', 'r2', 'r3'])
        passed = vals[0] == 1 and vals[1] == 2 and vals[2] == 3 and vals[3] == 4
        test_count += 1
        if passed:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")
            
        # Restore regs
        origRegs[0] = origR0
        target.write_core_registers_raw(['r0', 'r1', 'r2', 'r3'], origRegs)
        
        print("Verify exception is raised while core is running")
        target.resume()
        try:
            val = target.read_core_register('r0')
        except exceptions.CoreRegisterAccessError:
            passed = True
        else:
            passed = False
        test_count += 1
        if passed:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")
        
        print("Verify failure to write core register while running raises exception")
        try:
            target.write_core_register('r0', 0x1234)
        except exceptions.CoreRegisterAccessError:
            passed = True
        else:
            passed = False
        test_count += 1
        if passed:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")
        
        # Resume execution.
        target.halt()

        if target.selected_core.has_fpu:
            print("Reading s0")
            val = target.read_core_register('s0')
            rawVal = target.read_core_register_raw('s0')
            origRawS0 = rawVal
            passed = isinstance(val, float) and isinstance(rawVal, int) \
                        and float32_to_u32(val) == rawVal
            test_count += 1
            if passed:
                test_pass_count += 1
                print("TEST PASSED")
            else:
                print("TEST FAILED")

            print("Writing s0")
            target.write_core_register('s0', math.pi)
            val = target.read_core_register('s0')
            rawVal = target.read_core_register_raw('s0')
            passed = float_compare(val, math.pi) and float_compare(u32_to_float32(rawVal), math.pi)
            test_count += 1
            if passed:
                test_pass_count += 1
                print("TEST PASSED")
            else:
                print("TEST FAILED (%f==%f, 0x%08x->%f)" % (val, math.pi, rawVal, u32_to_float32(rawVal)))

            print("Raw writing s0")
            x = float32_to_u32(32.768)
            target.write_core_register_raw('s0', x)
            val = target.read_core_register('s0')
            passed = float_compare(val, 32.768)
            test_count += 1
            if passed:
                test_pass_count += 1
                print("TEST PASSED")
            else:
                print("TEST FAILED (%f==%f)" % (val, 32.768))

            print("Read/write s0, s1")
            _1p1 = float32_to_u32(1.1)
            _2p2 = float32_to_u32(2.2)
            origRegs = target.read_core_registers_raw(['s0', 's1'])
            target.write_core_registers_raw(['s0', 's1'], [_1p1, _2p2])
            vals = target.read_core_registers_raw(['s0', 's1'])
            s0 = target.read_core_register('s0')
            s1 = target.read_core_register('s1')
            passed = vals[0] == _1p1 and float_compare(s0, 1.1) \
                        and vals[1] == _2p2 and float_compare(s1, 2.2)
            test_count += 1
            if passed:
                test_pass_count += 1
                print("TEST PASSED")
            else:
                print("TEST FAILED (0x%08x==0x%08x, %f==%f, 0x%08x==0x%08x, %f==%f)" \
                    % (vals[0], _1p1, s0, 1.1, vals[1], _2p2, s1, 2.2))
            
            # Restore s0
            origRegs[0] = origRawS0
            target.write_core_registers_raw(['s0', 's1'], origRegs)
        
        print("Verify that all listed core registers can be accessed")
        reg_count = 0
        passed_reg_count = 0
        for r in target.selected_core.core_registers.as_set:
            try:
                reg_count += 1
                val = target.read_core_register(r.name)
                target.write_core_register(r.name, val)
                passed_reg_count += 1
            except exceptions.CoreRegisterAccessError:
                pass
        test_count += 1
        if passed_reg_count == reg_count:
            test_pass_count += 1
            print("TEST PASSED (%i registers)" % reg_count)
        else:
            print("TEST FAILED (%i registers, %i failed)" % (reg_count, reg_count - passed_reg_count))

        print("\n\n------ Testing Invalid Memory Access Recovery ------")
        memory_access_pass = True
        try:
            print("reading 0x1000 bytes at invalid address 0x%08x" % addr_invalid)
            target.read_memory_block8(addr_invalid, 0x1000)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if expect_invalid_access_to_fail:
                print("  failed to get expected fault")
                memory_access_pass = False
            else:
                print("  no fault as expected")
        except exceptions.TransferFaultError as exc:
            print("  got expected error: " + str(exc))

        try:
            print("reading 0x1000 bytes at invalid address 0x%08x" % (addr_invalid + 1))
            target.read_memory_block8(addr_invalid + 1, 0x1000)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if expect_invalid_access_to_fail:
                print("  failed to get expected fault")
                memory_access_pass = False
            else:
                print("  no fault as expected")
        except exceptions.TransferFaultError as exc:
            print("  got expected error: " + str(exc))

        data = [0x00] * 0x1000
        try:
            print("writing 0x%08x bytes at invalid address 0x%08x" % (len(data), addr_invalid))
            target.write_memory_block8(addr_invalid, data)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if expect_invalid_access_to_fail:
                print("  failed to get expected fault!")
                memory_access_pass = False
            else:
                print("  no fault as expected")
        except exceptions.TransferFaultError as exc:
            print("  got expected error: " + str(exc))

        data = [0x00] * 0x1000
        try:
            print("writing 0x%08x bytes at invalid address 0x%08x" % (len(data), addr_invalid + 1))
            target.write_memory_block8(addr_invalid + 1, data)
            target.flush()
            # If no exception is thrown the tests fails except on nrf51 where invalid addresses read as 0
            if expect_invalid_access_to_fail:
                print("  failed to get expected fault!")
                memory_access_pass = False
            else:
                print("  no fault as expected")
        except exceptions.TransferFaultError as exc:
            print("  got expected error: " + str(exc))

        data = [randrange(0, 255) for x in range(size)]
        print("r/w 0x%08x bytes at 0x%08x" % (size, addr))
        target.write_memory_block8(addr, data)
        block = target.read_memory_block8(addr, size)
        if same(data, block):
            print("  Aligned access pass")
        else:
            print("  Memory read does not match memory written")
            memory_access_pass = False

        data = [randrange(0, 255) for x in range(size)]
        print("r/w 0x%08x bytes at 0x%08x" % (size, addr + 1))
        target.write_memory_block8(addr + 1, data)
        block = target.read_memory_block8(addr + 1, size)
        if same(data, block):
            print("  Unaligned access pass")
        else:
            print("  Unaligned memory read does not match memory written")
            memory_access_pass = False

        test_count += 1
        if memory_access_pass:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")

        print("\n\n------ Testing Software Breakpoints ------")
        test_passed = True
        orig8x2 = target.read_memory_block8(addr, 2)
        orig8 = target.read8(addr)
        orig16 = target.read16(addr & ~1)
        orig32 = target.read32(addr & ~3)
        origAligned32 = target.read_memory_block32(addr & ~3, 1)

        def test_filters():
            test_passed = True
            filtered = target.read_memory_block8(addr, 2)
            if same(orig8x2, filtered):
                print("2 byte unaligned passed")
            else:
                print("2 byte unaligned failed (read %x-%x, expected %x-%x)" % (filtered[0], filtered[1], orig8x2[0], orig8x2[1]))
                test_passed = False

            for now in (True, False):
                filtered = target.read8(addr, now)
                if not now:
                    filtered = filtered()
                if filtered == orig8:
                    print("8-bit passed [now=%s]" % now)
                else:
                    print("8-bit failed [now=%s] (read %x, expected %x)" % (now, filtered, orig8))
                    test_passed = False

                filtered = target.read16(addr & ~1, now)
                if not now:
                    filtered = filtered()
                if filtered == orig16:
                    print("16-bit passed [now=%s]" % now)
                else:
                    print("16-bit failed [now=%s] (read %x, expected %x)" % (now, filtered, orig16))
                    test_passed = False

                filtered = target.read32(addr & ~3, now)
                if not now:
                    filtered = filtered()
                if filtered == orig32:
                    print("32-bit passed [now=%s]" % now)
                else:
                    print("32-bit failed [now=%s] (read %x, expected %x)" % (now, filtered, orig32))
                    test_passed = False

            filtered = target.read_memory_block32(addr & ~3, 1)
            if same(filtered, origAligned32):
                print("32-bit aligned passed")
            else:
                print("32-bit aligned failed (read %x, expected %x)" % (filtered[0], origAligned32[0]))
                test_passed = False
            return test_passed

        print("Installed software breakpoint at 0x%08x" % addr)
        target.set_breakpoint(addr, Target.BreakpointType.SW)
        test_passed = test_filters() and test_passed

        print("Removed software breakpoint")
        target.remove_breakpoint(addr)
        test_passed = test_filters() and test_passed

        test_count += 1
        if test_passed:
            test_pass_count += 1
            print("TEST PASSED")
        else:
            print("TEST FAILED")

        print("\nTest Summary:")
        print("Pass count %i of %i tests" % (test_pass_count, test_count))
        if test_pass_count == test_count:
            print("CORTEX TEST PASSED")
        else:
            print("CORTEX TEST FAILED")

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD cpu test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    cortex_test(None)
