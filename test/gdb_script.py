"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2015 ARM Limited

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
from __future__ import print_function

# Notes about this script
# 1. This script runs inside arm-none-eabi-gdb-py
# 2. GDB processes commands inside a queue on a worker
#    thread.  Commands that change the state of the target
#    should run from this queue via gdb.post_event(cb).
# 3. After running a command that changes the state of a target
#    in the background, like "continue&", the code needs to
#    return so the event processing that occurs on the worker
#    thread can continue.  No target state changes will be
#    seen until the worker thread gets a chance to process the data.
# 4. To make the code flow better with #3 the main test function,
#    run_test, takes advantage of the 'yield' call.  After
#    performing a background operation that causes the target run
#    'yield' must be called with a timeout value.  The code
#    will wait for the target to halt for the time specified and
#    if no signal arrives in that time the target is explicitly
#    halted.
# 5. Only use packages in the standard library in this script.
#    Since the current version of arm-none-eabi-gdb-py.exe is
#    only 32 bit on windows, there must be a 32 bit python
#    install for it to work.  If your primary version of python
#    is 64 bit, you can install the 32 bit version as a non
#    primary version.  This will allow arm-none-eabi-gdb-py.exe
#    to work.  The only problem with this is that when pyOCD
#    is installed through pip only the 64 bit version of
#    pyOCD and it's dependencies will get installed.
#    If only the standard library is used here then this
#    script will have no external dependencies.

import gdb
from time import time
from threading import Timer
from functools import partial
from random import randrange
from itertools import product
import traceback
import json
import sys

# We expect arm-none-eabi-gdb-py to only run Python 2.x. If it moves
# to Python 3, we need to know about it, so print a warning.
print("arm-none-eabi-gdb-py is using Python %s" % sys.version)
if sys.version_info.major != 2:
    print("*** Unexpected arm-none-eabi-gdb-py Python version %d! ***" % sys.version_info.major)

DEFAULT_TIMEOUT = 2.0
STACK_OFFSET = 0x800
TEST_RAM_OFFSET = 0x800
MAX_TEST_SIZE = 0x1000
MAX_BKPT = 10

assert STACK_OFFSET < MAX_TEST_SIZE
assert TEST_RAM_OFFSET < MAX_TEST_SIZE

TEST_PARAM_FILE = "test_params.txt"
TEST_RESULT_FILE = "test_results.txt"

monitor_commands = [
    "help",
    "help reset",
    "help halt",
    "init",
    "reset",
    "reset halt",
    "halt",
    "arm semihosting enable",
    "arm semihosting disable",
    "set vector-catch n",
    "set vector-catch a",
    "set step-into-interrupt on",
    "set step-into-interrupt off",
    # Invalid Command
    "fawehfawoefhad"
]

SIZE_TO_C_TYPE = {
    1: "uint8_t*",
    2: "uint16_t*",
    4: "uint32_t*",
}

TO_GDB_ACCESS = {
    "read": gdb.WP_READ,
    "write": gdb.WP_WRITE,
    "read_write": gdb.WP_ACCESS,
}


def gdb_execute(cmd):
    print("Executing command:", cmd)
    gdb.execute(cmd)


def test_step_type(step_type):
    step_count = 20
    start = time()
    for _ in range(step_count):
        gdb_execute(step_type)
    end = time()
    seconds_per_operation = (end - start) / step_count
    return seconds_per_operation


def is_event_breakpoint(event, bkpt=None):
    if not isinstance(event, gdb.BreakpointEvent):
        return False
    if bkpt is None:
        return True
    return event.breakpoints[-1] is bkpt


def is_event_signal(event, signal_name):
    if not isinstance(event, gdb.SignalEvent):
        return False
    return event.stop_signal == signal_name


def has_read(name):
    if name == "read":
        return True
    if name == "read_write":
        return True
    assert name == "write"
    return False


def has_write(name):
    if name == "write":
        return True
    if name == "read_write":
        return True
    assert name == "read"
    return False


def size_to_type(size):
    return SIZE_TO_C_TYPE[size]


def to_gdb_access(access):
    return TO_GDB_ACCESS[access]


def should_trigger_break(bkpt_size, bkpt_access,
                         bkpt_addr, size, access, addr):
    left_access_addr = addr
    right_access_addr = addr + size - 1
    left_bkpt_addr = bkpt_addr
    right_bkpt_addr = bkpt_addr + bkpt_size
    overlap = (left_access_addr <= right_bkpt_addr and
               right_access_addr >= left_bkpt_addr)
    read_break = has_read(bkpt_access) and has_read(access)
    write_break = has_write(bkpt_access) and has_write(access)
    should_break = overlap and (read_break or write_break)
    return should_break


def valid_watchpoint(bkpt_size, bkpt_access, bkpt_addr):
    # Unaligned breakpoints are not allowed
    return bkpt_addr % bkpt_size == 0


# Initial setup
with open(TEST_PARAM_FILE, "rb") as f:
    test_params = json.loads(f.read())


def run_test():

    test_result = {}
    rom_start = test_params['rom_start']
    ram_start = test_params['ram_start']
    ram_length = test_params['ram_length']
    invalid_addr = test_params["invalid_start"]
    error_on_invalid_access = test_params["expect_error_on_invalid_access"]
    ignore_hw_bkpt_result = test_params["ignore_hw_bkpt_result"]
    target_test_elf = test_params["test_elf"]

    assert ram_length >= MAX_TEST_SIZE
    stack_addr = ram_start + STACK_OFFSET
    test_ram_addr = ram_start + TEST_RAM_OFFSET

    fail_count = 0
    try:
        # Turn off confirmations that would block the script
        gdb_execute("set pagination off")
        gdb_execute("set confirm off")

        # Allow GDB to access even unmapped regions
        gdb_execute("set mem inaccessible-by-default off")

        # Set raw logging
        gdb_execute("set remotelogfile gdb_test_raw.txt")

        # Connect to server
        gdb_execute("target remote localhost:3334")

        # Possibly useful other commands for reference:
        # info breakpoints
        # info mem
        # show code-cache
        # show stack-cache
        # show dcache
        # show mem inaccessible-by-default
        # show can-use-hw-watchpoints
        # info all-registers
        # set logging file gdb.txt
        # set logging on

        # Test running the monitor commands
        for command in monitor_commands:
            gdb_execute("mon %s" % command)

        # Load target-specific test program into flash.
        gdb_execute("load %s" % target_test_elf)

        # Reset the target and let it run so it has
        # a chance to disable the watchdog
        gdb_execute("mon reset halt")
        gdb_execute("c&")
        event = yield(0.1)
        if not is_event_signal(event, "SIGINT"):
            fail_count += 1
            print("Error - target not interrupted as expected")

        # Load test program and symbols
        test_binary = "../src/gdb_test_program/gdb_test.bin"
        test_elf = "../src/gdb_test_program/gdb_test.elf"
        gdb_execute("restore %s binary 0x%x" % (test_binary, ram_start))
        gdb_execute("add-symbol-file %s 0x%x" % (test_elf, ram_start))

        # Set pc to the test program.  Make sure
        # interrupts are disabled to prevent
        # other code from running.
        gdb_execute("set $primask = 1")
        gdb_execute("set $sp = 0x%x" % stack_addr)
        gdb_execute("b main")
        breakpoint = gdb.Breakpoint("main")
        gdb_execute("set $pc = main")
        gdb_execute("c&")
        event = yield(DEFAULT_TIMEOUT)
        if not is_event_breakpoint(event, breakpoint):
            fail_count += 1
            print("Error - could not set pc to function")
        breakpoint.delete()

## Stepping removed as a workaround for a GDB bug. Launchpad issue tracking this is here:
## https://bugs.launchpad.net/gcc-arm-embedded/+bug/1700595
#
#        # Test the speed of the different step types
#        test_result["step_time_si"] = test_step_type("si")
#        test_result["step_time_s"] = test_step_type("s")
#        test_result["step_time_n"] = test_step_type("n")
        test_result["step_time_si"] = -1
        test_result["step_time_s"] = -1
        test_result["step_time_n"] = -1
        # TODO,c1728p9 - test speed getting stack trace
        # TODO,c1728p9 - test speed with cache turned on
        # TODO,c1728p9 - check speed vs breakpoints

        # Let target run to initialize variables
        gdb_execute("c&")
        event = yield(0.1)
        if not is_event_signal(event, "SIGINT"):
            fail_count += 1
            print("Error - target not interrupted as expected")

        # Check number of supported breakpoints, along
        # with graceful handling of a request using
        # more than the supported number of breakpoints
        break_list = []
        for i in range(MAX_BKPT):
            addr = rom_start + i * 4
            breakpoint = gdb.Breakpoint("*0x%x" % addr)
            break_list.append(breakpoint)
        while True:
            try:
                gdb_execute("c&")
                yield(0.1)
                break
            except gdb.error:
                bkpt = break_list.pop()
                bkpt.delete()
        test_result["breakpoint_count"] = len(break_list)
        for bkpt in break_list:
            bkpt.delete()

        # Check number of supported watchpoints, along
        # with graceful handling of a request using
        # more than the supported number of watchpoints
        watch_list = []
        for i in range(MAX_BKPT):
            addr = rom_start + i * 4
            breakpoint = gdb.Breakpoint("*0x%x" % addr,
                                        gdb.BP_WATCHPOINT, gdb.WP_ACCESS)
            watch_list.append(breakpoint)
        while True:
            try:
                gdb_execute("c&")
                yield(0.1)
                break
            except gdb.error:
                bkpt = watch_list.pop()
                bkpt.delete()
        test_result["watchpoint_count"] = len(watch_list)
        for bkpt in watch_list:
            bkpt.delete()

        # Make sure breakpoint is hit as expected
        rmt_func = "breakpoint_test"
        gdb_execute("set var run_breakpoint_test = 1")
        breakpoint = gdb.Breakpoint(rmt_func)
        gdb_execute("c&")
        event = yield(DEFAULT_TIMEOUT)
        if not is_event_breakpoint(event, breakpoint):
            fail_count += 1
            print("Error - breakpoint 1 test failed")
        func_name = gdb.selected_frame().function().name
        if rmt_func != func_name:
            fail_count += 1
            print("ERROR - break occurred at wrong function %s" % func_name)
        breakpoint.delete()
        gdb_execute("set var run_breakpoint_test = 0")

        # Let target run, make sure breakpoint isn't hit
        gdb_execute("set var run_breakpoint_test = 1")
        gdb_execute("c&")
        event = yield(0.1)
        if not is_event_signal(event, "SIGINT"):
            fail_count += 1
            print("Error - target not interrupted as expected")
        gdb_execute("set var run_breakpoint_test = 0")

        # Make sure hardware breakpoint is hit as expected
        rmt_func = "breakpoint_test"
        gdb_execute("set var run_breakpoint_test = 1")
        gdb_execute("hbreak %s" % rmt_func)
        gdb_execute("c&")
        event = yield(DEFAULT_TIMEOUT)
# TODO, c1728p9 - determine why there isn't a breakpoint event returned
#         if not is_event_breakpoint(event):
#             fail_count += 1
#             print("Error - breakpoint 2 test failed")
        func_name = gdb.selected_frame().function().name
        if rmt_func != func_name and not ignore_hw_bkpt_result:
            fail_count += 1
            print("ERROR - break occurred at wrong function %s" % func_name)
        gdb_execute("clear %s" % rmt_func)
        gdb_execute("set var run_breakpoint_test = 0")

        # Test valid memory write
        addr_value_list = [(test_ram_addr + i * 4,
                           randrange(1, 50)) for i in range(4)]
        for addr, value in addr_value_list:
            gdb_execute("set *((int *) 0x%x) = 0x%x" % (addr, value))

        # Test invalid memory write
        invalid_addr_list = [invalid_addr + i * 4 for i in range(4)]
        for addr in invalid_addr_list:
            try:
                gdb_execute("set *((int *) 0x%x) = 0x%x" % (addr, randrange(1, 50)))
                if error_on_invalid_access:
                    fail_count += 1
                    print("Error - invalid memory write did not fault @ 0x%x" % addr)
            except gdb.MemoryError:
                pass

        # Test valid memory read
        for addr, value in addr_value_list:
            val_read = gdb.parse_and_eval("*((int *) 0x%x)" % addr)
            val_read = int(val_read)
            assert value == val_read

        # Test invalid memory read
        for addr in invalid_addr_list:
            try:
                gdb_execute("x 0x%x" % addr)
                if error_on_invalid_access:
                    fail_count += 1
                    print("Error - invalid memory read did not fault @ 0x%x" % addr)
            except gdb.MemoryError:
                pass

        # Test watchpoints
        access_addr = long(gdb.parse_and_eval("&watchpoint_write_buffer[1]"))
        bkpt_sizes = [1, 2, 4]
        bkpt_accesses = ["read", "write", "read_write"]
        # use "range(-4, 8, 1)" for extended testing
        bkpt_addresses = [access_addr + offset for offset in range(0, 4, 1)]
        sizes = [1, 2, 4]
        accesses = ["read", "write", "read_write"]
        addresses = [access_addr]
        generator = product(bkpt_sizes, bkpt_accesses, bkpt_addresses,
                            sizes, accesses, addresses)
        for bkpt_size, bkpt_access, bkpt_addr, size, access, addr in generator:
            gdb_size = size_to_type(bkpt_size)
            gdb_access = to_gdb_access(bkpt_access)
            gdb_execute("set var watchpoint_write = %i" %
                        (1 if has_write(access) else 0))
            gdb_execute("set var watchpoint_read = %i" %
                        (1 if has_read(access) else 0))
            gdb_execute("set var watchpoint_size = %i" % size)
            gdb_execute("set var write_address = %i" % addr)
            breakpoint = gdb.Breakpoint("*(%s)0x%x" % (gdb_size, bkpt_addr),
                                        gdb.BP_WATCHPOINT, gdb_access)

            # Run until breakpoint is hit
            gdb_execute("c&")
            event = yield(0.1)
            bkpt_hit = not is_event_signal(event, "SIGINT")

            # Compare against expected result
            should_break = should_trigger_break(bkpt_size, bkpt_access,
                                                bkpt_addr, size, access, addr)
            valid = valid_watchpoint(bkpt_size, bkpt_access, bkpt_addr)

            if valid and bkpt_hit != should_break:
                fail_count += 1
                print("Error - watchpoint problem:")
                print("  Watchpoint was hit %s" % bkpt_hit)
                print("  Watchpoint should be hit %s" % should_break)
                print("  bkpt_size %s, bkpt_access %s, bkpt_address 0x%x, "
                      "size %s, access %s, addr 0x%x" %
                      (bkpt_size, bkpt_access, bkpt_addr, size, access, addr))
                print()

            breakpoint.delete()

        # TODO,c1728p9 - test reading/writing registers

        # TODO,c1728p9 - test stepping into interrupts

        # TODO,c1728p9 - test vector catch
            # -test hard fault handling
            # -test reset catch
        # TODO,c1728p9 - test signals/hard fault

        if fail_count:
            print("Test completed with %i errors" % fail_count)
        else:
            print("Test completed successfully")
    except:
        print("Main Error:")
        traceback.print_exc()
        fail_count += 1
    finally:
        test_result["fail_count"] = fail_count
        with open(TEST_RESULT_FILE, "wb") as f:
            f.write(json.dumps(test_result))
        gdb_execute("detach")
        gdb_execute("quit %i" % fail_count)


ignore_events = True
interrupt_timer = None
interrupt_arg = None
generator = run_test()


# Post task to halt the processor
def post_interrupt_task(interrupt_arg):
    # Halt the target by interrupting it
    # This must only run on GDB's queue
    def interrupt_task():
        if not interrupt_arg["aborted"]:
            gdb_execute("interrupt")
    gdb.post_event(interrupt_task)


# Run the main test by repreatedly calling the generator
# This must only run on GDB's queue
def run_generator(event):
    global ignore_events
    global interrupt_timer
    global interrupt_arg
    ignore_events = True
    if interrupt_timer is not None:
        interrupt_timer.cancel()
        interrupt_arg["aborted"] = True
    interrupt_arg = None
    stop_delay = 0
    try:
        stop_delay = generator.send(event)
    except:
        print("Error")
        traceback.print_exc()
    interrupt_arg = {"aborted": False}
    interrupt_timer = Timer(stop_delay, post_interrupt_task, [interrupt_arg])
    interrupt_timer.start()
    ignore_events = False


# Runs on stop events and posts run_generator to the
# main queue so it can continue execution
def stop_handler(event):
    if ignore_events:
        return
    bound_run_generator = partial(run_generator, event)
    gdb.post_event(bound_run_generator)
gdb.events.stop.connect(stop_handler)

# Start testing
bound_run_generator = partial(run_generator, None)
gdb.post_event(bound_run_generator)
