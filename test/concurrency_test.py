# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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
import struct
import traceback
import argparse
import logging
from itertools import (chain, repeat)

from pyocd.core.helpers import ConnectHelper
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.utility.conversion import float32_to_u32
from pyocd.utility.mask import same
from pyocd.utility.compatibility import to_str_safe
from pyocd.core.memory_map import MemoryType

from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    run_in_parallel,
    )

# Test configuration values.        
TEST_MAX_LENGTH = 1 * 1024 * 1024
TEST_THREAD_COUNT = 8
TEST_SUBCHUNK_COUNT = 2 # Number of reads/writes per thread.

def ncycles(iterable, n):
    return chain.from_iterable(repeat(tuple(iterable), n))

class ConcurrencyTestResult(TestResult):
    def __init__(self):
        super(ConcurrencyTestResult, self).__init__(None, None, None)
        self.name = "concurrency"

class ConcurrencyTest(Test):
    def __init__(self):
        super(ConcurrencyTest, self).__init__("Concurrency Test", concurrency_test)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            result = ConcurrencyTestResult()
            result.passed = False
            print("Exception %s when testing board %s" % (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def concurrency_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target = session.target

        test_params = get_target_test_params(session)
        session.probe.set_clock(test_params['test_clock'])

        memory_map = target.get_memory_map()
        boot_region = memory_map.get_boot_memory()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)

        test_pass_count = 0
        test_count = 0
        result = ConcurrencyTestResult()
        
        target.reset_and_halt()
        
        # Prepare TEST_THREAD_COUNT regions of RAM with patterns
        data_len = min(TEST_MAX_LENGTH, ram_region.length)
        chunk_len = data_len // TEST_THREAD_COUNT
        subchunk_len = chunk_len // TEST_SUBCHUNK_COUNT
        
        chunk_data = []
        for i in range(TEST_THREAD_COUNT):
            chunk_data.append([(i + j) % 256 for j in range(chunk_len)])
        
        def write_chunk_data(core, i):
            start = ram_region.start + chunk_len * i
            for j in range(TEST_SUBCHUNK_COUNT):
                offset = subchunk_len * j
                addr = start + offset
                end = addr + subchunk_len - 1
                print("Writing region %i:%i from %#010x to %#010x via %s" % (i, j, addr, end, core.ap))
                core.write_memory_block8(addr, chunk_data[i][offset:offset + subchunk_len])
                print("Finished writing region %i:%i" % (i, j))

        def read_chunk_data(core, i):
            start = ram_region.start + chunk_len * i
            for j in range(TEST_SUBCHUNK_COUNT):
                offset = subchunk_len * j
                addr = start + offset
                end = addr + subchunk_len - 1
                print("Reading region %i:%i from %#010x to %#010x via %s" % (i, j, addr, end, core.ap))
                data = core.read_memory_block8(addr, subchunk_len)
                chunk_read_data[i].extend(data)
                print("Finished reading region %i:%i" % (i, j))
        
        # Test with a single core/AP.
        print("\n------ Test 1: Concurrent memory accesses, single core ------")
        
        core = target.cores[0]

        # Write chunk patterns concurrently.
        print("Writing %i regions to RAM" % TEST_THREAD_COUNT)
        run_in_parallel(write_chunk_data, [[core, i] for i in range(TEST_THREAD_COUNT)])
        
        print("Reading %i regions to RAM" % TEST_THREAD_COUNT)
        chunk_read_data = [list() for i in range(TEST_THREAD_COUNT)]
        run_in_parallel(read_chunk_data, [[core, i] for i in range(TEST_THREAD_COUNT)])
        
        print("Comparing data")
        
        for i in range(TEST_THREAD_COUNT):
            test_count += 1
            if same(chunk_read_data[i], chunk_data[i]):
                test_pass_count += 1
                print("Region %i PASSED" % i)
            else:
                print("Region %i FAILED" % i)
        
        # Test with a multiple cores/APs.
        # Disabled until cores each have their own memory map, the regions accessible to each
        # core can be identified.
        if False: # len(target.cores) > 1:
            print("\n------ Test 2: Concurrent memory accesses, multiple cores ------")
            
            cycle_count = ((len(target.cores) + TEST_THREAD_COUNT - 1) // TEST_THREAD_COUNT * TEST_THREAD_COUNT)
            repeat_cores = ncycles(iter(target.cores), cycle_count)
            thread_args = []
            for i in range(TEST_THREAD_COUNT):
                thread_args.append((target.cores[next(repeat_cores)], i))

            # Write chunk patterns concurrently.
            print("Writing %i regions to RAM" % TEST_THREAD_COUNT)
            run_in_parallel(write_chunk_data, thread_args)
        
            print("Reading %i regions to RAM" % TEST_THREAD_COUNT)
            chunk_read_data = [list() for i in range(TEST_THREAD_COUNT)]
            run_in_parallel(read_chunk_data, thread_args)
        
            print("Comparing data")
        
            for i in range(TEST_THREAD_COUNT):
                test_count += 1
                if same(chunk_read_data[i], chunk_data[i]):
                    test_pass_count += 1
                    print("Region %i PASSED" % i)
                else:
                    print("Region %i FAILED" % i)

        # --- end ---
        print("\nTest Summary:")
        print("Pass count %i of %i tests" % (test_pass_count, test_count))
        if test_pass_count == test_count:
            print("CONCURRENCY TEST PASSED")
        else:
            print("CONCURRENCY TEST FAILED")

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD concurrency test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    # Set to debug to print some of the decisions made while flashing
    session = ConnectHelper.session_with_chosen_probe(**get_session_options())
    test = ConcurrencyTest()
    result = [test.run(session.board)]

