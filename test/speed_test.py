# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import os
import sys
from time import (sleep, time)
from random import randrange
import traceback
import argparse
import logging

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess
from pyocd.core.memory_map import MemoryType
from pyocd.utility import conversion

from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params
    )

_1MB = (1 * 1024 * 1024)

class SpeedTestResult(TestResult):
    def __init__(self):
        super(SpeedTestResult, self).__init__(None, None, None)
        self.name = "speed"

class SpeedTest(Test):
    def __init__(self):
        super(SpeedTest, self).__init__("Speed Test", speed_test)

    def print_perf_info(self, result_list, output_file=None):
        format_str = "{:<15}{:>18}{:>18}{:>18}"
        result_list = filter(lambda x: isinstance(x, SpeedTestResult), result_list)
        print("\n\n------ Speed Test Performance ------", file=output_file)
        print(format_str.format("Target", "RAM Read Speed", "RAM Write Speed", "ROM Read Speed"),
              file=output_file)
        print("", file=output_file)
        for result in result_list:
            if result.passed:
                read_speed = "%.3f KB/s" % (float(result.read_speed) / float(1000))
                write_speed = "%.3f KB/s" % (float(result.write_speed) / float(1000))
                rom_read_speed = "%.3f KB/s" % (float(result.rom_read_speed) / float(1000))
            else:
                read_speed = "Fail"
                write_speed = "Fail"
                rom_read_speed = "Fail"
            print(format_str.format(result.board,
                                    read_speed, write_speed, rom_read_speed),
                  file=output_file)
        print("", file=output_file)

    def run(self, board):
        passed = False
        read_speed = None
        write_speed = None
        try:
            result = self.test_function(board.unique_id)
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.unique_id))
            result = SpeedTestResult()
            result.passed = False
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result


def speed_test(board_id):
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target_type = board.target_type

        memory_map = board.target.get_memory_map()
        ram_region = memory_map.get_default_region_of_type(MemoryType.RAM)
        rom_region = memory_map.get_boot_memory()

        # Limit region sizes used for performance testing to 1 MB. We don't really need to
        # be reading all 32 MB of a QSPI!
        ram_start = ram_region.start
        ram_size = min(ram_region.length, _1MB)
        rom_start = rom_region.start
        rom_size = min(rom_region.length, _1MB)

        target = board.target

        test_pass_count = 0
        test_count = 0
        result = SpeedTestResult()

        test_params = get_target_test_params(session)
        session.probe.set_clock(test_params['test_clock'])
        
        test_config = "uncached 8-bit"

        def test_ram(record_speed=False, width=8):
            print("\n\n------ TEST RAM READ / WRITE SPEED [%s] ------" % test_config)
            test_addr = ram_start
            test_size = ram_size
            data = [randrange(1, 50) for x in range(test_size)]
            start = time()
            if width == 8:
                target.write_memory_block8(test_addr, data)
            elif width == 32:
                target.write_memory_block32(test_addr, conversion.byte_list_to_u32le_list(data))
            target.flush()
            stop = time()
            diff = stop - start
            if diff == 0:
                print("Unexpected ram write elapsed time of 0!")
                write_speed = 0
            else:
                write_speed = test_size / diff
            if record_speed:
                result.write_speed = write_speed
            print("Writing %i byte took %.3f seconds: %.3f B/s" % (test_size, diff, write_speed))
            start = time()
            if width == 8:
                block = target.read_memory_block8(test_addr, test_size)
            elif width == 32:
                block = conversion.u32le_list_to_byte_list(target.read_memory_block32(test_addr, test_size // 4))
            target.flush()
            stop = time()
            diff = stop - start
            if diff == 0:
                print("Unexpected ram read elapsed time of 0!")
                read_speed = 0
            else:
                read_speed = test_size / diff
            if record_speed:
                result.read_speed = read_speed
            print("Reading %i byte took %.3f seconds: %.3f B/s" % (test_size, diff, read_speed))
            error = False
            if len(block) != len(data):
                error = True
                print("ERROR: read length (%d) != write length (%d)!" % (len(block), len(data)))
            if not error:
                for i in range(len(block)):
                    if (block[i] != data[i]):
                        error = True
                        print("ERROR: 0x%X, 0x%X, 0x%X!!!" % ((test_addr + i), block[i], data[i]))
            if error:
                print("TEST FAILED")
            else:
                print("TEST PASSED")
            return not error

        def test_rom(record_speed=False, width=8):
            print("\n\n------ TEST ROM READ SPEED [%s] ------" % test_config)
            test_addr = rom_start
            test_size = rom_size
            start = time()
            if width == 8:
                block = target.read_memory_block8(test_addr, test_size)
            elif width == 32:
                block = conversion.u32le_list_to_byte_list(target.read_memory_block32(test_addr, test_size // 4))
            target.flush()
            stop = time()
            diff = stop - start
            if diff == 0:
                print("Unexpected rom read elapsed time of 0!")
                read_speed = 0
            else:
                read_speed = test_size / diff
            if record_speed:
                result.rom_read_speed = read_speed
            print("Reading %i byte took %.3f seconds: %.3f B/s" % (test_size, diff, read_speed))
            print("TEST PASSED")
            return True
        
        # 8-bit without memcache
        passed = test_ram(True, 8)
        test_count += 1
        test_pass_count += int(passed)
        
        passed = test_rom(True, 8)
        test_count += 1
        test_pass_count += int(passed)
        
        # 32-bit without memcache
        test_config = "uncached 32-bit"
        passed = test_ram(False, 32)
        test_count += 1
        test_pass_count += int(passed)
        
        passed = test_rom(False, 32)
        test_count += 1
        test_pass_count += int(passed)
        
        # With memcache
        target = target.get_target_context()
        test_config = "cached 8-bit, pass 1"
        
        passed = test_ram()
        test_count += 1
        test_pass_count += int(passed)
        
        passed = test_rom()
        test_count += 1
        test_pass_count += int(passed)
        
        # Again with memcache
        test_config = "cached 8-bit, pass 2"
        passed = test_ram()
        test_count += 1
        test_pass_count += int(passed)
        
        passed = test_rom()
        test_count += 1
        test_pass_count += int(passed)

        board.target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD speed test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    DAPAccess.set_args(args.daparg)
    session = ConnectHelper.session_with_chosen_probe(**get_session_options())
    test = SpeedTest()
    result = [test.run(session.board)]
    test.print_perf_info(result)
