"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

import os, sys
from time import sleep, time
from random import randrange
import traceback
import argparse

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parentdir)

import pyOCD
from pyOCD.board import MbedBoard
from test_util import Test, TestResult
import logging

USB_TEST_XFER_COUNT = 128 * 1024 / 64  # 128 KB = 2K usb packets

class SpeedTestResult(TestResult):
    def __init__(self):
        super(SpeedTestResult, self).__init__(None, None, None)

class SpeedTest(Test):
    def __init__(self):
        super(SpeedTest, self).__init__("Speed Test", speed_test)

    def print_perf_info(self, result_list):
        result_list = filter(lambda x : isinstance(x, SpeedTestResult), result_list)
        print("\r\n\r\n------ Speed Test Performance ------")
        print("{:<10}{:<16}{:<16}{:<16}{:<16}".format("Target","Write Speed","Read Speed", "USB speed", "USB overlap speed"))
        print("")
        for result in result_list:
            if result.passed:
                read_speed = "%f KB/s" % (float(result.read_speed) / float(1000))
                write_speed = "%f KB/s" % (float(result.write_speed) / float(1000))
                usb_speed = "%f KB/s" % (float(result.usb_speed) / float(1000))
                usb_overlapped = "%f KB/s" % (float(result.usb_overlapped) / float(1000))
            else:
                read_speed = "Fail"
                write_speed = "Fail"
                usb_speed = "Fail"
                usb_overlapped = "Fail"
            print("{:<10}{:<16}{:<16}{:<16}{:<16}".format(result.board.target_type, read_speed, write_speed, usb_speed, usb_overlapped))
        print("")

    def run(self, board):
        passed = False
        read_speed = None
        write_speed = None
        try:
            result = self.test_function(board.getUniqueID())
        except Exception as e:
            print("Exception %s when testing board %s" % (e, board.getUniqueID()))
            result = SpeedTestResult()
            result.passed = False
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result


def speed_test(board_id):
    with MbedBoard.chooseBoard(board_id = board_id, frequency = 1000000) as board:
        target_type = board.getTargetType()

        test_clock = 10000000
        if target_type == "kl25z":
            ram_start = 0x1ffff000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x20000
        elif target_type == "kl28z":
            ram_start = 0x1fffa000
            ram_size = 96*1024
            rom_start = 0x00000000
            rom_size = 512*1024
        elif target_type == "kl46z":
            ram_start = 0x1fffe000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x40000
        elif target_type == "k22f":
            ram_start = 0x1fff0000
            ram_size = 0x20000
            rom_start = 0x00000000
            rom_size = 0x80000
        elif target_type == "k64f":
            ram_start = 0x1FFF0000
            ram_size = 0x40000
            rom_start = 0x00000000
            rom_size = 0x100000
        elif target_type == "lpc11u24":
            ram_start = 0x10000000
            ram_size = 0x2000
            rom_start = 0x00000000
            rom_size = 0x8000
        elif target_type == "lpc1768":
            ram_start = 0x10000000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x80000
        elif target_type == "lpc800":
            ram_start = 0x10000000
            ram_size = 0x1000
            rom_start = 0x00000000
            rom_size = 0x4000
        elif target_type == "lpc4330":
            ram_start = 0x10000000
            ram_size = 0x20000
            rom_start = 0x14000000
            rom_size = 0x100000
        elif target_type == "nrf51":
            ram_start = 0x20000000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x40000
            # Override clock since 10MHz is too fast
            test_clock = 1000000
        elif target_type == "maxwsnenv":
            ram_start = 0x20000000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x40000
        elif target_type == "max32600mbed":
            ram_start = 0x20000000
            ram_size = 0x8000
            rom_start = 0x00000000
            rom_size = 0x40000
        elif target_type == "w7500":
            ram_start = 0x20000000
            ram_size = 0x4000
            rom_start = 0x00000000
            rom_size = 0x20000
        else:
            raise Exception("The board is not supported by this test script.")

        target = board.target
        transport = board.transport
        flash = board.flash
        interface = board.interface

        test_pass_count = 0
        test_count = 0
        result = SpeedTestResult()

        transport.setClock(test_clock)
        transport.setDeferredTransfer(True)

        print "\r\n\r\n------ TEST USB TRANSFER SPEED ------"
        max_packets = interface.getPacketCount()
        data_to_write = [0x80] + [0x00] * 63
        start = time()
        packet_count = USB_TEST_XFER_COUNT
        while packet_count > 0:
                interface.write(data_to_write)
                interface.read()
                packet_count = packet_count - 1
        stop = time()
        result.usb_speed = USB_TEST_XFER_COUNT * 64 / (stop-start)
        print "USB transfer rate %f B/s" % result.usb_speed

        print "\r\n\r\n------ TEST OVERLAPPED USB TRANSFER SPEED ------"
        max_packets = interface.getPacketCount()
        print("Concurrent packets: %i" % max_packets)
        data_to_write = [0x80] + [0x00] * 63
        start = time()
        packet_count = USB_TEST_XFER_COUNT
        reads_pending = 0
        while packet_count > 0 or reads_pending > 0:
            # Make sure the transmit buffer stays saturated
            while packet_count > 0 and reads_pending < max_packets:
                interface.write(data_to_write)
                packet_count = packet_count - 1
                reads_pending = reads_pending + 1

            # Read data
            if reads_pending > 0:
                interface.read()
                reads_pending = reads_pending - 1
        stop = time()
        result.usb_overlapped = USB_TEST_XFER_COUNT * 64 / (stop-start)
        print "USB transfer rate %f B/s" % result.usb_overlapped

        print "\r\n\r\n------ TEST RAM READ / WRITE SPEED ------"
        test_addr = ram_start
        test_size = ram_size
        data = [randrange(1, 50) for x in range(test_size)]
        start = time()
        target.writeBlockMemoryUnaligned8(test_addr, data)
        stop = time()
        diff = stop-start
        result.write_speed = test_size / diff
        print("Writing %i byte took %s seconds: %s B/s" % (test_size, diff,  result.write_speed))
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        stop = time()
        diff = stop-start
        result.read_speed = test_size / diff
        print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  result.read_speed))
        error = False
        for i in range(len(block)):
            if (block[i] != data[i]):
                error = True
                print "ERROR: 0x%X, 0x%X, 0x%X!!!" % ((addr + i), block[i], data[i])
        if error:
            print "TEST FAILED"
        else:
            print "TEST PASSED"
            test_pass_count += 1
        test_count += 1

        print "\r\n\r\n------ TEST ROM READ SPEED ------"
        test_addr = rom_start
        test_size = rom_size
        start = time()
        block = target.readBlockMemoryUnaligned8(test_addr, test_size)
        stop = time()
        diff = stop-start
        print("Reading %i byte took %s seconds: %s B/s" % (test_size, diff,  test_size / diff))
        print "TEST PASSED"
        test_pass_count += 1
        test_count += 1

        target.reset()

        result.passed = test_count == test_pass_count
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD speed test')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    board = pyOCD.board.mbed_board.MbedBoard.getAllConnectedBoards(close = True)[0]
    test = SpeedTest()
    result = [test.run(board)]
    test.print_perf_info(result)
