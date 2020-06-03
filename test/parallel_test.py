# pyOCD debugger
# Copyright (c) 2016-2020 Arm Limited
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

import threading
import multiprocessing

from pyocd.core.helpers import ConnectHelper
from pyocd.probe.pydapaccess import DAPAccess

from test_util import run_in_parallel

def run_in_processes(function, args_list):
    """Create and run a processes in parallel for each element in args_list

    Wait until all processes finish executing. Throw an exception if an
    exception occurred on any of the processes.
    """
    process_list = []
    for args in args_list:
        process = multiprocessing.Process(target=function, args=args)
        process.start()
        process_list.append(process)

    error_during_run = False
    for process in process_list:
        process.join()
        if process.exitcode != 0:
            error_during_run = True
    if error_during_run:
        raise Exception("Running in process failed")


def list_boards(id_list):
    """List all connected DAPLink boards repeatedly

    Assert that they are the same as the id list passed in.
    """
    for _ in range(0, 20):
        device_list = DAPAccess.get_connected_devices()
        found_id_list = [device.get_unique_id() for device in device_list]
        found_id_list.sort()
        assert id_list == found_id_list, "Expected %s, got %s" % \
            (id_list, found_id_list)


def search_and_lock(board_id):
    """Repeatedly lock a board with the given ID"""
    for _ in range(0, 20):
        device = DAPAccess.get_device(board_id)
        device.open()
        device.close()
        with ConnectHelper.session_with_chosen_probe(unique_id=board_id):
            pass


def open_already_opened(board_id):
    """Open a device that is already open to verify it gives an error"""
    device = DAPAccess.get_device(board_id)
    try:
        device.open()
        assert False
    except DAPAccess.DeviceError:
        pass


def parallel_test():
    """Test that devices can be found and opened in parallel"""
    device_list = DAPAccess.get_connected_devices()
    id_list = [device.get_unique_id() for device in device_list]
    id_list.sort()

    if len(id_list) < 2:
        print("Need at least 2 boards to run the parallel test")
        exit(-1)

    # Goal of this file is to test that:
    # -The process of listing available boards does not interfere
    #  with other processes enumerating, opening, or using boards
    # -Opening and using a board does not interfere with another process
    #  processes which is enumerating, opening, or using boards as
    # long as that is not the current board

    print("Listing board from multiple threads at the same time")
    args_list = [(id_list,) for _ in range(5)]
    run_in_parallel(list_boards, args_list)

    print("Listing board from multiple processes at the same time")
    run_in_processes(list_boards, args_list)

    print("Opening same board from multiple threads at the same time")
    device = DAPAccess.get_device(id_list[0])
    device.open()
    open_already_opened(id_list[0])
    args_list = [(id_list[0],) for _ in range(5)]
    run_in_parallel(open_already_opened, args_list)
    device.close()

    print("Opening same board from multiple processes at the same time")
    device = DAPAccess.get_device(id_list[0])
    device.open()
    open_already_opened(id_list[0])
    args_list = [(id_list[0],) for _ in range(5)]
    run_in_processes(open_already_opened, args_list)
    device.close()

    print("Opening different boards from different threads")
    args_list = [(board_id,) for board_id in id_list]
    run_in_parallel(search_and_lock, args_list)

    print("Opening different boards from different processes")
    run_in_processes(search_and_lock, args_list)

    print("Test passed")


if __name__ == "__main__":
    multiprocessing.set_start_method('spawn')
    parallel_test()
