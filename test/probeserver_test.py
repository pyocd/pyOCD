# pyOCD debugger
# Copyright (c) 2021 Arm Limited
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

# Note
#  To run this script GNU Tools ARM Embedded must be installed,
#  along with python for the same architecture.  The program
#  "arm-none-eabi-gdb-py.exe" requires python for the same
#  architecture (x86 or 64) to work correctly. Also, on windows
#  the GNU Tools ARM Embedded bin directory needs to be added to
#  your path.

import os
import json
import sys
from subprocess import (
    Popen,
    STDOUT,
    PIPE,
    check_output,
    )
import argparse
import logging
import traceback
import threading
from time import sleep

from pyocd.__main__ import PyOCDTool
from pyocd.core.helpers import ConnectHelper
from pyocd.utility.compatibility import to_str_safe
from pyocd.core.memory_map import MemoryType
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.utility.timeout import Timeout
from test_util import (
    Test,
    TestResult,
    get_session_options,
    get_target_test_params,
    binary_to_elf_file,
    get_env_file_name,
    get_test_binary_path,
    TEST_DIR,
    TEST_OUTPUT_DIR,
    ensure_output_dir,
    wait_with_deadline,
    )

LOG = logging.getLogger(__name__)

TEST_TIMEOUT_SECONDS = 60.0 * 5

class TestError(Exception):
    pass

class ProbeserverTestResult(TestResult):
    def __init__(self):
        super(self.__class__, self).__init__(None, None, None)
        self.name = "probeserver"

class ProbeserverTest(Test):
    def __init__(self):
        super(self.__class__, self).__init__("Probeserver Test", test_probeserver)

    def run(self, board):
        try:
            result = self.test_function(board.unique_id, self.n)
        except Exception as e:
            result = ProbeserverTestResult()
            result.passed = False
            print("Exception %s when testing board %s" %
                  (e, board.unique_id))
            traceback.print_exc(file=sys.stdout)
        result.board = board
        result.test = self
        return result

def test_probeserver(board_id=None, n=0):
    test_port = 5555 + n
    temp_test_elf_name = None
    result = ProbeserverTestResult()
    print("Connecting to identify target")
    with ConnectHelper.session_with_chosen_probe(unique_id=board_id, **get_session_options()) as session:
        board = session.board
        target_test_params = get_target_test_params(session)
        binary_file = get_test_binary_path(board.test_binary)
        if board_id is None:
            board_id = board.unique_id
        target_type = board.target_type

    # Run the test. We can't kill the server thread, so 
    LOG.info('Starting server on port %d', test_port)
    server_args = ['pyocd', 'server',
            '-v',
            '--port=%i' % test_port,
            "--uid=%s" % board_id,
            ]
    server_program = Popen(server_args, stdout=PIPE, stderr=STDOUT)
    
    try:
        # Read server output waiting for it to report that the server is running.
        with Timeout(TEST_TIMEOUT_SECONDS) as time_out:
            while time_out.check():
                ln = server_program.stdout.readline().decode('ascii')
                print("Server:", ln, end='')
                if "Serving debug probe" in ln:
                    break
                if ln == '':
                    raise TestError("no more output from server")
            else:
                raise TestError("server failed to start")
    
        server_thread = threading.Thread(target=wait_with_deadline, args=[server_program, TEST_TIMEOUT_SECONDS])
        server_thread.daemon = True
        server_thread.start()

        # Start client in a thread.
        client_args = ['flash',
                "--frequency=%i" % target_test_params['test_clock'],
                "--uid=remote:localhost:%d" % test_port,
                "--target=%s" % target_type,
                binary_file
                ]
        client = PyOCDTool()
        LOG.info('Starting client: %s', ' '.join(client_args))
        client_thread = threading.Thread(target=client.run, args=[client_args])
        client_thread.daemon = True
        client_thread.start()

        LOG.info('Waiting for client to finish...')
        client_thread.join(timeout=TEST_TIMEOUT_SECONDS)
        did_complete = not client_thread.is_alive()
        if not did_complete:
            LOG.error("Test timed out!")
        LOG.info("killing probe server process")
        server_program.kill()
    except TestError as err:
        LOG.info("test failed: %s", err)
        did_complete = False
        if server_program.returncode is None:
            server_program.kill()

    # Read back the result
    result.passed = did_complete

    if result.passed:
        print("PROBESERVER TEST PASSED")
    else:
        print("PROBESERVER TEST FAILED")

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pyOCD probeserver test')
    parser.add_argument('-u', '--uid', help='Debug probe unique ID')
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug logging')
    args = parser.parse_args()
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level)
    ensure_output_dir()
    test_probeserver(args.uid)
