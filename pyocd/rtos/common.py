# pyOCD debugger
# Copyright (c) 2016 Arm Limited
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

from ..core import exceptions
import logging

## @brief Reads a null-terminated C string from the target.
def read_c_string(context, ptr):
    if ptr == 0:
        return ""

    s = ""
    done = False
    count = 0
    badCount = 0
    try:
        while not done and count < 256:
            data = context.read_memory_block8(ptr, 16)
            ptr += 16
            count += 16

            for c in data:
                if c == 0:
                    done = True
                    break
                elif c > 127:
                    # Replace non-ASCII characters. If there is a run of invalid characters longer
                    # than 4, then terminate the string early.
                    badCount += 1
                    if badCount > 4:
                        done = True
                        break
                    s += '?'
                else:
                    s += chr(c)
                    badCount = 0
    except exceptions.TransferError:
        logging.debug("TransferError while trying to read 16 bytes at 0x%08x", ptr)

    return s

