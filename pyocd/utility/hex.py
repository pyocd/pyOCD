# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

import sys

def format_hex_width(value, width):
    if width == 8:
        return "%02x" % value
    elif width == 16:
        return "%04x" % value
    elif width == 32:
        return "%08x" % value
    else:
        raise ValueError("unrecognized register width (%d)" % width)

def dump_hex_data(data, startAddress=0, width=8, output=None):
    if output is None:
        output = sys.stdout
    i = 0
    while i < len(data):
        output.write("%08x:  " % (startAddress + (i * (width // 8))))

        while i < len(data):
            d = data[i]
            i += 1
            if width == 8:
                output.write("%02x " % d)
                if i % 4 == 0:
                    output.write(" ")
                if i % 16 == 0:
                    break
            elif width == 16:
                output.write("%04x " % d)
                if i % 8 == 0:
                    break
            elif width == 32:
                output.write("%08x " % d)
                if i % 4 == 0:
                    break
        output.write("\n")
