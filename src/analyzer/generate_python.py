# pyOCD debugger
# Copyright (c) 2006-2015,2020 Arm Limited
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
import sys
from struct import unpack

INPUT_FILENAME = sys.argv[1]
OUTPUT_FILENAME = sys.argv[2]

with open(INPUT_FILENAME, "rb") as f:
    data = f.read()

words = len(data) // 4
if len(data) % 4 != 0:
    print("Warning: input length not word aligned")
print("Data length %i" % len(data))
data = unpack("<%iL" % words, data)

str = "analyzer = (\n    "
count = 0
for val in data:
    if count % 8 == 7:
        str += "0x{:08x},\n    ".format(val)
    else:
        str += "0x{:08x}, ".format(val)
    count += 1
str += "\n    )"
data = str

with open(OUTPUT_FILENAME, "w") as f:
    f.write(data)
