"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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
from struct import unpack

with open("main.bin", "rb") as f:
    data = f.read()

words = len(data) / 4
str = "<L%i" % words
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

with open("main.py", "wb") as f:
    f.write(data)
