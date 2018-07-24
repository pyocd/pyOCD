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
import functools

PY3 = sys.version_info[0] == 3

# iter_single_bytes() returns an iterator over a bytes object that produces
# single-byte bytes objects for each byte in the passed in value. Normally on
# py3 iterating over a bytes will give you ints for each byte, while on py3
# you'll get single-char strs.
if PY3:
    iter_single_bytes = functools.partial(map, lambda v: bytes((v,)))
else:
    iter_single_bytes = iter

# to_bytes_safe() converts a unicode string to a bytes object by encoding as
# latin-1. It will also accept a value that is already a bytes object and
# return it unmodified.
if PY3:
    def to_bytes_safe(v):
        if type(v) is str:
            return v.encode('latin-1')
        else:
            return v
else:
    def to_bytes_safe(v):
        if type(v) is unicode:
            return v.encode('latin-1')
        else:
            return v

# to_str_safe() converts a bytes object to a unicode string by decoding from
# latin-1. It will also accept a value that is already a str object and
# return it unmodified.
if PY3:
    def to_str_safe(v):
        if type(v) is str:
            return v
        else:
            return v.decode('latin-1')
else:
    def to_str_safe(v):
        if type(v) is unicode:
            return v.decode('latin-1')
        else:
            return v

