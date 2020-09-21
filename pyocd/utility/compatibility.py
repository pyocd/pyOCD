# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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
    iter_single_bytes = functools.partial(map, lambda v: bytes((v,))) # pylint: disable=invalid-name
else:
    iter_single_bytes = iter # pylint: disable=invalid-name

# to_bytes_safe() converts a unicode string to a bytes object by encoding as
# latin-1. It will also accept a value that is already a bytes object and
# return it unmodified.
if PY3:
    def to_bytes_safe(v):
        if type(v) is str:
            return v.encode('utf-8')
        else:
            return v
else:
    def to_bytes_safe(v):
        if type(v) is unicode:
            return v.encode('utf-8')
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
            return v.decode('utf-8')
else:
    def to_str_safe(v):
        if type(v) is unicode:
            return v.encode('utf-8')
        else:
            return v

# Make FileNotFoundError available to Python 2.x.
try:
    FileNotFoundError = FileNotFoundError
except NameError:
    FileNotFoundError = OSError

# zipfile from Python 2 has a misspelled BadZipFile exception class.
try:
    from zipfile import BadZipFile
except ImportError:
    from zipfile import BadZipfile as BadZipFile

try:
    from shutil import get_terminal_size
except ImportError:
    # From http://stackoverflow.com/a/566752/2646228
    def get_terminal_size():
        import os
        env = os.environ
        def ioctl_GWINSZ(fd):
            try:
                import fcntl, termios, struct, os
                cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
            except:
                return
            return cr
        cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
        if not cr:
            try:
                fd = os.open(os.ctermid(), os.O_RDONLY)
                cr = ioctl_GWINSZ(fd)
                os.close(fd)
            except:
                pass
        if not cr:
            cr = (env.get('LINES', 25), env.get('COLUMNS', 80))
        return int(cr[1]), int(cr[0])
