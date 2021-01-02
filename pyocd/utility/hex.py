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
import string
import six

from . import conversion

## ASCII printable characters not including whitespace that changes line position.
_PRINTABLE = string.digits + string.ascii_letters + string.punctuation + ' '

def format_hex_width(value, width):
    """! @brief Formats the value as hex of the specified bit width.
    
    @param value Integer value to be formatted.
    @param width Bit width, must be one of 8, 16, 32, 64.
    @return String with (width / 8) hex digits. Does not have a "0x" prefix.
    """
    if width == 8:
        return "%02x" % value
    elif width == 16:
        return "%04x" % value
    elif width == 32:
        return "%08x" % value
    elif width == 64:
        return "%016x" % value
    else:
        raise ValueError("unrecognized register width (%d)" % width)

def dump_hex_data(data, start_address=0, width=8, output=None, print_ascii=True):
    """! @brief Prints a canonical hex dump of the given data.
    
    Each line of the output consists of an address column, the data as hex, and a printable ASCII
    representation of the data.
    
    The @a width parameter controls grouping of the hex bytes in the output. The bytes of the
    provided data are progressively read as little endian values of the specified bit width, then
    printed at that width. For example, for input data of [0x61 0x62 0x63 0x64], if @width is set to
    8 the output will be "61 62 63 64", for 16 it will be printed as "6261 6463", and for 32 bit
    width it will be shown as "64636261". A space is inserted after each bit-width value, with an
    extra space every 4 bytes for 8 bit width.
    
    The output looks similar to this (width of 8):
    ```
    00000000:  85 89 70 0f  20 b1 ff bc  a9 0c c8 3c  bc a6 47 dd    ..p. ......<..G.
    00000010:  c8 c9 66 ab  59 c8 35 6c  57 94 00 c8  17 35 85 b2    ..f.Y.5lW....5..
    ```
    
    The output is always terminated with a newline.
    
    If you want a string instead of output to a file, use the dump_hex_data_to_str() function.
    
    @param data The data to print as hex. Can be a `bytes`, `bytearray`, or list of integers.
    @param start_address Address of the first byte of the data. Defaults to 0. If set to None,
        then the address column is not printed.
    @param width Controls grouping of the hex bytes in the output as described above. Must be one of
        (8, 16, 32, 64).
    @param output Optional file where the output will be written. If not provided, sys.stdout is
        used.
    @param print_ascii Whether to include the printable ASCII column. Defaults to True.
    """
    if output is None:
        output = sys.stdout
    if width == 8:
        line_width = 16
    elif width == 16:
        line_width = 8
    elif width == 32:
        line_width = 4
    elif width == 64:
        line_width = 2
    i = 0
    while i < len(data):
        if start_address is not None:
            output.write("%08x:  " % (start_address + (i * (width // 8))))

        start_i = i
        while i < len(data):
            d = data[i]
            i += 1
            if width == 8:
                output.write("%02x " % d)
                if (i % 4 == 0) and not (i % line_width == 0):
                    output.write(" ")
            elif width == 16:
                output.write("%04x " % d)
            elif width == 32:
                output.write("%08x " % d)
            elif width == 64:
                output.write("%016x " % d)
            if i % line_width == 0:
                break
        
        if print_ascii:
            s = "|"
            for n in range(start_i, start_i + line_width):
                if n >= len(data):
                    break
                d = data[n]
                if width == 8:
                    d = [d]
                else:
                    d = conversion.nbit_le_list_to_byte_list([d], width)
                    d.reverse()
                s += "".join((chr(b) if (chr(b) in _PRINTABLE) else '.') for b in d)
            output.write("   " + s + "|")
        
        output.write("\n")

def dump_hex_data_to_str(data, **kwargs):
    """! @brief Returns a string with data formatted as hex.
    @see dump_hex_data()
    """
    sio = six.StringIO()
    dump_hex_data(data, output=sio, **kwargs)
    return sio.getvalue()
