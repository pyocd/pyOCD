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

import struct
import binascii
import six

def byte_list_to_u32le_list(data):
    """Convert a list of bytes to a list of 32-bit integers (little endian)"""
    res = []
    for i in range(len(data) // 4):
        res.append(data[i * 4 + 0] |
                   data[i * 4 + 1] << 8 |
                   data[i * 4 + 2] << 16 |
                   data[i * 4 + 3] << 24)
    return res


def u32le_list_to_byte_list(data):
    """Convert a word array into a byte array"""
    res = []
    for x in data:
        res.append((x >> 0) & 0xff)
        res.append((x >> 8) & 0xff)
        res.append((x >> 16) & 0xff)
        res.append((x >> 24) & 0xff)
    return res


def u16le_list_to_byte_list(data):
    """Convert a halfword array into a byte array"""
    byteData = []
    for h in data:
        byteData.extend([h & 0xff, (h >> 8) & 0xff])
    return byteData


def byte_list_to_u16le_list(byteData):
    """Convert a byte array into a halfword array"""
    data = []
    for i in range(0, len(byteData), 2):
        data.append(byteData[i] | (byteData[i + 1] << 8))
    return data


def u32_to_float32(data):
    """Convert a 32-bit int to an IEEE754 float"""
    d = struct.pack(">I", data)
    return struct.unpack(">f", d)[0]


def float32_to_u32(data):
    """Convert an IEEE754 float to a 32-bit int"""
    d = struct.pack(">f", data)
    return struct.unpack(">I", d)[0]


def u32_to_hex8le(val):
    """Create 8-digit hexadecimal string from 32-bit register value"""
    return ''.join("%02x" % (x & 0xFF) for x in (
        val,
        val >> 8,
        val >> 16,
        val >> 24,
    ))


def hex8_to_u32be(data):
    """Build 32-bit register value from little-endian 8-digit hexadecimal string"""
    return int(data[6:8] + data[4:6] + data[2:4] + data[0:2], 16)


def hex8_to_u32le(data):
    """Build 32-bit register value from little-endian 8-digit hexadecimal string"""
    return int(data[0:2] + data[2:4] + data[4:6] + data[6:8], 16)


def byte_to_hex2(val):
    """Create 2-digit hexadecimal string from 8-bit value"""
    return "%02x" % int(val)


def hex_to_byte_list(data):
    """Convert string of hex bytes to list of integers"""
    return list(six.iterbytes(binascii.unhexlify(data)))


def hex_decode(cmd):
    return binascii.unhexlify(cmd)


def hex_encode(string):
    return binascii.hexlify(string)
