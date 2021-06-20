# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import struct
import binascii
import six

from .mask import align_up

def byte_list_to_nbit_le_list(data, bitwidth, pad=0x00):
    """! @brief Convert a list of bytes to a list of n-bit integers (little endian)
    
    If the length of the data list is not a multiple of `bitwidth` // 8, then the pad value is used
    for the additional required bytes.
    
    @param data List of bytes.
    @param bitwidth Width in bits of the resulting values.
    @param pad Optional value used to pad input data if not aligned to the bitwidth.
    @result List of integer values that are `bitwidth` bits wide.
    """
    bytewidth = bitwidth // 8
    datalen = len(data) // bytewidth * bytewidth
    res = [sum((data[offset + i] << (i * 8)) for i in range(bytewidth))
            for offset in range(0, datalen, bytewidth)
            ]
    remainder = len(data) % bytewidth
    if remainder != 0:
        pad_count = bytewidth - remainder
        padded_data = list(data[-remainder:]) + [pad] * pad_count
        res.append(sum((padded_data[i] << (i * 8)) for i in range(bytewidth)))
    return res

def nbit_le_list_to_byte_list(data, bitwidth):
    """! @brief Convert a list of n-bit values into a byte list.
    
    @param data List of n-bit values.
    @param bitwidth Width in bits of the input vales.
    @result List of integer bytes.
    """
    return [(x >> shift) & 0xff for x in data for shift in range(0, bitwidth, 8)]

def byte_list_to_u32le_list(data, pad=0x00):
    """! @brief Convert a list of bytes to a list of 32-bit integers (little endian)
    
    If the length of the data list is not a multiple of 4, then the pad value is used
    for the additional required bytes.
    """
    res = []
    for i in range(len(data) // 4):
        res.append(data[i * 4 + 0] |
                   data[i * 4 + 1] << 8 |
                   data[i * 4 + 2] << 16 |
                   data[i * 4 + 3] << 24)
    remainder = (len(data) % 4)
    if remainder != 0:
        padCount = 4 - remainder
        res += byte_list_to_u32le_list(list(data[-remainder:]) + [pad] * padCount)
    return res

def u32le_list_to_byte_list(data):
    """! @brief Convert a word array into a byte array"""
    res = []
    for x in data:
        res.append((x >> 0) & 0xff)
        res.append((x >> 8) & 0xff)
        res.append((x >> 16) & 0xff)
        res.append((x >> 24) & 0xff)
    return res

def u16le_list_to_byte_list(data):
    """! @brief Convert a halfword array into a byte array"""
    byteData = []
    for h in data:
        byteData.extend([h & 0xff, (h >> 8) & 0xff])
    return byteData

def byte_list_to_u16le_list(byteData):
    """! @brief Convert a byte array into a halfword array"""
    data = []
    for i in range(0, len(byteData), 2):
        data.append(byteData[i] | (byteData[i + 1] << 8))
    return data

def u32_to_float32(data):
    """! @brief Convert a 32-bit int to an IEEE754 float"""
    d = struct.pack(">I", data)
    return struct.unpack(">f", d)[0]

def float32_to_u32(data):
    """! @brief Convert an IEEE754 float to a 32-bit int"""
    d = struct.pack(">f", data)
    return struct.unpack(">I", d)[0]

def u64_to_float64(data):
    """! @brief Convert a 64-bit int to an IEEE754 float"""
    d = struct.pack(">Q", data)
    return struct.unpack(">d", d)[0]

def float64_to_u64(data):
    """! @brief Convert an IEEE754 float to a 64-bit int"""
    d = struct.pack(">d", data)
    return struct.unpack(">Q", d)[0]

def uint_to_hex_le(value, width):
    """! @brief Create an n-digit hexadecimal string from an integer value.
    @param value Integer value to format.
    @param width The width in bits. 
    @return A string with the number of hex bytes required to fit `width` bits, rounded up to the
        next whole byte. The bytes represent `value` in little-endian order. That is, the first hex
        byte contains the LSB of `value`, while the last hex byte the MSB.
    """
    return ''.join("%02x" % ((value >> b) & 0xff) for b in range(0, align_up(width, 8), 8))

def hex_le_to_uint(value, width):
    """! @brief Create an an integer value from an n-digit hexadecimal string.
    @param value String consisting of pairs of hex digits with no intervening whitespace. Must have at least
        enough hex bytes to meet the desired width. The first hex byte is the LSB.
    @param width The width in bits. The width can be shorter then the input `value` width, in which case
        more significant bytes will be truncated.
    @return An integer converted from `value`.
    """
    return sum((int(value[i:i+2], base=16) << (i * 4)) for i in range(0, align_up(width, 8) // 4, 2))

def u32_to_hex8le(val):
    """! @brief Create 8-digit hexadecimal string from 32-bit register value"""
    return uint_to_hex_le(val, 32)

def u64_to_hex16le(val):
    """! @brief Create 16-digit hexadecimal string from 64-bit register value"""
    return uint_to_hex_le(val, 64)

def hex8_to_u32be(data):
    """! @brief Build 32-bit register value from big-endian 8-digit hexadecimal string
    @note Endianness in this function name is backwards.
    """
    return hex_le_to_uint(data, 32)

def hex16_to_u64be(data):
    """! @brief Build 64-bit register value from big-endian 16-digit hexadecimal string
    @note Endianness in this function name is backwards.
    """
    return hex_le_to_uint(data, 64)

def hex8_to_u32le(data):
    """! @brief Build 32-bit register value from little-endian 8-digit hexadecimal string
    @note Endianness in this function name is backwards.
    """
    return int(data[0:8], 16)

def hex16_to_u64le(data):
    """! @brief Build 64-bit register value from little-endian 16-digit hexadecimal string
    @note Endianness in this function name is backwards.
    """
    return int(data[0:16], 16)

def byte_to_hex2(val):
    """! @brief Create 2-digit hexadecimal string from 8-bit value"""
    return "%02x" % int(val)

def hex_to_byte_list(data):
    """! @brief Convert string of hex bytes to list of integers"""
    return list(six.iterbytes(binascii.unhexlify(data)))

def hex_decode(cmd):
    """! @brief Return the binary data represented by the hexadecimal string."""
    return binascii.unhexlify(cmd)

def hex_encode(string):
    """! @brief Return the hexadecimal representation of the binary data."""
    return binascii.hexlify(string)

def pairwise(iterable):
    """! s -> (s0,s1), (s2,s3), (s3, s4), ..."""
    r = []
    for x in iterable:
        r.append(x)
        if len(r) == 2:
            yield tuple(r)
            r = []
    if len(r) > 0:
        yield (r[0], r[1])
