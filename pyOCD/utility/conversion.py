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

## @brief Convert a byte array into a word array.
def byte2word(data):
    res = []
    for i in range(len(data)/4):
        res.append(data[i*4 + 0] << 0  |
                   data[i*4 + 1] << 8  |
                   data[i*4 + 2] << 16 |
                   data[i*4 + 3] << 24)
    return res

## @brief Convert a word array into a byte array.
def word2byte(data):
    res = []
    for x in data:
        res.append((x >> 0) & 0xff)
        res.append((x >> 8) & 0xff)
        res.append((x >> 16) & 0xff)
        res.append((x >> 24) & 0xff)
    return res

## @brief Convert a halfword array into a byte array
def half2byte(data):
    byteData = []
    for h in data:
        byteData.extend([h & 0xff, (h >> 8) & 0xff])
    return byteData

## @brief Convert a byte array into a halfword array.
def byte2half(byteData):
    data = []
    for i in range(0, len(byteData), 2):
        data.append(byteData[i] | (byteData[i+1] << 8))
    return data

## @brief Convert a 32-bit int to an IEEE754 float.
def int2float(data):
    d = struct.pack("@I", data)
    return struct.unpack("@f", d)[0]

## @brief Convert an IEEE754 float to a 32-bit int.
def float2int(data):
    d = struct.pack("@f", data)
    return struct.unpack("@I", d)[0]

## @brief create 8-digit hexadecimal string from 32-bit register value.
def intToHex8(val):
    val = hex(int(val))[2:]
    size = len(val)
    r = ''
    for i in range(8-size):
        r += '0'
    r += str(val)

    resp = ''
    for i in range(4):
        resp += r[8 - 2*i - 2: 8 - 2*i]

    return resp

## @brief Build 32-bit register value from little-endian 8-digit hexadecimal string.
def hex8ToInt(data):
    return int(data[6:8] + data[4:6] + data[2:4] + data[0:2], 16)

## @brief Create 2-digit hexadecimal string from 8-bit value.
def intToHex2(val):
    val = hex(int(val))[2:]
    if len(val) < 2:
        return '0' + val
    else:
        return val

## @brief Convert string of hex bytes to list of integers.
def hexStringToIntList(data):
    return [ord(i) for i in binascii.unhexlify(data)]

def hexDecode(cmd):
    return binascii.unhexlify(cmd)

def hexEncode(string):
    return binascii.hexlify(string)

