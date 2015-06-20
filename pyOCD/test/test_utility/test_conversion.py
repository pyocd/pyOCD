# mbed CMSIS-DAP debugger
# Copyright (c) 2015 Paul Osborne <osbpau@gmail.com>
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
import unittest
from pyOCD.utility.conversion import byteListToLittleEndianU32List, u32leListToBytelist, u16leListToByteList, \
    byteListToU16leList, int2float, float2int, intToHex8, hex8ToInt, intToHex2, hexStringToIntList, hexDecode, hexEncode


class TestConversionUtilities(unittest.TestCase):

    def test_byteListToLittleEndianU32List(self):
        data = range(32)
        self.assertEqual(byteListToLittleEndianU32List(data), [
            0x03020100,
            0x07060504,
            0x0B0A0908,
            0x0F0E0D0C,
            0x13121110,
            0x17161514,
            0x1B1A1918,
            0x1F1E1D1C,
        ])

    def test_u32leListToByteList(self):
        data = [
            0x03020100,
            0x07060504,
            0x0B0A0908,
            0x0F0E0D0C,
            0x13121110,
            0x17161514,
            0x1B1A1918,
            0x1F1E1D1C,
        ]
        self.assertEqual(u32leListToBytelist(data), range(32))

    def test_byteListToNibbleList(self):
        data = [0x3412, 0xFEAB]
        self.assertEqual(u16leListToByteList(data), [
            0x12,
            0x34,
            0xAB,
            0xFE
        ])

    def test_byteListToU16leList(self):
        data = [0x01, 0x00, 0xAB, 0xCD,]
        self.assertEqual(byteListToU16leList(data), [
            0x0001,
            0xCDAB,
        ])

    def test_int2float(self):
        self.assertEqual(int2float(0x012345678), 5.690456613903524e-28)

    def test_float2int(self):
        self.assertEqual(float2int(5.690456613903524e-28), 0x012345678)

    def test_intToHex8(self):
        self.assertEqual(intToHex8(0x0102ABCD), "0102ABCD")

    def test_hex8ToInt(self):
        self.assertEqual(hex8ToInt("0102ABCD"), 0xCDAB0201)

    def test_intToHex2(self):
        self.assertEqual(intToHex2(0xC3), "c3")

    def test_hexStringToIntList(self):
        self.assertEqual(hexStringToIntList("ABCDEF1234"),
                         [0xAB, 0xCD, 0xEF, 0x12, 0x34])

    def test_hexDecode(self):
        self.assertEqual(hexDecode('ABCDEF1234'),
                         '\xab\xcd\xef\x12\x34')

    def test_hexEncode(self):
        self.assertEqual(hexEncode('\xab\xcd\xef\x12\x34'),
                         'abcdef1234')
