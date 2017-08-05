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
from pyOCD.utility.conversion import byteListToU32leList, u32leListToByteList, u16leListToByteList, \
    byteListToU16leList, u32BEToFloat32BE, float32beToU32be, u32beToHex8le, hex8leToU32be, byteToHex2, hexToByteList, \
    hexDecode, hexEncode


class TestConversionUtilities(unittest.TestCase):
    def test_byteListToU32leList(self):
        data = range(32)
        self.assertEqual(byteListToU32leList(data), [
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
        self.assertEqual(u32leListToByteList(data), range(32))

    def test_u16leListToByteList(self):
        data = [0x3412, 0xFEAB]
        self.assertEqual(u16leListToByteList(data), [
            0x12,
            0x34,
            0xAB,
            0xFE
        ])

    def test_byteListToU16leList(self):
        data = [0x01, 0x00, 0xAB, 0xCD, ]
        self.assertEqual(byteListToU16leList(data), [
            0x0001,
            0xCDAB,
        ])

    def test_u32BEToFloat32BE(self):
        self.assertEqual(u32BEToFloat32BE(0x012345678), 5.690456613903524e-28)

    def test_float32beToU32be(self):
        self.assertEqual(float32beToU32be(5.690456613903524e-28), 0x012345678)

    def test_u32beToHex8le(self):
        self.assertEqual(u32beToHex8le(0x0102ABCD), "cdab0201")

    def test_hex8leToU32be(self):
        self.assertEqual(hex8leToU32be("0102ABCD"), 0xCDAB0201)

    def test_byteToHex2(self):
        self.assertEqual(byteToHex2(0xC3), "c3")

    def test_hexToByteList(self):
        self.assertEqual(hexToByteList("ABCDEF1234"),
                         [0xAB, 0xCD, 0xEF, 0x12, 0x34])

    def test_hexDecode(self):
        self.assertEqual(hexDecode('ABCDEF1234'),
                         '\xab\xcd\xef\x12\x34')

    def test_hexEncode(self):
        self.assertEqual(hexEncode('\xab\xcd\xef\x12\x34'),
                         'abcdef1234')
