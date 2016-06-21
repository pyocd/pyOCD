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

## @brief Returns a mask with specified bit ranges set.
#
# An integer mask is generated based on the bits and bit ranges specified by the
# arguments. Any number of arguments can be provided. Each argument may be either
# a 2-tuple of integers, a list of integers, or an individual integer. The result
# is the combination of masks produced by the arguments.
#
# - 2-tuple: The tuple is a bit range with the first element being the MSB and the
#       second element the LSB. All bits from LSB up to and included MSB are set.
# - list: Each bit position specified by the list elements is set.
# - int: The specified bit position is set.
#
# @return An integer mask value computed from the logical OR'ing of masks generated
#   by each argument.
#
# Example:
# @code
#   >>> hex(bitmask((23,17),1))
#   0xfe0002
#   >>> hex(bitmask([4,0,2],(31,24))
#   0xff000015
# @endcode
def bitmask(*args):
    mask = 0

    for a in args:
        if type(a) is tuple:
            for b in range(a[1], a[0]+1):
                mask |= 1 << b
        elif type(a) is list:
            for b in a:
                mask |= 1 << b
        elif type(a) is int:
            mask |= 1 << a

    return mask

## @brief Return the 32-bit inverted value of the argument.
def invert32(value):
    return 0xffffffff & ~value

## @brief Extract a value from a bitfield.
def bfx(value, msb, lsb):
    mask = bitmask((msb, lsb))
    return (value & mask) >> lsb

## @brief Change a bitfield value.
def bfi(value, msb, lsb, field):
    mask = bitmask((msb, lsb))
    value &= ~mask
    value |= (field & mask) << lsb
    return value

def _msb( n ):
    ndx = 0
    while ( 1 < n ):
        n = ( n >> 1 )
        ndx += 1
    return ndx

