# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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

import operator
from functools import reduce

def bitmask(*args):
    """! @brief Returns a mask with specified bit ranges set.
    
    An integer mask is generated based on the bits and bit ranges specified by the
    arguments. Any number of arguments can be provided. Each argument may be either
    a 2-tuple of integers, a list of integers, or an individual integer. The result
    is the combination of masks produced by the arguments.
    
    - 2-tuple: The tuple is a bit range with the first element being the MSB and the
          second element the LSB. All bits from LSB up to and included MSB are set.
    - list: Each bit position specified by the list elements is set.
    - int: The specified bit position is set.
    
    @return An integer mask value computed from the logical OR'ing of masks generated
      by each argument.
    
    Example:
    @code
      >>> hex(bitmask((23,17),1))
      0xfe0002
      >>> hex(bitmask([4,0,2],(31,24))
      0xff000015
    @endcode
    """
    mask = 0

    for a in args:
        if isinstance(a, tuple):
            hi, lo = a
            mask |= ((1 << (hi - lo + 1)) - 1) << lo
        elif isinstance(a, (list, set)):
            mask |= reduce(operator.or_, ((1 << b) for b in a))
        elif isinstance(a, int):
            mask |= 1 << a

    return mask

def invert32(value):
    """! @brief Return the 32-bit inverted value of the argument."""
    return 0xffffffff & ~value

def bfx(value, msb, lsb):
    """! @brief Extract a value from a bitfield."""
    mask = bitmask((msb, lsb))
    return (value & mask) >> lsb

def bfi(value, msb, lsb, field):
    """! @brief Change a bitfield value."""
    mask = bitmask((msb, lsb))
    value &= ~mask
    value |= (field << lsb) & mask
    return value

def msb(n):
    """! @brief Return the bit number of the highest set bit."""
    ndx = 0
    while ( 1 < n ):
        n = ( n >> 1 )
        ndx += 1
    return ndx

def same(d1, d2):
    """! @brief Test whether two sequences contain the same values.
    
    Unlike a simple equality comparison, this function works as expected when the two sequences
    are of different types, such as a list and bytearray. The sequences must return
    compatible types from indexing.
    """
    if len(d1) != len(d2):
        return False
    for i in range(len(d1)):
        if d1[i] != d2[i]:
            return False
    return True

def align_up(value, multiple):
    """! @brief Return value aligned up to multiple."""
    return (value + multiple - 1) // multiple * multiple

