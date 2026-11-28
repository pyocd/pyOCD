# pyOCD debugger
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

import pytest

from pyocd.utility.mask import (
    bfx,
    bfxw,
    )

class TestBfxw:
    @pytest.mark.parametrize(("value", "lsb", "width"), [
            (0xffffffff, 0, 1),
            (0xffffffff, 31, 1),
            (0x1f0, 4, 4),
            (0xffffcfff, 12, 2),
            (0x12345678, 8, 8),
            (0x12345678, 0, 32),
            (0xffffffff, 3, 5),
        ])
    def test_matches_bfx(self, value, lsb, width):
        result = bfxw(value, lsb, width)
        assert result == bfx(value, lsb + width - 1, lsb)
        assert result < (1 << width)

    def test_nibble(self):
        assert bfxw(0x1f0, 4, 4) == 0xf

    def test_zero_width(self):
        assert bfxw(0xffffffff, 4, 0) == 0
