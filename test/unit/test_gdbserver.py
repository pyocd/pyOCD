# pyOCD debugger
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

from pyocd.gdbserver.gdbserver import (
    escape,
    unescape,
)

# escaped chars: '#$}*'
# escaped by prefixing with '}' and xor'ing the char with 0x20
#
# '#' (0x23) -> '}\x03'
# '$' (0x24) -> '}\x04'
# '}' (0x7d) -> '}]'
# '*' (0x2a) -> '}\x0a'

class TestGdbServerEscaping:
    def test_escape_transparent(self):
        assert escape(b"hello") == b"hello"

    def test_escape_individual(self):
        assert escape(b"hello#foo") == b"hello}\x03foo"
        assert escape(b"hello$foo") == b"hello}\x04foo"
        assert escape(b"hello}foo") == b"hello}]foo"
        assert escape(b"hello*foo") == b"hello}\x0afoo"

    def test_escape_single(self):
        assert escape(b"#") == b"}\x03"
        assert escape(b"$") == b"}\x04"
        assert escape(b"}") == b"}]"
        assert escape(b"*") == b"}\x0a"

    def test_escape_combined(self):
        assert escape(b"#$}*") == b"}\x03}\x04}]}\x0a"
        assert escape(b'}}}') == b"}]}]}]"

    def test_unescape_transparent(self):
        assert unescape(b"bytes") == list(b"bytes")

    def test_unescape_individual(self):
        assert unescape(b"hello}\x03foo") == list(b"hello#foo")
        assert unescape(b"hello}\x04foo") == list(b"hello$foo")
        assert unescape(b"hello}]foo") == list(b"hello}foo")
        assert unescape(b"hello}\x0afoo") == list(b"hello*foo")

    def test_unescape_single(self):
        assert unescape(b"}\x03") == [b'#'[0]]
        assert unescape(b"}\x04") == [b'$'[0]]
        assert unescape(b"}]") == [b'}'[0]]
        assert unescape(b"}\x0a") == [b'*'[0]]

    def test_unescape_combined(self):
        assert unescape(b"}\x03}\x04}]}\x0a") == list(b"#$}*")
        assert unescape(b"}]}]}]") == list(b"}}}")
