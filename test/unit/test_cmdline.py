# pyOCD debugger
# Copyright (c) 2015,2018-2019 Arm Limited
# Copyright (c) 2022 Chris Reed
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
import six

from pyocd.utility.cmdline import (
    split_command_line,
    convert_vector_catch,
    VECTOR_CATCH_CHAR_MAP,
    convert_session_options,
    )
from pyocd.core.target import Target
from pyocd.target import normalise_target_type_name

class TestSplitCommandLine(object):
    def test_split(self):
        assert split_command_line('foo') == ['foo']
        assert split_command_line(['foo']) == ['foo']
        assert split_command_line('foo bar') == ['foo', 'bar']
        assert split_command_line(['foo bar']) == ['foo', 'bar']

    def test_split_strings(self):
        assert split_command_line('"foo"') == ['foo']
        assert split_command_line('"foo bar"') == ['foo bar']
        assert split_command_line(['"foo"']) == ['foo']
        assert split_command_line('a "b c" d') == ['a', "b c", 'd']
        assert split_command_line("'foo bar'") == ['foo bar']

    def test_split_whitespace(self):
        assert split_command_line('a b') == ['a', 'b']
        assert split_command_line('a\tb') == ['a', 'b']
        assert split_command_line('a\rb') == ['a', 'b']
        assert split_command_line('a\nb') == ['a', 'b']
        assert split_command_line('a   \tb') == ['a', 'b']

    @pytest.mark.parametrize(("input", "result"), [
        (r'\h\e\l\l\o', ['hello']),
        (r'"\"hello\""', ['"hello"']),
        ('x "a\\"b" y', ['x', 'a"b', 'y']),
        ('hello"there"', ['hello', 'there']),
        (r"'raw\string'", [r'raw\string']),
        ('"foo said \\"hi\\"" and \'C:\\baz\'', ['foo said "hi"', 'and', 'C:\\baz']),
        ("foo;bar", ["foo", ";", "bar"]),
        ])
    def test_em(self, input, result):
        assert split_command_line(input) == result

    # ;!@#$%^&*()+=[]{}|<>,?
    @pytest.mark.parametrize("sep",
        list(c for c in ';!@#$%^&*()+=[]{}|<>,?')
        )
    def test_word_separators(self, sep):
        assert split_command_line(f"foo{sep}bar") == ["foo", sep, "bar"]
        assert split_command_line(f"foo{sep} bar") == ["foo", sep, "bar"]
        assert split_command_line(f"foo {sep}bar") == ["foo", sep, "bar"]
        assert split_command_line(f"foo {sep} bar") == ["foo", sep, "bar"]

class TestConvertVectorCatch(object):
    def test_none_str(self):
        assert convert_vector_catch('none') == 0

    def test_all_str(self):
        assert convert_vector_catch('all') == Target.VectorCatch.ALL

    def test_none_b(self):
        assert convert_vector_catch(b'none') == 0

    def test_all_b(self):
        assert convert_vector_catch(b'all') == Target.VectorCatch.ALL

    @pytest.mark.parametrize(("vc", "msk"),
        list(VECTOR_CATCH_CHAR_MAP.items()))
    def test_vc_str(self, vc, msk):
        assert convert_vector_catch(vc) == msk

    @pytest.mark.parametrize(("vc", "msk"),
        [(six.b(x), y) for x,y in VECTOR_CATCH_CHAR_MAP.items()])
    def test_vc_b(self, vc, msk):
        assert convert_vector_catch(vc) == msk

class TestConvertSessionOptions(object):
    def test_empty(self):
        assert convert_session_options([]) == {}

    def test_unknown_option(self):
        # No value.
        assert convert_session_options(['dumkopf']) == {}
        # With a value
        assert convert_session_options(['dumkopf=123']) == {'dumkopf': "123"}

    def test_bool(self):
        assert convert_session_options(['auto_unlock']) == {'auto_unlock': True}
        assert convert_session_options(['no-auto_unlock']) == {'auto_unlock': False}
        assert convert_session_options(['auto_unlock=1']) == {'auto_unlock': True}
        assert convert_session_options(['auto_unlock=true']) == {'auto_unlock': True}
        assert convert_session_options(['auto_unlock=yes']) == {'auto_unlock': True}
        assert convert_session_options(['auto_unlock=on']) == {'auto_unlock': True}
        assert convert_session_options(['auto_unlock=0']) == {'auto_unlock': False}
        assert convert_session_options(['auto_unlock=false']) == {'auto_unlock': False}
        assert convert_session_options(['auto_unlock=True']) == {'auto_unlock': True}
        assert convert_session_options(['auto_unlock=False']) == {'auto_unlock': False}
        assert convert_session_options(['auto_unlock=YES']) == {'auto_unlock': True}
        assert convert_session_options(['auto_unlock=oFF']) == {'auto_unlock': False}
        assert convert_session_options(['auto_unlock=anything-goes-here']) == {}

    def test_noncasesense(self):
        # Test separate paths for with and without a value.
        assert convert_session_options(['AUTO_Unlock']) == {'auto_unlock': True}
        assert convert_session_options(['AUTO_Unlock=0']) == {'auto_unlock': False}

    def test_int(self):
        # Non-bool with no value is ignored (and logged).
        assert convert_session_options(['frequency']) == {}
        # Invalid int value is ignored and logged
        assert convert_session_options(['frequency=abc']) == {}
        # Ignore with no- prefix
        assert convert_session_options(['no-frequency']) == {}
        # Valid int
        assert convert_session_options(['frequency=1000']) == {'frequency': 1000}
        # Valid hex int
        assert convert_session_options(['frequency=0x40']) == {'frequency': 64}

    def test_str(self):
        # Ignore with no value
        assert convert_session_options(['test_binary']) == {}
        # Ignore with no- prefix
        assert convert_session_options(['no-test_binary']) == {}
        # Valid
        assert convert_session_options(['test_binary=abc']) == {'test_binary': 'abc'}

class TestTargetTypeNormalisation:
    def test_passthrough(self):
        assert normalise_target_type_name("foobar") == "foobar"
        assert normalise_target_type_name("foo123bar") == "foo123bar"
        assert normalise_target_type_name("foo_bar") == "foo_bar"

    def test_lower(self):
        assert normalise_target_type_name("TARGET") == "target"
        assert normalise_target_type_name("BIGtarget") == "bigtarget"
        assert normalise_target_type_name("someTARGET123") == "sometarget123"

    def test_trans(self):
        assert normalise_target_type_name("foo-bar") == "foo_bar"
        assert normalise_target_type_name("foo--bar") == "foo_bar"
        assert normalise_target_type_name("foo!@#$%^&*()x") == "foo_x"

