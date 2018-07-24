"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015,2018 ARM Limited

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

from pyOCD.utility.cmdline import (
    split_command_line,
    convert_vector_catch,
    VECTOR_CATCH_CHAR_MAP
    )
from pyOCD.core.target import Target
import pytest
import six

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

class TestConvertVectorCatch(object):
    def test_none_str(self):
        assert convert_vector_catch('none') == 0

    def test_all_str(self):
        assert convert_vector_catch('all') == Target.CATCH_ALL

    def test_none_b(self):
        assert convert_vector_catch(b'none') == 0

    def test_all_b(self):
        assert convert_vector_catch(b'all') == Target.CATCH_ALL

    @pytest.mark.parametrize(("vc", "msk"),
        list(VECTOR_CATCH_CHAR_MAP.items()))
    def test_vc_str(self, vc, msk):
        assert convert_vector_catch(vc) == msk

    @pytest.mark.parametrize(("vc", "msk"),
        [(six.b(x), y) for x,y in VECTOR_CATCH_CHAR_MAP.items()])
    def test_vc_b(self, vc, msk):
        assert convert_vector_catch(vc) == msk
        
