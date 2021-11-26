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

from pyocd.utility.strings import (
    uniquify_name,
    )

class TestUniquifyName:
    def test_empty_with_no_others(self):
        assert uniquify_name('', []) == ''

    def test_empty_with_others(self):
        assert uniquify_name('', ['bar', 'buz']) == ''

    def test_empty_with_another_empty(self):
        assert uniquify_name('', ['bar', 'buz', '']) == '_1'

    def test_no_others(self):
        assert uniquify_name('foo', []) == 'foo'

    def test_already_unique(self):
        assert uniquify_name('foo', ['bar']) == 'foo'

    def test_no_trailing_int(self):
        assert uniquify_name('foo', ['foo']) == 'foo_1'

    def test_1_trailing_int(self):
        assert uniquify_name('foo1', ['foo1']) == 'foo2'

    def test_multiple_trailing_ints(self):
        assert uniquify_name('foo1', ['foo1', 'foo2']) == 'foo3'

    def test_name_has_int(self):
        assert uniquify_name('foo2', ['foo2', 'bar', 'foo3']) == 'foo4'

    def test_multiple_ints_in_name(self):
        assert uniquify_name('baz 2 monkey-3', ['fun', 'baz 2 monkey-3']) == 'baz 2 monkey-4'

