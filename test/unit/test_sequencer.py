# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

import pytest
import six

from pyocd.utility.sequencer import CallSequence

class TestCallSequence:
    def test_empty(self):
        cs = CallSequence()
        assert cs.count == 0
    
    def test_a(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.invoke()
        assert results == ['a ran', 'b ran']

    def test_append_1(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                )
        assert cs.count == 1

        cs.append(        
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        
        cs.invoke()
        assert results == ['a ran', 'b ran']

    def test_append_2(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                )
        assert cs.count == 1

        cs.append(        
                ('b', lambda : results.append('b ran')),
                ('c', lambda : results.append('c ran')),
                )
        assert cs.count == 3
        
        cs.invoke()
        assert results == ['a ran', 'b ran', 'c ran']

    def test_remove_1(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        
        cs.remove_task('b')
        assert cs.count == 1
        
        cs.invoke()
        assert results == ['a ran']

    def test_callable(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs()
        assert results == ['a ran', 'b ran']

    def test_nested(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs2 = CallSequence(
                ('c', cs),
                )
        assert cs2.count == 1
        cs2.invoke()
        assert results == ['a ran', 'b ran']

    def test_clear(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.clear()
        assert cs.count == 0

    def test_iter(self):
        results = []
        def task_a():
            results.append('a ran')
        def task_b():
            results.append('b ran')
        cs = CallSequence(
                ('a', task_a),
                ('b', task_b),
                )
        assert cs.count == 2
        it = iter(cs)
        print("it=",repr(it),dir(it))
        assert six.next(it) == ('a', task_a)
        assert six.next(it) == ('b', task_b)
        with pytest.raises(StopIteration):
            six.next(it)

    def test_get(self):
        results = []
        def task_a():
            results.append('a ran')
        cs = CallSequence(
                ('a', task_a),
                )
        assert cs.count == 1
        assert cs.get_task('a') == task_a
        with pytest.raises(KeyError):
            cs.get_task('foo')

    def test_has(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                )
        assert cs.count == 1
        assert cs.has_task('a')
        assert not cs.has_task('foo')

    def test_replace(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.replace_task('b', lambda : results.append('wheee'))
        cs()
        assert results == ['a ran', 'wheee']

    def test_wrap(self):
        results = []
        def task_b():
            results.append('b ran')
            return "task b result"
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', task_b),
                )
        assert cs.count == 2
        def wrapper(t):
            assert t == "task b result"
            results.append('wrapper ran')
        cs.wrap_task('b', wrapper)
        cs()
        assert results == ['a ran', 'b ran', 'wrapper ran']

    def test_returned_seq(self):
        results = []
        def task_b():
            results.append('b ran')
            cs2 = CallSequence(
                    ('x', lambda : results.append('x ran')),
                    ('y', lambda : results.append('y ran')),
                    )
            assert cs2.count == 2
            return cs2
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', task_b),
                ('c', lambda : results.append('c ran')),
                )
        assert cs.count == 3
        cs()
        assert results == ['a ran', 'b ran', 'x ran', 'y ran', 'c ran']

    def test_insert_before_1(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.insert_before('b', ('c', lambda : results.append('c ran')))
        assert cs.count == 3
        cs()
        assert results == ['a ran', 'c ran', 'b ran']

    def test_insert_before_2(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.insert_before('a', ('c', lambda : results.append('c ran')))
        assert cs.count == 3
        cs()
        assert results == ['c ran', 'a ran', 'b ran']

    def test_insert_before_3(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.insert_before('a', ('c', lambda : results.append('c ran')),
                              ('d', lambda : results.append('d ran')))
        assert cs.count == 4
        cs()
        assert results == ['c ran', 'd ran', 'a ran', 'b ran']

    def test_insert_before_4(self):
        results = []
        cs = CallSequence()
        with pytest.raises(KeyError):
            cs.insert_before('z', ('c', lambda : results.append('c ran')))

    def test_insert_after_1(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.insert_after('b', ('c', lambda : results.append('c ran')))
        assert cs.count == 3
        cs()
        assert results == ['a ran', 'b ran', 'c ran']

    def test_insert_after_2(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.insert_after('a', ('c', lambda : results.append('c ran')))
        assert cs.count == 3
        cs()
        assert results == ['a ran', 'c ran', 'b ran']

    def test_insert_after_3(self):
        results = []
        cs = CallSequence(
                ('a', lambda : results.append('a ran')),
                ('b', lambda : results.append('b ran')),
                )
        assert cs.count == 2
        cs.insert_after('a', ('c', lambda : results.append('c ran')),
                             ('d', lambda : results.append('d ran')))
        assert cs.count == 4
        cs()
        assert results == ['a ran', 'c ran', 'd ran', 'b ran']

    def test_insert_after_4(self):
        results = []
        cs = CallSequence()
        with pytest.raises(KeyError):
            cs.insert_after('z', ('c', lambda : results.append('c ran')))


