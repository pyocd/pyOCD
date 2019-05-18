# pyOCD debugger
# Copyright (c) 2019 Arm Limited
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

from pyocd.core.options_manager import OptionsManager
from pyocd.core.options import OPTIONS_INFO

@pytest.fixture(scope='function')
def mgr():
    return OptionsManager()

@pytest.fixture(scope='function')
def layer1():
    return {
            'foo': 1,
            'bar': 2,
            'baz': 3,
            'auto_unlock': False,
        }

@pytest.fixture(scope='function')
def layer2():
    return {
            'baz': 33,
            'dogcow': 777,
        }

class TestOptionsManager(object):
    def test_defaults(self, mgr):
        assert mgr.get('auto_unlock') == OPTIONS_INFO['auto_unlock'].default
        assert mgr['auto_unlock'] == OPTIONS_INFO['auto_unlock'].default
        assert 'auto_unlock' not in mgr
        assert mgr.get_default('auto_unlock') == OPTIONS_INFO['auto_unlock'].default

    def test_a(self, mgr, layer1):
        mgr.add_front(layer1)
        assert 'auto_unlock' in mgr
        assert mgr.get('auto_unlock') == False

    def test_b(self, mgr, layer1):
        mgr.add_front(layer1)
        mgr.add_front({'auto_unlock': True})
        assert 'auto_unlock' in mgr
        assert mgr.get('auto_unlock') == True

    def test_c(self, mgr, layer1):
        mgr.add_front(layer1)
        mgr.add_back({'auto_unlock': True})
        assert 'auto_unlock' in mgr
        assert mgr.get('auto_unlock') == False

    def test_none_value(self, mgr):
        mgr.add_back({'auto_unlock': None})
        assert 'auto_unlock' not in mgr
        assert mgr.get('auto_unlock') == True

    def test_convert_double_underscore(self, mgr):
        mgr.add_back({'debug__traceback': False})
        assert 'debug.traceback' in mgr
        assert mgr.get('debug.traceback') == False
        
    def test_set(self, mgr, layer1):
        mgr.add_front(layer1)
        mgr.set('buzz', 1234)
        assert mgr['buzz'] == 1234
        mgr.add_front({'buzz': 4321})
        assert mgr.get('buzz') == 4321
        
    def test_update(self, mgr, layer1, layer2):
        mgr.add_front(layer1)
        mgr.add_front(layer2)
        mgr.update({'foo': 888, 'debug__traceback': False})
        assert mgr['foo'] == 888
        assert mgr.get('debug.traceback') == False

    def test_notify_set(self, mgr, layer1):
        mgr.add_front(layer1)
        flag = [False]
        def cb(note):
            flag[0] = True
            assert note.event == 'foo'
            assert note.source == mgr
            assert note.data.new_value == 100 and note.data.old_value == 1
        mgr.subscribe(cb, 'foo')
        mgr.set('foo', 100)
        assert flag[0] == True

    def test_notify_layer(self, mgr, layer1, layer2):
        mgr.add_front(layer1)
        flag = [False]
        def cb(note):
            flag[0] = True
            assert note.event == 'baz'
            assert note.source == mgr
            assert note.data.new_value == 33 and note.data.old_value == 3
        mgr.subscribe(cb, 'baz')
        mgr.add_front(layer2)
        assert flag[0] == True

    def test_notify_back_layer(self, mgr, layer1, layer2):
        mgr.add_front(layer1)
        flag = [False]
        def cb(note):
            flag[0] = True
        mgr.subscribe(cb, 'baz')
        mgr.add_back(layer2)
        assert flag[0] == False

        
