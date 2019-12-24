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
from enum import Enum

from pyocd.utility.notification import (Notification, Notifier)

# Test both int and string events.
EVENT_A = 1
EVENT_B = "foo"

class Subscriber(object):
    def __init__(self):
        self.was_called = False
        self.last_note = None
    
    def cb(self, note):
        self.was_called = True
        self.last_note = note

@pytest.fixture
def notifier():
    return Notifier()

@pytest.fixture
def subscriber():
    return Subscriber()

class TestNotification(object):
    def test_basic_sub_and_send_a(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_A)
        notifier.notify(EVENT_A, self)
        assert subscriber.was_called
        assert subscriber.last_note.event == EVENT_A
        assert subscriber.last_note.source == self
        assert subscriber.last_note.data == None

    def test_basic_sub_and_send_b(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_B)
        notifier.notify(EVENT_B, self)
        assert subscriber.was_called
        assert subscriber.last_note.event == EVENT_B
        assert subscriber.last_note.source == self
        assert subscriber.last_note.data == None

    def test_unsub(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_A)
        notifier.unsubscribe(subscriber.cb)
        notifier.notify(EVENT_A, self)
        assert not subscriber.was_called

    def test_unsub2(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_A)
        notifier.unsubscribe(subscriber.cb, events=[EVENT_B])
        notifier.notify(EVENT_A, self)
        assert subscriber.was_called

    def test_multiple_sub(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, (EVENT_A, EVENT_B))
        notifier.notify(EVENT_A, self)
        assert subscriber.was_called
        assert subscriber.last_note.event == EVENT_A
        assert subscriber.last_note.source == self
        assert subscriber.last_note.data == None
        notifier.notify(EVENT_B, self)
        assert subscriber.was_called
        assert subscriber.last_note.event == EVENT_B
        assert subscriber.last_note.source == self
        assert subscriber.last_note.data == None

    def test_diff_sub(self, notifier, subscriber):
        s2 = Subscriber()
        notifier.subscribe(subscriber.cb, EVENT_A)
        notifier.subscribe(s2.cb, EVENT_B)
        notifier.notify(EVENT_B, self)
        assert not subscriber.was_called
        assert s2.was_called
        assert s2.last_note.event == EVENT_B

    def test_src_sub(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_A, source=self)
        notifier.notify(EVENT_A, self)
        assert subscriber.was_called
        assert subscriber.last_note.event == EVENT_A
        assert subscriber.last_note.source == self
        assert subscriber.last_note.data == None

    def test_src_sub2(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_A, source=self)
        notifier.notify(EVENT_A, notifier)
        assert not subscriber.was_called

    def test_unsub_src(self, notifier, subscriber):
        notifier.subscribe(subscriber.cb, EVENT_A, source=self)
        notifier.unsubscribe(subscriber.cb)
        notifier.notify(EVENT_A, self)
        assert not subscriber.was_called

        
