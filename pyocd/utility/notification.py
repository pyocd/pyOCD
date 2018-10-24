"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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

import logging

##
# @brief Class that holds information about a notification to subscribers.
class Notification(object):
    def __init__(self, event, source, data=None):
        self._event = event
        self._source = source
        self._data = data

    @property
    def event(self):
        return self._event

    @property
    def source(self):
        return self._source

    @property
    def data(self):
        return self._data

    def __repr__(self):
        return "<Notification@0x%08x event=%s source=%s data=%s>" % (id(self), repr(self.event), repr(self.source), repr(self.data))

##
# @brief Mix-in class that provides notification capabilities.
class Notifier(object):
    def __init__(self):
        self._subscribers = {}

    def subscribe(self, events, cb):
        if not type(events) in (list, tuple):
            events = [events]
        for event in events:
            if event in self._subscribers:
                self._subscribers[event].append(cb)
            else:
                self._subscribers[event] = [cb]

    def unsubscribe(self, events, cb):
        pass

    def notify(self, *notifications):
        for note in notifications:
            # This debug log is commented out because it produces too much output unless you
            # are specifically working on notifications.
#             logging.debug("Sending notification: %s", repr(note))
            for cb in self._subscribers.get(note.event, []):
                cb(note)


