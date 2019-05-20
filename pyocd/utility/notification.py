# pyOCD debugger
# Copyright (c) 2016-2019 Arm Limited
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

import logging

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class Notification(object):
    """!@brief Holds information about a notification to subscribers."""

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

class Notifier(object):
    """!@brief Mix-in class that provides notification broadcast capabilities.
    
    In this notification model, subscribers register callbacks for one or more events. The events
    are simply a Python object of any kind, as long as it is hashable. Typically integers or Enums
    are used. Subscriptions can be registered for any sender of an event, or be filtered by the
    sender (called the source).
    
    When a notification is sent to the callback, it is wrapped up as a Notification object. Along
    with the notification, an optional, arbitrary data value can be sent. This allows for further
    specifying the event, or passing related values (or anything else you can think of).
    """
    
    def __init__(self):
        ## Dict of subscribers for particular events and sources.
        #
        # One subscriber can appear in multiple places in the dict.
        #
        # Schema:
        # ```
        # {
        #   event : ( [ subscribers-for-any-source ],
        #               {
        #                   source : [ subscribers ],
        #               } ),
        # }
        # ```
        self._subscribers = {}

    def subscribe(self, cb, events, source=None):
        """!@brief Subscribe to selection of events from an optional source.
        
        @param self
        @param cb The callable that will be invoked when a matching notification is sent. Must
            accept a single parameter, a Notification instance.
        @param events Either a single event or an iterable of events. Events must be a hashable, and
            are usually just integers.
        @param source Optional notifier object. If not None, the callback is only invoked if one
            of the events is sent from the specified source. If a matching event is sent from
            another source, no action is taken.
        """
        if not isinstance(events, (tuple, list, set)):
            events = [events]
        
        for event in events:
            if event not in self._subscribers:
                self._subscribers[event] = ([], {})
            event_info = self._subscribers[event]
            
            if source is None:
                event_info[0].append(cb)
            else:
                if source not in event_info[1]:
                    event_info[1][source] = []
                event_info[1][source].append(cb)

    def unsubscribe(self, cb, events=None):
        """!@brief Remove a callback from the subscribers list.
        
        @param self
        @param cb The callback to remove from all subscriptions.
        @param events Optional. May be a single event or an iterable of events. If specified, the
            _cb_ will be removed only from those events.
        """
        if (events is not None) and (not isinstance(events, (tuple, list, set))):
            events = [events]
        
        for event, event_info in self._subscribers.items():
            # Skip this event if it's not one on the removal list.
            if (events is not None) and (event not in events):
                continue
            
            # Remove callback from all-sources list.
            if cb in event_info[0]:
                event_info[0].remove(cb)
            
            # Scan source-specific subscribers.
            for source_info in event_info[1].values():
                if cb in source_info:
                    source_info.remove(cb)

    def notify(self, event, source=None, data=None):
        """!@brief Notify subscribers of an event.
        
        @param self
        @param event Event to send. Must be a hashable object. It is acceptable to notify for an
            event for which there are no subscribers.
        @param source The object sending the notification. If not set, the source defaults to self,
            the object on which the notify() method was called.
        @param data Optional data value to send with the notification.
        """
        # Look up subscribers for this event.
        try:
            event_info = self._subscribers[event]
        except KeyError:
            # Nobody has subscribed to this event, so nothing to do.
            TRACE.debug("Not sending notification because no subscribers: event=%s", event)
            return
        
        # Look up subscribers for this event + source combo.
        try:
            source_subscribers = event_info[1][source]
        except KeyError:
            # No source-specific subscribers.
            source_subscribers = []
        
        # Create combined subscribers list. Exit if no subscribers matched.
        subscribers = event_info[0] + source_subscribers
        if not subscribers:
            TRACE.debug("Not sending notification because no matching subscribers: event=%s", event)
            return
        
        # Create the notification object now that we know there are some subscribers.
        if source is None:
            source = self
        note = Notification(event, source, data)
        TRACE.debug("Sending notification to %d subscribers: %s", len(subscribers), note)
        
        # Tell everyone!
        for cb in subscribers:
            cb(note)


