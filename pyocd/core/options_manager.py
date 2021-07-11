# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

import logging
from functools import partial
from collections import namedtuple

from .options import OPTIONS_INFO
from ..utility.notification import Notifier

LOG = logging.getLogger(__name__)

## @brief Data for an option value change notification.
#
# Instances of this class are used for the data attribute of the @ref
# pyocd.utility.notification.Notification "Notification" sent to subscribers when an option's value
# is changed.
#
# An instance of this class has two attributes:
# - `new_value`: The new, current value of the option.
# - `old_value`: The previous value of the option.
OptionChangeInfo = namedtuple('OptionChangeInfo', 'new_value old_value')

class OptionsManager(Notifier):
    """! @brief Handles session option management for a session.
    
    The options manager supports multiple layers of option priority. When an option's value is
    accessed, the highest priority layer that contains a value for the option is used. This design
    makes it easy to load options from multiple sources. The default value specified for an option
    in the OPTIONS_INFO dictionary provides a layer with an infinitely low priority.
    
    Users can subscribe to notifications for changes to option values by calling the subscribe()
    method. The notification events are the option names themselves. The source for notifications is
    always the options manager instance. The notification data is an instance of OptionChangeInfo
    with `new_value` and `old_value` attributes. If the option was not previously set, then the
    old value is the option's default.
    """

    def __init__(self):
        """! @brief Option manager constructor.
        """
        super(OptionsManager, self).__init__()
        self._layers = []
    
    def _update_layers(self, new_options, update_operation):
        """! @brief Internal method to add a new layer dictionary.
        
        @param self
        @param new_options Dictionary of option values.
        @param update_operation Callable to add the layer. Must accept a single parameter, which is
            the filtered _new_options_ dictionary.
        """
        if new_options is None:
            return
        filtered_options = self._convert_options(new_options)
        previous_values = {name: self.get(name) for name in filtered_options.keys()}
        update_operation(filtered_options)
        new_values = {name: self.get(name) for name in filtered_options.keys()}
        self._notify_changes(previous_values, new_values)

    def add_front(self, new_options):
        """! @brief Add a new highest priority layer of option values.
        
        @param self
        @param new_options Dictionary of option values.
        """
        self._update_layers(new_options, partial(self._layers.insert, 0))
    
    def add_back(self, new_options):
        """! @brief Add a new lowest priority layer of option values.
        
        @param self
        @param new_options Dictionary of option values.
        """
        self._update_layers(new_options, self._layers.append)
    
    def _convert_options(self, new_options):
        """! @brief Prepare a dictionary of session options for use by the manager.
        
        1. Strip dictionary entries with a value of None.
        2. Replace double-underscores ("__") with a dot (".").
        3. Convert option names to all-lowercase.
        """
        output = {}
        for name, value in new_options.items():
            if value is None:
                continue
            else:
                name = name.replace("__", ".").lower()
                output[name] = value
        return output

    def is_set(self, key):
        """! @brief Return whether a value is set for the specified option.
        
        This method returns True as long as any layer has a value set for the option, even if the
        value is the same as the default value. If the option is not set in any layer, then False is
        returned regardless of whether the default value is None.
        """
        for layer in self._layers:
            if key in layer:
                return True
        return False

    def get_default(self, key):
        """! @brief Return the default value for the specified option."""
        if key in OPTIONS_INFO:
            return OPTIONS_INFO[key].default
        else:
            return None

    def get(self, key):
        """! @brief Return the highest priority value for the option, or its default."""
        for layer in self._layers:
            if key in layer:
                return layer[key]
        return self.get_default(key)
    
    def set(self, key, value):
        """! @brief Set an option in the current highest priority layer."""
        self.update({key: value})
    
    def update(self, new_options):
        """! @brief Set multiple options in the current highest priority layer."""
        filtered_options = self._convert_options(new_options)
        previous_values = {name: self.get(name) for name in filtered_options.keys()}
        self._layers[0].update(filtered_options)
        self._notify_changes(previous_values, filtered_options)
    
    def _notify_changes(self, previous, options):
        """! @brief Send notifications that the specified options have changed."""
        for name, new_value in options.items():
            previous_value = previous[name]
            if new_value != previous_value:
                self.notify(name, data=OptionChangeInfo(new_value, previous_value))

    def __contains__(self, key):
        """! @brief Returns whether the named option has a non-default value."""
        return self.is_set(key)
        
    def __getitem__(self, key):
        """! @brief Return the highest priority value for the option, or its default."""
        return self.get(key)
    
    def __setitem__(self, key, value):
        """! @brief Set an option in the current highest priority layer."""
        self.set(key, value)
