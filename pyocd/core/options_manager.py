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

import logging
import six
import yaml
import os

from .options import OPTIONS_INFO

LOG = logging.getLogger(__name__)

class OptionsManager(object):
    """! @brief Handles user option management for a session.
    
    The option manager supports multiple layers of option priority. When an option's value is
    accessed, the highest priority layer that contains a value for the option is used. This design
    makes it easy to load options from multiple sources. The default value specified for an option
    in the OPTIONS_INFO dictionary provides a layer with an infinitely low priority.
    """

    def __init__(self, session):
        """! @brief Option manager constructor.
        """
        self._session = session
        self._layers = []

    def add_front(self, new_options):
        """! @brief Add a new highest priority layer of option values.
        
        @param self
        @param new_options Dictionary of option values.
        """
        if new_options is None:
            return
        self._layers.insert(0, self._convert_options(new_options))
    
    def add_back(self, new_options):
        """! @brief Add a new lowest priority layer of option values.
        
        @param self
        @param new_options Dictionary of option values.
        """
        if new_options is None:
            return
        self._layers.append(self._convert_options(new_options))
    
    def _convert_options(self, new_options):
        """! @brief Prepare a dictionary of user options for use by the manager.
        
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

    def get(self, key):
        """! @brief Return the highest priority value for the option, or its default."""
        for layer in self._layers:
            if key in layer:
                return layer[key]
        else:
            if key in OPTIONS_INFO:
                return OPTIONS_INFO[key].default
            else:
                return None
    
    def set(self, key, value):
        """! @brief Set an option in the current highest priority layer."""
        self.update({key: value})
    
    def update(self, new_options):
        """! @brief Set multiple options in the current highest priority layer."""
        self._layers[0].update(self._convert_options(new_options))

    def __contains__(self, key):
        """! @brief Returns whether the named option has a non-default value."""
        for layer in self._layers:
            if key in layer:
                return True
        else:
            return False
        
    def __getitem__(self, key):
        """! @brief Return the highest priority value for the option, or its default."""
        return self.get(key)
    
    def __setitem__(self, key, value):
        """! @brief Set an option in the current highest priority layer."""
        self.set(key, value)
