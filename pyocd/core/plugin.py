# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import pkg_resources
import logging

from .._version import version as pyocd_version
from .options import add_option_set

LOG = logging.getLogger(__name__)

class Plugin(object):
    """! @brief Class that describes a plugin for pyOCD.
    
    Each plugin vends a subclass of Plugin that describes itself and provides meta-actions.
    
    An instance is created and queried for whether the plugin can be loaded by calling
    should_load(). If this method returns True, then load() is called. The default implementation
    will always load, and does nothing when loaded.
    """
    
    def should_load(self):
        """! @brief Whether the plugin should be loaded."""
        return True
    
    def load(self):
        """! @brief Load the plugin and return the plugin implementation.
        
        This method can perform any actions required to load the plugin beyond simply returning
        the implementation.
        
        @return An object appropriate for the plugin type, which normally would be a class object.
        """
        pass
    
    @property
    def options(self):
        """! @brief A list of options added by the plugin.
        @return List of @ref pyocd.core.options.OptionInfo "OptionInfo" objects.
        """
        return []
    
    @property
    def version(self):
        """! @brief Current version of the plugin.
        
        The default implementation returns pyOCD's version.
        
        @return String with the plugin's version, such as '2.13.4'.
        """
        return pyocd_version
    
    @property
    def name(self):
        """! @brief Name of the plugin."""
        raise NotImplementedError()
    
    @property
    def description(self):
        """! @brief Short description of the plugin."""
        return ""

def load_plugin_classes_of_type(plugin_group, plugin_dict, base_class):
    """! @brief Helper method to load plugins.
    
    Plugins are expected to return an implementation class from their Plugin.load() method. This
    class must be derived from `base_class`.
    
    @param plugin_group String of the plugin group, e.g. 'pyocd.probe'.
    @param plugin_dict Dictionary to fill with loaded plugin classes.
    @param base_class The required superclass for plugin implementation classes.
    """
    for entry_point in pkg_resources.iter_entry_points(plugin_group):
        # Instantiate the plugin class.
        plugin = entry_point.load()()
        if not isinstance(plugin, Plugin):
            LOG.warning("Plugin '%s' of type '%s' has an invalid plugin object",
                    entry_point.name, plugin_group)
            continue
        
        # Ask the plugin whether it should be loaded.
        if plugin.should_load():
            # Load the plugin and stuff the implementation class it gives
            impl_class = plugin.load()
            if not issubclass(impl_class, base_class):
                LOG.warning("Plugin '%s' of type '%s' returned an unexpected implementation class",
                        plugin.name, plugin_group)
                continue
            plugin_dict[plugin.name] = impl_class
            
            # Add any plugin options.
            add_option_set(plugin.options)
                
