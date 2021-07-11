# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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

from ..core import exceptions
from ..core.plugin import load_plugin_classes_of_type
from .debug_probe import DebugProbe

## @brief Dictionary of loaded probe plugins indexed by name.
PROBE_CLASSES = {}

class DebugProbeAggregator(object):
    """! @brief Simple class to enable collecting probes of all supported probe types."""

    @staticmethod
    def _get_probe_classes(unique_id):
        """! @brief Return probe classes to query based on the unique ID string."""
        probe_type = None
        if unique_id is not None:
            fields = unique_id.split(':', 1)
            if len(fields) > 1:
                probe_type = fields[0].lower()
                unique_id = fields[1]

        if probe_type is None:
            klasses = PROBE_CLASSES.values()
        else:
            # Perform a case-insensitive match.
            klasses = [PROBE_CLASSES[k] for k in PROBE_CLASSES if k.lower() == probe_type]
            if not klasses:
                raise exceptions.Error("unknown debug probe type '{}'".format(probe_type))

        return klasses, unique_id, (probe_type is not None)

    @staticmethod
    def get_all_connected_probes(unique_id=None):
        klasses, unique_id, is_explicit = DebugProbeAggregator._get_probe_classes(unique_id)
        
        probes = []
        
        # First look for a match against the full ID, as this can be more efficient for certain probes.
        if unique_id is not None:
            for cls in klasses:
                probe = cls.get_probe_with_id(unique_id, is_explicit)
                if probe is not None:
                    return [probe]
        
        # No full match, so ask probe classes for probes.
        for cls in klasses:
            probes += cls.get_all_connected_probes(unique_id, is_explicit)
        
        # Filter by unique ID.
        if unique_id is not None:
            unique_id = unique_id.lower()
            probes = [probe for probe in probes if (unique_id in probe.unique_id.lower())]
        
        return probes
    
    @classmethod
    def get_probe_with_id(cls, unique_id):
        klasses, unique_id, is_explicit = DebugProbeAggregator._get_probe_classes(unique_id)
        
        for cls in klasses:
            probe = cls.get_probe_with_id(unique_id, is_explicit)
            if probe is not None:
                return probe
        return None

# Load plugins when this module is loaded.
load_plugin_classes_of_type('pyocd.probe', PROBE_CLASSES, DebugProbe)
