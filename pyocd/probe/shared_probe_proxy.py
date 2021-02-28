# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from .debug_probe import DebugProbe
from ..core import exceptions

LOG = logging.getLogger(__name__)

class SharedDebugProbeProxy(object):
    """! @brief Proxy for a DebugProbe that allows it to be shared by multiple clients.
    
    The main purpose of this class is to keep track of the number of times the probe has been
    opened and connected, and to perform checks to ensure that probes don't interfere with each
    other. Most probe APIs are simply passed to the underlying probe object.
    """
    
    def __init__(self, probe):
        self._session = None
        self._probe = probe
        self._open_count = 0
        self._connect_count = 0

    @property
    def session(self):
        """! @brief Session associated with this probe."""
        return self._session
    
    @session.setter
    def session(self, the_session):
        self._session = the_session
        self._probe.session = the_session
    
    @property
    def probe(self):
        return self._probe
    
    def open(self):
        if self._open_count == 0:
            self._probe.open()
        self._open_count += 1
    
    def close(self):
        if self._open_count == 1:
            self._probe.close()
        self._open_count -= 1

    def connect(self, protocol=None):
        # First to connect gets to choose the protocol.
        if self._connect_count == 0:
            self._probe.connect(protocol)
        elif protocol not in (DebugProbe.Protocol.DEFAULT, self._probe.wire_protocol):
            raise exceptions.ProbeError("probe already connected using %s protocol" % self._probe.wire_protocol.name)
        self._connect_count += 1

    def disconnect(self):
        if self._connect_count == 1:
            self._probe.disconnect()
        self._connect_count -= 1

    def swj_sequence(self, length, bits):
        self._probe.swj_sequence(length, bits)
    
    def __getattr__(self, name):
        """! @brief Redirect to underlying probe object methods."""
        if hasattr(self._probe, name):
            return getattr(self._probe, name)
        else:
            raise AttributeError(name)

