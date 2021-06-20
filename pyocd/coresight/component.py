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

from ..utility.graph import GraphNode

class CoreSightComponent(GraphNode):
    """! @brief CoreSight component base class."""
    
    @classmethod
    def factory(cls, ap, cmpid, address):
        """! @brief Common CoreSightComponent factory."""
        cmp = cls(ap, cmpid, address)
        if hasattr(ap, 'core') and ap.core:
            ap.core.add_child(cmp)
        return cmp

    def __init__(self, ap, cmpid=None, addr=None):
        """! @brief Constructor."""
        super(CoreSightComponent, self).__init__()
        self._ap = ap
        self._cmpid = cmpid
        self._address = addr if (addr is not None) else (cmpid.address if cmpid else None)
    
    @property
    def ap(self):
        return self._ap
    
    @property
    def cmpid(self):
        return self._cmpid
    
    @cmpid.setter
    def cmpid(self, newCmpid):
        self._cmpid = newCmpid
    
    @property
    def address(self):
        return self._address
    
    @address.setter
    def address(self, newAddr):
        self._address = newAddr

class CoreSightCoreComponent(CoreSightComponent):
    """! @brief CoreSight component for a CPU core.
    
    This class serves only as a superclass for identifying core-type components.
    """
    pass
