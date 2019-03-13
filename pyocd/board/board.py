# pyOCD debugger
# Copyright (c) 2006-2013,2018 Arm Limited
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

from ..target import TARGET
from ..target.pack import pack_target
from ..utility.graph import GraphNode
import logging
import six

log = logging.getLogger('board')

class Board(GraphNode):
    """
    This class associates a target and flash to create a board.
    """
    def __init__(self, session, target=None):
        super(Board, self).__init__()
        
        # As a last resort, default the target to 'cortex_m'.
        if target is None:
            target = 'cortex_m'
        self._session = session
        self._target_type = target.lower()
        self._test_binary = session.options.get('test_binary', None)
        self._delegate = None
        
        # Create targets from provided CMSIS pack.
        if ('pack' in session.options) and (session.options['pack'] is not None):
            pack_target.populate_targets_from_pack(session.options['pack'])

        # Create Target and Flash instances.
        try:
            log.info("Target type is %s", self._target_type)
            self.target = TARGET[self._target_type](session)
        except KeyError as exc:
            log.error("target '%s' not recognized", self._target_type)
            six.raise_from(KeyError("target '%s' not recognized" % self._target_type), exc)
        self._inited = False
        
        self.add_child(self.target)

    ## @brief Initialize the board.
    def init(self):
        # If we don't have a delegate set yet, see if there is a session delegate.
        if (self.delegate is None) and (self.session.delegate is not None):
            self.delegate = self.session.delegate
        
        # Delegate pre-init hook.
        if (self.delegate is not None) and hasattr(self.delegate, 'will_connect'):
            self.delegate.will_connect(board=self)
        
        # Init the target.
        self.target.init()
        self._inited = True
        
        # Delegate post-init hook.
        if (self.delegate is not None) and hasattr(self.delegate, 'did_connect'):
            self.delegate.did_connect(board=self)

    ## @brief Uninitialize the board.
    def uninit(self):
        if self._inited:
            log.debug("uninit board %s", self)
            try:
                resume = self.session.options.get('resume_on_disconnect', True)
                self.target.disconnect(resume)
                self._inited = False
            except:
                log.error("link exception during target disconnect:", exc_info=True)

    @property
    def session(self):
        return self._session
    
    @property
    def delegate(self):
        return self._delegate
    
    @delegate.setter
    def delegate(self, the_delegate):
        self._delegate = the_delegate
        
    @property
    def unique_id(self):
        return self.session.probe.unique_id
    
    @property
    def target_type(self):
        return self._target_type
    
    @property
    def test_binary(self):
        return self._test_binary
    
    @property
    def name(self):
        return "generic"
    
    @property
    def description(self):
        return "Generic board via " + self.session.probe.vendor_name + " " \
                + self.session.probe.product_name + " [" + self.target_type + "]"
