"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013,2018 ARM Limited

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

from ..target import (TARGET, FLASH)
import logging
import json
import six

log = logging.getLogger('board')

class Board(object):
    """
    This class associates a target, a flash and a link to create a board
    """
    def __init__(self, session, target=None):
        if target is None:
            target = 'cortex_m'
        self._session = session
        self._target_type = target.lower()
        self._test_binary = None
        
        # Pick up any settings for this board from a config file.
        boardConfig = self._load_board_config()
        for uid, settings in boardConfig.items():
            if uid.lower() in self.unique_id.lower():
                log.info("Using board config settings for board %s" % (session.probe.unique_id))
                if 'target_type' in settings:
                    self._target_type = settings['target_type']
                if 'test_binary' in settings:
                    self._test_binary = settings['test_binary']

        # Create Target and Flash instances.
        try:
            log.info("Target type is %s", self._target_type)
            self.target = TARGET[self._target_type](session)
            self.flash = FLASH[self._target_type](self.target)
        except KeyError as exc:
            log.error("target '%s' not recognized", self._target_type)
            six.raise_from(KeyError("target '%s' not recognized" % self._target_type), exc)
        self.target.setFlash(self.flash)
        self._inited = False
    
    def _load_board_config(self):
        # Load board config file if one was provided via options.
        if self._session.options.get('board_config_file', None) is not None:
            configPath = self._session.options['board_config_file']
            try:
                with open(configPath, 'r') as configFile:
                    return json.load(configFile)
            except IOError:
                pass
        
        return {}

    ## @brief Initialize the board.
    def init(self):
        self.target.init()
        self._inited = True

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

    # Deprecated methods...
    
    def getUniqueID(self):
        """
        Return the unique id of the board
        """
        return self.unique_id

    def getTargetType(self):
        """
        Return the type of the board
        """
        return self.target_type

    def getTestBinary(self):
        """
        Return name of test binary file
        """
        return self.test_binary

    def getBoardName(self):
        """
        Return board name
        """
        return self.name

    def getInfo(self):
        return self.description
