# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

from ..board.board import Board
import logging
import logging.config
import six
import yaml
import os

DEFAULT_CLOCK_FREQ = 1000000 # 1 MHz

log = logging.getLogger('session')

## @brief Top-level object for a debug session.
#
# This class represents a debug session with a single debug probe. It is the root of the object
# graph, where it owns the debug probe and the board objects.
#
# Another important function of this class is that it contains a dictionary of session-scope
# user options. These would normally be passed in from the command line, or perhaps a config file.
#
# See the ConnectHelper class for several methods that make it easy to create new
# sessions, with or without user interaction in the case of multiple available debug probes.
#
# A Session instance can be used as a context manager. The session will *not* be automatically
# opened. However, it will be closed when the `with` block is exited (which is harmless if the
# session was never opened). A common pattern is to combine ConnectHelper.session_with_chosen_probe()
# and a `with` block. Unless the `open_session` parameter to ConnectHelper.session_with_chosen_probe()
# is changed from the default of True, the newly created Session will be opened for you prior to
# entering the with block.
#
# Supported user options:
# - auto_unlock
# - config_file
# - frequency
# - halt_on_connect
# - no_config
# - resume_on_disconnect
# - target_override
# - test_binary
class Session(object):

    ## @brief Session constructor.
    #
    # Creates a new session using the provided debug probe. User options are merged from the
    # _options_ parameter and any keyword arguments. Normally a board instance is created that can
    # either be a generic board or a board associated with the debug probe.
    #
    # Passing in a _probe_ that is None is allowed. This is useful to create a session that operates
    # only as a container for user options. In this case, the board instance is not created, so the
    # #board attribute will be None. Such a Session cannot be opened.
    #
    # @param self
    # @param probe The DebugProbe instance.
    # @param options Optional user options dictionary.
    # @param kwargs User options passed as keyword arguments.
    def __init__(self, probe, options=None, **kwargs):
        self._probe = probe
        self._closed = True
        self._inited = False
        
        # Update options.
        self._options = options or {}
        self._options.update(kwargs)
        
        # Bail early if we weren't provided a probe.
        if probe is None:
            self._board = None
            return
            
        # Apply common configuration settings from the config file.
        config = self._get_config()
        probesConfig = config.pop('probes', None)
        self._options.update(config)

        # Pick up any config file options for this board.
        if probesConfig is not None:
            for uid, settings in probesConfig.items():
                if uid.lower() in probe.unique_id.lower():
                    log.info("Using config settings for board %s" % (probe.unique_id))
                    self._options.update(settings)
        
        # Ask the probe if it has an associated board, and if not then we create a generic one.
        self._board = probe.create_associated_board(self) \
                        or Board(self, self._options.get('target_override', None))
    
    def _get_config(self):
        # Load config file if one was provided via options, and no_config option was not set.
        if not self._options.get('no_config', False):
            configPath = self._options.get('config_file', None)
            
            # Look for default config files.
            if configPath is None:
                if os.path.isfile("pyocd.yaml"):
                    configPath = "pyocd.yaml"
                elif os.path.isfile("pyocd.yml"):
                    configPath = "pyocd.yml"
                    
            if isinstance(configPath, six.string_types):
                try:
                    with open(configPath, 'r') as configFile:
                        log.debug("loading config from '%s'", configPath)
                        return yaml.safe_load(configFile)
                except IOError as err:
                    log.warning("Error attempting to access config file '%s': %s", configPath, err)
        
        return {}
    
    @property
    def is_open(self):
        return self._inited and not self._closed
    
    @property
    def probe(self):
        return self._probe
    
    @property
    def board(self):
        return self._board
    
    @property
    def target(self):
        return self.board.target
    
    @property
    def options(self):
        return self._options

    def __enter__(self):
        assert self._probe is not None
        return self

    def __exit__(self, type, value, traceback):
        self.close()
        return False

    ## @brief Initialize the session
    def open(self):
        if not self._inited:
            assert self._probe is not None
            self._probe.open()
            self._probe.set_clock(self._options.get('frequency', DEFAULT_CLOCK_FREQ))
            self._board.init()
            self._inited = True
            self._closed = False

    ## @brief Close the session.
    def close(self):
        if self._closed:
            return
        self._closed = True

        log.debug("uninit session %s", self)
        if self._inited:
            try:
                self.board.uninit()
                self._inited = False
            except:
                log.error("exception during board uninit:", exc_info=True)
        
        if self._probe.is_open:
            try:
                self._probe.disconnect()
            except:
                log.error("probe exception during disconnect:", exc_info=True)
            try:
                self._probe.close()
            except:
                log.error("probe exception during close:", exc_info=True)

