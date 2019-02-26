# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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
import six
import yaml
import os

# inspect.getargspec is deprecated in Python 3.
try:
    from inspect import getfullargspec as getargspec
except ImportError:
    from inspect import getargspec

DEFAULT_CLOCK_FREQ = 1000000 # 1 MHz

LOG = logging.getLogger(__name__)

## @brief Set of default config filenames to search for.
_CONFIG_FILE_NAMES = [
        "pyocd.yaml",
        "pyocd.yml",
        ".pyocd.yaml",
        ".pyocd.yml",
    ]

## @brief Set of default user script names to search for.
_USER_SCRIPT_NAMES = [
        "pyocd_user.py",
        ".pyocd_user.py",
    ]

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
        self._user_script_proxy = None
        self._delegate = None
        
        # Update options.
        self._options = options or {}
        self._options.update(kwargs)
        
        # Init project directory.
        if self._options.get('project_dir', None) is None:
            self._project_dir = os.getcwd()
        else:
            self._project_dir = os.path.abspath(os.path.expanduser(self._options['project_dir']))
        LOG.debug("Project directory: %s", self.project_dir)
        
        # Bail early if we weren't provided a probe.
        if probe is None:
            self._board = None
            return
            
        # Apply common configuration settings from the config file.
        config = self._get_config()
        probesConfig = config.pop('probes', None)
        self._options.update(config)

        # Pick up any config file options for this probe.
        if probesConfig is not None:
            for uid, settings in probesConfig.items():
                if str(uid).lower() in probe.unique_id.lower():
                    LOG.info("Using config settings for board %s" % (probe.unique_id))
                    self._options.update(settings)
        
        # Ask the probe if it has an associated board, and if not then we create a generic one.
        self._board = probe.create_associated_board(self) \
                        or Board(self, self._options.get('target_override', None))
    
    def _get_config(self):
        # Load config file if one was provided via options, and no_config option was not set.
        if not self._options.get('no_config', False):
            configPath = self.find_user_file('config_file', _CONFIG_FILE_NAMES)
                    
            if isinstance(configPath, six.string_types):
                try:
                    with open(configPath, 'r') as configFile:
                        LOG.debug("Loading config from: %s", configPath)
                        return yaml.safe_load(configFile)
                except IOError as err:
                    LOG.warning("Error attempting to access config file '%s': %s", configPath, err)
        
        return {}
            
    def find_user_file(self, option_name, filename_list):
        """! @brief Search the project directory for a file."""
        if option_name is not None:
            filePath = self._options.get(option_name, None)
        else:
            filePath = None
        
        # Look for default filenames if a path wasn't provided.
        if filePath is None:
            for filename in filename_list:
                thisPath = os.path.join(self.project_dir, filename)
                if os.path.isfile(thisPath):
                    filePath = thisPath
                    break
        # Use the path passed in options, which may be absolute, relative to the
        # home directory, or relative to the project directory.
        else:
            filePath = os.path.expanduser(filePath)
            if not os.path.isabs(filePath):
                filePath = os.path.join(self.project_dir, filePath)
        
        return filePath
    
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
    
    @property
    def project_dir(self):
        return self._project_dir
    
    @property
    def delegate(self):
        return self._delegate
    
    @delegate.setter
    def delegate(self, new_delegate):
        self._delegate = new_delegate
    
    @property
    def user_script_proxy(self):
        return self._user_script_proxy

    def __enter__(self):
        assert self._probe is not None
        return self

    def __exit__(self, type, value, traceback):
        self.close()
        return False
    
    def _load_user_script(self):
        scriptPath = self.find_user_file('user_script', _USER_SCRIPT_NAMES)

        if isinstance(scriptPath, six.string_types):
            try:
                # Read the script source.
                with open(scriptPath, 'r') as scriptFile:
                    LOG.debug("Loading user script: %s", scriptPath)
                    scriptCode = scriptFile.read()
                
                # Construct the user script namespace. The namespace will have convenient access to
                # most of the pyOCD object graph.
                import pyocd
                namespace = {
                    'pyocd': pyocd,
                    'session': self,
                    'options': self.options,
                    'probe': self.probe,
                    'board': self.board,
                    'target': self.target,
                    'dp': self.target.dp,
                    'aps': self.target.aps,
                    'Target': pyocd.core.target.Target,
                    'ResetType': pyocd.core.target.Target.ResetType,
                    'MemoryType': pyocd.core.memory_map.MemoryType,
                    'FileProgrammer': pyocd.flash.loader.FileProgrammer,
                    'FlashEraser': pyocd.flash.loader.FlashEraser,
                    'FlashLoader': pyocd.flash.loader.FlashLoader,
                    'LOG': logging.getLogger(os.path.basename('pyocd.user_script')),
                    }
                
                # Executing the code will create definitions in the namespace for any
                # functions or classes. A single namespace is shared for both globals and
                # locals so that script-level definitions are available within the
                # script functions.
                six.exec_(scriptCode, namespace, namespace)
                
                # Create the proxy for the user script. It becomes the delegate unless
                # another delegate was already set.
                self._user_script_proxy = UserScriptDelegateProxy(namespace)
                if self._delegate is None:
                    self._delegate = self._user_script_proxy
            except IOError as err:
                LOG.warning("Error attempting to load user script '%s': %s", scriptPath, err)

    ## @brief Initialize the session
    def open(self, init_board=True):
        """! @brief Open the session.
        
        This method does everything necessary to begin a debug session. It first loads the user
        script, if there is one. The user script will be available via the _user_script_proxy_
        property. Then it opens the debug probe and sets the clock rate from the `frequency` user
        option. Finally, it inits the board (which will init the target, which performs the
        full target init sequence).
        
        @param self
        @param init_board This parameter lets you prevent the board from being inited, which can
            be useful in board bringup situations. It's also used by pyocd commander's "no init"
            feature.
        """
        if not self._inited:
            assert self._probe is not None, "Cannot open a session without a probe."
            assert self._board is not None, "Must have a board to open a session."
            
            # Load the user script just before we init everything.
            self._load_user_script()
            
            self._probe.open()
            self._probe.set_clock(self._options.get('frequency', DEFAULT_CLOCK_FREQ))
            if init_board:
                self._board.init()
                self._inited = True
            self._closed = False

    ## @brief Close the session.
    def close(self):
        """! @brief Close the session.
        
        Uninits the board and disconnects then closes the probe.
        """
        if self._closed:
            return
        self._closed = True

        LOG.debug("uninit session %s", self)
        if self._inited:
            try:
                self.board.uninit()
                self._inited = False
            except:
                LOG.error("exception during board uninit:", exc_info=True)
        
        if self._probe.is_open:
            try:
                self._probe.disconnect()
            except:
                LOG.error("probe exception during disconnect:", exc_info=True)
            try:
                self._probe.close()
            except:
                LOG.error("probe exception during close:", exc_info=True)

class UserScriptFunctionProxy(object):
    """! @brief Proxy for user script functions.
    
    This proxy makes arguments to user script functions optional. 
    """

    def __init__(self, fn):
        self._fn = fn
        self._spec = getargspec(fn)
    
    def __call__(self, **kwargs):
        args = {}
        for arg in self._spec.args:
            if arg in kwargs:
                args[arg] = kwargs[arg]
        self._fn(**args)

class UserScriptDelegateProxy(object):
    """! @brief Delegate proxy for user scripts."""

    def __init__(self, script_namespace):
        super(UserScriptDelegateProxy, self).__init__()
        self._script = script_namespace
    
    def __getattr__(self, name):
        if name in self._script:
            fn = self._script[name]
            return UserScriptFunctionProxy(fn)
        else:
            raise AttributeError(name)
