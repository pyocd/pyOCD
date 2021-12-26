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

import logging
import logging.config
import yaml
import os
import weakref
from inspect import getfullargspec
from typing import (Any, cast, Dict, List, Mapping, Optional, TYPE_CHECKING)

from . import exceptions
from .options_manager import OptionsManager
from ..board.board import Board
from ..utility.notification import Notifier

if TYPE_CHECKING:
    from types import TracebackType
    from .soc_target import SoCTarget
    from ..probe.debug_probe import DebugProbe
    from ..probe.tcp_probe_server import DebugProbeServer
    from ..gdbserver.gdbserver import GDBServer

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

class Session(Notifier):
    """! @brief Top-level object for a debug session.

    This class represents a debug session with a single debug probe. It is the root of the object
    graph, where it owns the debug probe and the board objects.

    Another important function of this class is that it contains a dictionary of session-scope
    options. These would normally be passed in from the command line. Options can also be loaded
    from a config file.

    Precedence for session options:

    1. Keyword arguments to constructor.
    2. _options_ parameter to constructor.
    3. Probe-specific options from a config file.
    4. General options from a config file.
    5. _option_defaults_ parameter to constructor.

    The session also tracks several other objects:
    - @ref pyocd.gdbserver.gdbserver.GDBServer "GDBServer" instances created for any cores.
    - @ref pyocd.probe.tcp_probe_server.DebugProbeServer "DebugProbeServer".
    - The user script proxy.

    See the @ref pyocd.core.helpers.ConnectHelper "ConnectHelper" class for several methods that
    make it easy to create new sessions, with or without user interaction in the case of multiple
    available debug probes. A common pattern is to combine @ref
    pyocd.core.helpers.ConnectHelper.session_with_chosen_probe()
    "ConnectHelper.session_with_chosen_probe()" and a **with** block.

    A Session instance can be used as a context manager. The session will, by default, be
    automatically opened when the context is entered. And, of course, it will be closed when the
    **with** block is exited (which is harmless if the session was never opened). If you wish to
    disable automatic opening, set the `auto_open` parameter to the constructor to False. If an
    exception is raised while opening a session inside a **with** statement, the session will be
    closed for you to undo any partial initialisation.
    """

    ## @brief Weak reference to the most recently created session.
    _current_session: Optional[weakref.ref] = None

    @classmethod
    def get_current(cls) -> "Session":
        """! @brief Return the most recently created Session instance or a default Session.

        By default this method will return the most recently created Session object that is
        still alive. If no live session exists, a new default session will be created and returned.
        That at least provides access to the user's config file(s).

        Used primarily so code that doesn't have a session reference can access session options. This
        method should only be used to access options that are unlikely to differ between sessions,
        or for debug or other purposes.
        """
        if cls._current_session is not None:
            session = cls._current_session()
            if session is not None:
                return session

        return Session(None)

    def __init__(
            self,
            probe: Optional["DebugProbe"],
            auto_open: bool = True,
            options: Optional[Mapping[str, Any]] = None,
            option_defaults: Optional[Mapping[str, Any]] = None,
            **kwargs
            ) -> None:
        """! @brief Session constructor.

        Creates a new session using the provided debug probe. Session options are merged from the
        _options_ parameter and any keyword arguments. Normally a board instance is created that can
        either be a generic board or a board associated with the debug probe.

        Note that the 'project_dir' and 'config' options must be set in either keyword arguments or
        the _options_ parameter.

        Passing in a _probe_ that is None is allowed. This is useful to create a session that operates
        only as a container for session options. In this case, the board instance is not created, so the
        #board attribute will be None. Such a Session cannot be opened.

        @param self
        @param probe The @ref pyocd.probe.debug_probe. "DebugProbe" instance. May be None.
        @param auto_open Whether to automatically open the session when used as a context manager.
        @param options Optional session options dictionary.
        @param option_defaults Optional dictionary of session option values. This dictionary has the
            lowest priority in determining final session option values, and is intended to set new
            defaults for option if they are not set through any other method.
        @param kwargs Session options passed as keyword arguments.
        """
        super().__init__()

        Session._current_session = weakref.ref(self)

        self._probe = probe
        self._closed: bool = True
        self._inited: bool = False
        self._user_script_namespace: Dict[str, Any] = {}
        self._user_script_proxy: Optional[UserScriptDelegateProxy] = None
        self._delegate: Optional[Any] = None
        self._auto_open = auto_open
        self._options = OptionsManager()
        self._gdbservers: Dict[int, "GDBServer"] = {}
        self._probeserver: Optional["DebugProbeServer"] = None

        # Set this session on the probe, if we were given a probe.
        if probe is not None:
            probe.session = self

        # Update options.
        self._options.add_front(kwargs)
        self._options.add_back(options)

        # Init project directory.
        if self.options.get('project_dir') is None:
            self._project_dir: str = os.environ.get('PYOCD_PROJECT_DIR') or os.getcwd()
        else:
            self._project_dir: str = os.path.abspath(os.path.expanduser(self.options.get('project_dir')))
        LOG.debug("Project directory: %s", self.project_dir)

        # Switch the working dir to the project dir.
        os.chdir(self.project_dir)

        # Load options from the config file.
        config = self._get_config()
        probes_config = config.pop('probes', None)

        # Pick up any config file options for this probe. These have priority over global options.
        if (probe is not None) and (probes_config is not None):
            did_match_probe = False
            for uid, settings in probes_config.items():
                if str(uid).lower() in probe.unique_id.lower():
                    if did_match_probe:
                        LOG.warning("Multiple probe config options match probe ID %s", probe.unique_id)
                        break
                    LOG.info("Using config options for probe %s" % (probe.unique_id))
                    self._options.add_back(settings)
                    did_match_probe = True

        # Add global config options.
        self._options.add_back(config)

        # Merge in lowest priority options.
        self._options.add_back(option_defaults)

        # Logging config.
        self._configure_logging()

        # Bail early if we weren't provided a probe.
        if probe is None:
            self._board = None
            return

        # Load the user script.
        self._load_user_script()

        # Ask the probe if it has an associated board, and if not then we create a generic one.
        self._board = probe.create_associated_board() or Board(self)

    def _get_config(self) -> Dict[str, Any]:
        # Load config file if one was provided via options, and no_config option was not set.
        if not self.options.get('no_config'):
            configPath = self.find_user_file('config_file', _CONFIG_FILE_NAMES)

            if configPath is not None:
                try:
                    with open(configPath, 'r') as configFile:
                        LOG.debug("Loading config from: %s", configPath)
                        config = yaml.safe_load(configFile)
                        # Allow an empty config file.
                        if config is None:
                            return {}
                        # But fail if someone tries to put something other than a dict at the top.
                        elif not isinstance(config, dict):
                            raise exceptions.Error("configuration file %s does not contain a top-level dictionary"
                                    % configPath)
                        return config
                except IOError as err:
                    LOG.warning("Error attempting to access config file '%s': %s", configPath, err)

        return {}

    def find_user_file(self, option_name: Optional[str], filename_list: List[str]) -> Optional[str]:
        """! @brief Search the project directory for a file.

        @retval None No matching file was found.
        @retval string An absolute path to the requested file.
        """
        if option_name is not None:
            filePath = self.options.get(option_name)
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

    def _configure_logging(self) -> None:
        """! @brief Load a logging config dict or file."""
        # Get logging config that could have been loaded from the config file.
        config_value = self.options.get('logging')

        # Allow logging setting to refer to another file.
        if isinstance(config_value, str):
            loggingConfigPath = self.find_user_file(None, [config_value])

            if loggingConfigPath is not None:
                try:
                    with open(loggingConfigPath, 'r') as configFile:
                        config = yaml.safe_load(configFile)
                        LOG.debug("Using logging configuration from: %s", config)
                except IOError as err:
                    LOG.warning("Error attempting to load logging config file '%s': %s", config_value, err)
                    return
            else:
                LOG.warning("Logging config file '%s' does not exist", config_value)
                return
        else:
            config = config_value

        if config is not None:
            # Stuff a version key if it's missing, to make it easier to use.
            if 'version' not in config:
                config['version'] = 1
            # Set a different default for disabling existing loggers.
            if 'disable_existing_loggers' not in config:
                config['disable_existing_loggers'] = False
            # Remove an empty 'loggers' key.
            if ('loggers' in config) and (config['loggers'] is None):
                del config['loggers']

            try:
                logging.config.dictConfig(config)
            except (ValueError, TypeError, AttributeError, ImportError) as err:
                LOG.warning("Error applying logging configuration: %s", err)

    @property
    def is_open(self) -> bool:
        """! @brief Boolean of whether the session has been opened."""
        return self._inited and not self._closed

    @property
    def probe(self) -> Optional["DebugProbe"]:
        """! @brief The @ref pyocd.probe.debug_probe.DebugProbe "DebugProbe" instance."""
        return self._probe

    @property
    def board(self) -> Optional[Board]:
        """! @brief The @ref pyocd.board.board.Board "Board" object."""
        return self._board

    @property
    def target(self) -> Optional["SoCTarget"]:
        """! @brief The @ref pyocd.core.target.soc_target "SoCTarget" object representing the SoC.

        This is the @ref pyocd.core.target.soc_target "SoCTarget" instance owned by the board.
        """
        return self.board.target if self.board else None

    @property
    def options(self) -> OptionsManager:
        """! @brief The @ref pyocd.core.options_manager.OptionsManager "OptionsManager" object."""
        return self._options

    @property
    def project_dir(self) -> str:
        """! @brief Path to the project directory."""
        return self._project_dir

    @property
    def delegate(self) -> Any:
        """! @brief An optional delegate object for customizing behaviour."""
        return self._delegate

    @delegate.setter
    def delegate(self, new_delegate: Any) -> None:
        """! @brief Setter for the `delegate` property."""
        self._delegate = new_delegate

    @property
    def user_script_proxy(self) -> Optional["UserScriptDelegateProxy"]:
        """! @brief The UserScriptDelegateProxy object for a loaded user script."""
        return self._user_script_proxy

    @property
    def gdbservers(self) -> Dict[int, "GDBServer"]:
        """! @brief Dictionary of core numbers to @ref pyocd.gdbserver.gdbserver.GDBServer "GDBServer" instances."""
        return self._gdbservers

    @property
    def probeserver(self) -> Optional["DebugProbeServer"]:
        """! @brief A @ref pyocd.probe.tcp_probe_server.DebugProbeServer "DebugProbeServer" instance."""
        return self._probeserver

    @probeserver.setter
    def probeserver(self, server: "DebugProbeServer") -> None:
        """! @brief Setter for the `probeserver` property."""
        self._probeserver = server

    @property
    def log_tracebacks(self) -> bool:
        """! @brief Quick access to debug.traceback option since it is widely used."""
        return cast(bool, self.options.get('debug.traceback'))

    def __enter__(self) -> "Session":
        assert self._probe is not None
        if self._auto_open:
            try:
                self.open()
            except Exception:
                self.close()
                raise
        return self

    def __exit__(self, exc_type: type, value: Any, traceback: "TracebackType") -> bool:
        self.close()
        return False

    def _init_user_script_namespace(self, user_script_path: str) -> None:
        """! @brief Create the namespace dict used for user scripts.

        This initial namespace has only those objects that are available very early in the
        session init process. For instance, the Target instance isn't available yet. The
        _update_user_script_namespace() method is used to add such objects to the namespace
        later on.
        """
        import pyocd
        from . import target
        from . import memory_map
        from ..flash import file_programmer
        from ..flash import eraser
        from ..flash import loader
        self._user_script_namespace = {
            # Modules and classes
            'pyocd': pyocd,
            'exceptions': exceptions,
            'Error': exceptions.Error,
            'TransferError': exceptions.TransferError,
            'TransferFaultError': exceptions.TransferFaultError,
            'Target': target.Target,
            'State': target.Target.State,
            'SecurityState': target.Target.SecurityState,
            'BreakpointType': target.Target.BreakpointType,
            'WatchpointType': target.Target.WatchpointType,
            'VectorCatch': target.Target.VectorCatch,
            'Event': target.Target.Event,
            'RunType': target.Target.RunType,
            'HaltReason': target.Target.HaltReason,
            'ResetType': target.Target.ResetType,
            'MemoryType': memory_map.MemoryType,
            'MemoryMap': memory_map.MemoryMap,
            'RamRegion': memory_map.RamRegion,
            'RomRegion': memory_map.RomRegion,
            'FlashRegion': memory_map.FlashRegion,
            'DeviceRegion': memory_map.DeviceRegion,
            'FileProgrammer': file_programmer.FileProgrammer,
            'FlashEraser': eraser.FlashEraser,
            'FlashLoader': loader.FlashLoader,
            # User script info
            '__name__': os.path.splitext(os.path.basename(user_script_path))[0],
            '__file__': user_script_path,
            # Objects
            'session': self,
            'options': self.options,
            'LOG': logging.getLogger('pyocd.user_script'),
            }

    def _update_user_script_namespace(self) -> None:
        """! @brief Add objects available only after init to the user script namespace."""
        if self._user_script_namespace is not None:
            self._user_script_namespace.update({
                'probe': self.probe,
                'board': self.board,
                'target': self.target,
                'dp': getattr(self.target, "dp", None),
                'aps': getattr(self.target, "aps", None),
                })

    def _load_user_script(self) -> None:
        scriptPath = self.find_user_file('user_script', _USER_SCRIPT_NAMES)

        if scriptPath is not None:
            try:
                # Read the script source.
                with open(scriptPath, 'r') as scriptFile:
                    LOG.debug("Loading user script: %s", scriptPath)
                    scriptSource = scriptFile.read()

                self._init_user_script_namespace(scriptPath)

                scriptCode = compile(scriptSource, scriptPath, 'exec')
                # Executing the code will create definitions in the namespace for any
                # functions or classes. A single namespace is shared for both globals and
                # locals so that script-level definitions are available within the
                # script functions.
                exec(scriptCode, self._user_script_namespace, self._user_script_namespace)

                # Create the proxy for the user script. It becomes the delegate unless
                # another delegate was already set.
                self._user_script_proxy = UserScriptDelegateProxy(self._user_script_namespace)
                if self._delegate is None:
                    self._delegate = self._user_script_proxy
            except IOError as err:
                LOG.warning("Error attempting to load user script '%s': %s", scriptPath, err)

    def open(self, init_board: bool = True) -> None:
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

            # Add in the full set of objects for the user script.
            self._update_user_script_namespace()

            self._probe.open()
            self._closed = False
            self._probe.set_clock(self.options.get('frequency'))
            if init_board:
                self._board.init()
                self._inited = True

    def close(self) -> None:
        """! @brief Close the session.

        Uninits the board and disconnects then closes the probe.
        """
        if self._closed:
            return
        self._closed = True

        # Should not have been able to open the session with either _probe or _board being None.
        assert (self._probe is not None) and (self._board is not None)

        LOG.debug("uninit session %s", self)
        if self._inited:
            try:
                self._board.uninit()
                self._inited = False
            except exceptions.Error:
                LOG.error("exception during board uninit:", exc_info=self.log_tracebacks)

        if self._probe.is_open:
            try:
                self._probe.disconnect()
            except exceptions.Error:
                LOG.error("probe exception during disconnect:", exc_info=self.log_tracebacks)
            try:
                self._probe.close()
            except exceptions.Error:
                LOG.error("probe exception during close:", exc_info=self.log_tracebacks)

class UserScriptFunctionProxy:
    """! @brief Proxy for user script functions.

    This proxy makes arguments to user script functions optional.
    """

    def __init__(self, fn) -> None:
        self._fn = fn
        self._spec = getfullargspec(fn)

    def __call__(self, **kwargs) -> Any:
        args = {}
        for arg in self._spec.args:
            if arg in kwargs:
                args[arg] = kwargs[arg]
        self._fn(**args)

class UserScriptDelegateProxy:
    """! @brief Delegate proxy for user scripts."""

    def __init__(self, script_namespace: Dict) -> None:
        super().__init__()
        self._script = script_namespace

    def __getattr__(self, name: str) -> Any:
        if name in self._script:
            fn = self._script[name]
            return UserScriptFunctionProxy(fn)
        else:
            raise AttributeError(name)
