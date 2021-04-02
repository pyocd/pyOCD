# pyOCD debugger
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

import argparse
from typing import List
import logging
from time import sleep

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..core.session import Session
from ..utility.cmdline import convert_session_options
from ..probe.tcp_probe_server import DebugProbeServer

LOG = logging.getLogger(__name__)

class ServerSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['server']
    HELP = "Run debug probe server."
    
    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        server_parser = argparse.ArgumentParser(description='server', add_help=False)

        server_config_options = server_parser.add_argument_group('configuration')
        server_config_options.add_argument('-j', '--project', '--dir', metavar="PATH", dest="project_dir",
            help="Set the project directory. Defaults to the directory where pyocd was run.")
        server_config_options.add_argument('--config', metavar="PATH",
            help="Specify YAML configuration file. Default is pyocd.yaml or pyocd.yml.")
        server_config_options.add_argument("--no-config", action="store_true", default=None,
            help="Do not use a configuration file.")
        server_config_options.add_argument('-O', action='append', dest='options', metavar="OPTION=VALUE",
            help="Set named option.")
        server_config_options.add_argument("-da", "--daparg", dest="daparg", nargs='+',
            help="Send setting to DAPAccess layer.")

        server_options = server_parser.add_argument_group('probe server')
        server_options.add_argument("-p", "--port", dest="port_number", type=int, default=None,
            help="Set the server's port number (default 5555).")
        server_options.add_argument("--allow-remote", dest="serve_local_only", default=None, action="store_false",
            help="Allow remote TCP/IP connections (default is no).")
        server_options.add_argument("--local-only", default=False, action="store_true",
            help="Ignored and deprecated. Server is local only by default. Use --alow-remote to enable remote "
                 "connections.")
        server_options.add_argument("-u", "--uid", "--probe", dest="unique_id",
            help="Serve the specified probe. Optionally prefixed with '<probe-type>:' where <probe-type> is the "
                 "name of a probe plugin.")
        server_options.add_argument("-W", "--no-wait", action="store_true",
            help="Do not wait for a probe to be connected if none are available.")
        
        return [cls.CommonOptions.LOGGING, server_parser]
    
    def invoke(self) -> None:
        """! @brief Handle 'server' subcommand."""
        # Create a session to load config, particularly logging config. Even though we do have a
        # probe, we don't set it in the session because we don't want the board, target, etc objects
        # to be created.
        session_options = convert_session_options(self._args.options)
        session = Session(probe=None,
                serve_local_only=self._args.serve_local_only,
                options=session_options)
        
        # The ultimate intent is to serve all available probes by default. For now we just serve
        # a single probe.
        probe = ConnectHelper.choose_probe(unique_id=self._args.unique_id)
        if probe is None:
            return
        
        # Assign the session to the probe.
        probe.session = session
        
        # Create the server instance.
        server = DebugProbeServer(session, probe, self._args.port_number, self._args.serve_local_only)
        session.probeserver = server
        LOG.debug("Starting debug probe server")
        server.start()
        
        # Loop as long as the probe is running. The server thread is a daemon, so the main thread
        # must continue to exist.
        try:
            while server.is_running:
                sleep(0.1)
        except (KeyboardInterrupt, Exception):
            server.stop()
            raise

