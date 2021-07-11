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
from typing import (Optional, List)
import logging
import sys
import os
from time import sleep

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..core.session import Session
from ..utility.cmdline import (
    convert_session_options,
    split_command_line,
    )
from ..probe.shared_probe_proxy import SharedDebugProbeProxy
from ..gdbserver import GDBServer
from ..probe.tcp_probe_server import DebugProbeServer
from ..coresight.generic_mem_ap import GenericMemAPTarget
from ..utility.notification import Notification

LOG = logging.getLogger(__name__)

class GdbserverSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['gdbserver', 'gdb']
    HELP = "Run the gdb remote server(s)."
    
    ## @brief Valid erase mode options.
    ERASE_OPTIONS = [
        'auto',
        'chip',
        'sector',
        ]

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        gdbserver_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        gdbserver_options = gdbserver_parser.add_argument_group("gdbserver options")
        gdbserver_options.add_argument("-p", "--port", metavar="PORT", dest="port_number", type=int,
            default=3333,
            help="Set starting port number for the GDB server (default 3333). Additional cores "
                "will have a port number of this parameter plus the core number.")
        gdbserver_options.add_argument("-T", "--telnet-port", metavar="PORT", dest="telnet_port",
            type=int, default=4444,
            help="Specify starting telnet port for semihosting (default 4444).")
        gdbserver_options.add_argument("-R", "--probe-server-port",
            dest="probe_server_port", metavar="PORT", type=int, default=5555,
            help="Specify the telnet port for semihosting (default 4444).")
        gdbserver_options.add_argument("--allow-remote", dest="serve_local_only", default=True, action="store_false",
            help="Allow remote TCP/IP connections (default is no).")
        gdbserver_options.add_argument("--persist", action="store_true",
            help="Keep GDB server running even after remote has detached.")
        gdbserver_options.add_argument("-r", "--probe-server", action="store_true", dest="enable_probe_server",
            help="Enable the probe server in addition to the GDB server.")
        gdbserver_options.add_argument("--core", metavar="CORE_LIST",
            help="Comma-separated list of cores for which gdbservers will be created. Default is all cores.")
        gdbserver_options.add_argument("--elf", metavar="PATH",
            help="Optionally specify ELF file being debugged.")
        gdbserver_options.add_argument("-e", "--erase", choices=cls.ERASE_OPTIONS, default='sector',
            help="Choose flash erase method. Default is sector.")
        gdbserver_options.add_argument("--trust-crc", action="store_true",
            help="Use only the CRC of each page to determine if it already has the same data.")
        gdbserver_options.add_argument("-C", "--vector-catch", default='h',
            help="Enable vector catch sources, one letter per enabled source in any order, or 'all' "
                "or 'none'. (h=hard fault, b=bus fault, m=mem fault, i=irq err, s=state err, "
                "c=check err, p=nocp, r=reset, a=all, n=none). Default is hard fault.")
        gdbserver_options.add_argument("-S", "--semihosting", dest="enable_semihosting", action="store_true",
            help="Enable semihosting.")
        gdbserver_options.add_argument("--step-into-interrupts", dest="step_into_interrupt", default=False, action="store_true",
            help="Allow single stepping to step into interrupts.")
        gdbserver_options.add_argument("-c", "--command", dest="commands", metavar="CMD", action='append', nargs='+',
            help="Run command (OpenOCD compatibility).")
        
        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, gdbserver_parser]
    
    def __init__(self, args: argparse.Namespace):
        """! @brief Constructor."""
        super().__init__(args)
        self._echo_msg = None
        
    def _process_commands(self, commands: Optional[List[str]]):
        """! @brief Handle OpenOCD commands for compatibility."""
        if commands is None:
            return
        for cmd_list in commands:
            try:
                cmd_list = split_command_line(cmd_list)
                cmd = cmd_list[0]
                if cmd == 'gdb_port':
                    if len(cmd_list) < 2:
                        LOG.error("Missing port argument")
                    else:
                        self._args.port_number = int(cmd_list[1], base=0)
                elif cmd == 'telnet_port':
                    if len(cmd_list) < 2:
                        LOG.error("Missing port argument")
                    else:
                        self._args.telnet_port = int(cmd_list[1], base=0)
                elif cmd == 'echo':
                    self._echo_msg = ' '.join(cmd_list[1:])
                else:
                    LOG.error("Unsupported command: %s" % ' '.join(cmd_list))
            except IndexError:
                pass

    def _gdbserver_listening_cb(self, note: Notification):
        """! @brief Callback invoked when the gdbserver starts listening on its port."""
        if self._echo_msg is not None:
            print(self._echo_msg, file=sys.stderr)
            sys.stderr.flush()
    
    def invoke(self) -> int:
        """! @brief Handle 'gdbserver' subcommand."""
        self._process_commands(self._args.commands)

        probe_server = None
        gdbs = []
        try:
            # Build dict of session options.
            sessionOptions = convert_session_options(self._args.options)
            sessionOptions.update({
                'gdbserver_port' : self._args.port_number,
                'telnet_port' : self._args.telnet_port,
                'persist' : self._args.persist,
                'step_into_interrupt' : self._args.step_into_interrupt,
                'chip_erase': self._args.erase,
                'fast_program' : self._args.trust_crc,
                'enable_semihosting' : self._args.enable_semihosting,
                'serve_local_only' : self._args.serve_local_only,
                'vector_catch' : self._args.vector_catch,
                })
            
            # Split list of cores to serve.
            if self._args.core is not None:
                try:
                    core_list = {int(x) for x in self._args.core.split(',')}
                except ValueError as err:
                    LOG.error("Invalid value passed to --core")
                    return 1
            else:
                core_list = None
            
            # Get the probe.
            probe = ConnectHelper.choose_probe(
                        blocking=(not self._args.no_wait),
                        return_first=False,
                        unique_id=self._args.unique_id,
                        )
            if probe is None:
                LOG.error("No probe selected.")
                return 1
            
            # Create a proxy so the probe can be shared between the session and probe server.
            probe_proxy = SharedDebugProbeProxy(probe)
            
            # Create the session.
            session = Session(probe_proxy,
                project_dir=self._args.project_dir,
                user_script=self._args.script,
                config_file=self._args.config,
                no_config=self._args.no_config,
                pack=self._args.pack,
                unique_id=self._args.unique_id,
                target_override=self._args.target_override,
                frequency=self._args.frequency,
                connect_mode=self._args.connect_mode,
                options=sessionOptions)
            if session is None:
                LOG.error("No probe selected.")
                return 1
            with session:
                # Validate the core selection.
                all_cores = set(session.target.cores.keys())
                if core_list is None:
                    core_list = all_cores
                bad_cores = core_list.difference(all_cores)
                if len(bad_cores):
                    LOG.error("Invalid core number%s: %s",
                        "s" if len(bad_cores) > 1 else "",
                        ", ".join(str(x) for x in bad_cores))
                    return 1
                
                # Set ELF if provided.
                if self._args.elf:
                    session.board.target.elf = os.path.expanduser(self._args.elf)
                    
                # Run the probe server is requested.
                if self._args.enable_probe_server:
                    probe_server = DebugProbeServer(session, session.probe,
                            self._args.probe_server_port, self._args.serve_local_only)
                    session.probeserver = probe_server
                    probe_server.start()
                    
                # Start up the gdbservers.
                for core_number, core in session.board.target.cores.items():
                    # Don't create a server for CPU-less memory Access Port. 
                    if isinstance(session.board.target.cores[core_number], GenericMemAPTarget):
                        continue
                    # Don't create a server if this core is not listed by the user.
                    if core_number not in core_list:
                        continue
                    gdb = GDBServer(session, core=core_number)
                    # Only subscribe to the server for the first core, so echo messages aren't printed
                    # multiple times.
                    if not gdbs:
                        session.subscribe(self._gdbserver_listening_cb, GDBServer.GDBSERVER_START_LISTENING_EVENT, gdb)
                    session.gdbservers[core_number] = gdb
                    gdbs.append(gdb)
                    gdb.start()

                while any(g.is_alive() for g in gdbs):
                    sleep(0.1)
                if probe_server:
                    probe_server.stop()
        except (KeyboardInterrupt, Exception):
            for server in gdbs:
                server.stop()
            if probe_server:
                probe_server.stop()
            raise

        return 0

