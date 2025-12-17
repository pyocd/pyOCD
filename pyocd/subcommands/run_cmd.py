# pyOCD debugger
# Copyright (c) 2025 Arm Limited
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
import threading
from time import sleep, time

from pyocd.core import exceptions

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..core.session import Session
from ..utility.cmdline import convert_session_options
from ..probe.shared_probe_proxy import SharedDebugProbeProxy
from ..coresight.generic_mem_ap import GenericMemAPTarget

from ..core.target import Target
from ..debug import semihost
from ..utility.timeout import Timeout
from ..trace.swv import SWVReader

from ..utility.stdio import StdioHandler

LOG = logging.getLogger(__name__)

class RunSubcommand(SubcommandBase):
    """@brief `pyocd run` subcommand."""

    NAMES = ['run']
    HELP = "Load and run the target."
    DEFAULT_LOG_LEVEL = logging.WARNING

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""
        run_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        run_options = run_parser.add_argument_group("run options")
        run_options.add_argument("--eot", dest="eot", action="store_true", default=False,
            help="Terminate execution when EOT character (0x04) is detected on stdout (default disabled).")
        run_options.add_argument("--timelimit", metavar="SECONDS", dest="timelimit", type=float, default=None,
            help="Maximum execution time in seconds before terminating (default no time limit).")

        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, run_parser]

    def invoke(self) -> int:
        """@brief Handle 'run' subcommand."""

        self._increase_logging(["pyocd.subcommands.run_cmd", __name__])

        # Create shared shutdown event for all RunServer threads
        self.shared_shutdown = threading.Event()

        self._run_servers = []

        try:
            # Create session
            session = ConnectHelper.session_with_chosen_probe(
                project_dir=self._args.project_dir,
                config_file=self._args.config,
                user_script=self._args.script,
                no_config=self._args.no_config,
                pack=self._args.pack,
                cbuild_run=self._args.cbuild_run,
                unique_id=self._args.unique_id,
                target_override=self._args.target_override,
                frequency=self._args.frequency,
                blocking=(not self._args.no_wait),
                connect_mode=self._args.connect_mode,
                options=convert_session_options(self._args.options),
                option_defaults=self._modified_option_defaults(),
            )
            if session is None:
                LOG.error("No probe selected")
                return 1

        except Exception as e:
            LOG.error("Exception occurred while creating session: %s", e)
            return 1

        timelimit_triggered = False
        with session:
            #
            # ToDo: load support
            #
            # To simulate state after load, stop all cores before starting run servers
            for _, core in session.board.target.cores.items():
                core.halt()

            try:
                # Start up the run servers.
                for core_number, core in session.board.target.cores.items():
                    # Don't create a server for CPU-less memory Access Port.
                    if isinstance(session.board.target.cores[core_number], GenericMemAPTarget):
                        continue

                    run_server = RunServer(session, core=core_number, enable_eot=self._args.eot, shutdown_event=self.shared_shutdown)
                    self._run_servers.append(run_server)

                # Reset the target and start RunServers
                session.target.reset()
                for run_server in self._run_servers:
                    run_server.start()

                # Wait for all servers to complete or timelimit to expire
                start_time = time()
                timelimit = self._args.timelimit
                while any(server.is_alive() for server in self._run_servers):
                    # Check if timelimit has been exceeded
                    if timelimit is not None:
                        elapsed = time() - start_time
                        if elapsed >= timelimit:
                            LOG.info("Time limit of %.1f seconds reached; shutting down Run servers", timelimit)
                            timelimit_triggered = True
                            self.ShutDownRunServers()
                            break
                    sleep(0.1)

            except KeyboardInterrupt:
                LOG.info("KeyboardInterrupt received; shutting down Run servers")
                self.ShutDownRunServers()
                return 0
            except Exception:
                LOG.exception("Unhandled exception in 'run' subcommand")
                self.ShutDownRunServers()
                return 1

            if timelimit_triggered:
                return 0
            if any(getattr(server, "eot_flag", False) for server in self._run_servers):
                return 0
            if any(getattr(server, "error_flag", False) for server in self._run_servers):
                return 1

        LOG.warning("Run servers exited without EOT, reached timelimit or error; this is unexpected")
        return 1

    def ShutDownRunServers(self):
        self.shared_shutdown.set()
        # Wait for servers to finish
        for server in self._run_servers:
            server.join(timeout=5.0)
            if server.is_alive():
                LOG.warning("Run server for core %d did not terminate cleanly", server.core)

class RunServer(threading.Thread):

    def __init__(self, session: Session, core=None, enable_eot: bool=False, shutdown_event: threading.Event=None):
        super().__init__(daemon=True)
        self.session = session
        self.error_flag = False
        self.eot_flag = False
        self.board = session.board
        if core is None:
            self.core = 0
            self.target = self.board.target
        else:
            self.core = core
            self.target = self.board.target.cores[core]
        self.target_context = self.target.get_target_context()

        self.shutdown_event = shutdown_event or threading.Event()
        self.enable_eot = enable_eot

        self.name = "run-server-%d" % self.core

        # Semihosting always enabled
        self.enable_semihosting = True

        # Lock to synchronize SWO with other activity
        self.lock = threading.RLock()

        # Use internal IO handler.
        semihost_io_handler = semihost.InternalSemihostIOHandler()

        self._stdio_handler = StdioHandler(session=session, core=self.core, eot_enabled=self.enable_eot)
        semihost_console = semihost.ConsoleIOHandler(self._stdio_handler)
        self.semihost = semihost.SemihostAgent(self.target_context, io_handler=semihost_io_handler, console=semihost_console)


        # # Start with RTT disabled
        # self.rtt_server: Optional[RTTServer] = None

        #
        # If SWV is enabled, create a SWVReader thread. Note that we only do
        # this if the core is 0: SWV is not a per-core construct, and can't
        # be meaningfully read by multiple threads concurrently.
        #
        self._swv_reader = None
        if self._stdio_handler and session.options.get("enable_swv") and self.core == 0:
            if "swv_system_clock" not in session.options:
                LOG.warning("SWV not enabled; swv_system_clock option missing")
            else:
                sys_clock = int(session.options.get("swv_system_clock"))
                swo_clock = int(session.options.get("swv_clock"))
                self._swv_reader = SWVReader(session, self.core, self.lock)
                self._swv_reader.init(sys_clock, swo_clock, self._stdio_handler)

    def run(self):
        stdio_info = self._stdio_handler.info
        node_name = self.session.board.target.cores[self.core].node_name
        LOG.info("Run server started for %s (core %d); STDIO mode: %s", node_name, self.core, stdio_info)

        # Timeout used only if the target starts returning faults. The is_running property of this timeout
        # also serves as a flag that a fault occurred and we're attempting to retry.
        fault_retry_timeout = Timeout(self.session.options.get('debug.status_fault_retry_timeout'))

        while fault_retry_timeout.check():
            if self.shutdown_event.is_set():
                # Exit the thread
                LOG.debug("Exit Run server for core %d", self.core)
                break

            # Check for EOT (0x04)
            if self._stdio_handler and self.enable_eot:
                try:
                    if self._stdio_handler.eot_seen:
                        # EOT received, terminate execution
                        LOG.info("EOT (0x04) character received for core %d; shutting down Run servers", self.core)
                        self.eot_flag = True
                        self.shutdown_event.set()
                        continue
                except Exception as e:
                    LOG.debug("Error while waiting for EOT (0x04): %s", e)

            self.lock.acquire()

            try:
                state = self.target.get_state()

                # if self.rtt_server:
                #     self.rtt_server.poll()

                # If we were able to successfully read the target state after previously receiving a fault,
                # then clear the timeout.
                if fault_retry_timeout.is_running:
                    LOG.debug("Target control re-established")
                    fault_retry_timeout.clear()

                if state == Target.State.HALTED:
                    # Handle semihosting
                    if self.enable_semihosting:
                        was_semihost = self.semihost.check_and_handle_semihost_request()
                        if was_semihost:
                            self.target.resume()
                            continue

                    pc = self.target_context.read_core_register('pc')
                    LOG.error("Target core %d unexpectedly halted at pc=0x%08x; shutting down Run servers", self.core, pc)
                    self.error_flag = True
                    self.shutdown_event.set()
                    break

            except exceptions.TransferError as e:
                # If we get any sort of transfer error or fault while checking target status, then start
                # a timeout running. Upon a later successful status check, the timeout is cleared. In the event
                # that the timeout expires, this loop is exited and an error raised.
                if not fault_retry_timeout.is_running:
                    LOG.warning("Transfer error while checking target status; retrying: %s", e,
                            exc_info=self.session.log_tracebacks)
                fault_retry_timeout.start()
            except exceptions.Error as e:
                LOG.error("Error while target core %d running: %s; shutting down Run servers", self.core, e, exc_info=self.session.log_tracebacks)
                self.error_flag = True
                self.shutdown_event.set()
                break
            finally:
                self.lock.release()
                sleep(0.01)

        # Check if we exited the above loop due to a timeout after a fault.
        if fault_retry_timeout.did_time_out:
            LOG.error("Timeout re-establishing target core %d control; shutting down Run servers", self.core)
            self.error_flag = True
            self.shutdown_event.set()

        # Cleanup resources for this RunServer.
        try:
            if self._swv_reader is not None:
                self._swv_reader.stop()
        except Exception as e:
            LOG.debug("Error stopping SWV reader for core %d: %s", self.core, e)

        try:
            if self._stdio_handler is not None:
                self._stdio_handler.shutdown()
        except Exception as e:
            LOG.debug("Error closing stdio handler for core %d: %s", self.core, e)
