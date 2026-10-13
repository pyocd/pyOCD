# pyOCD debugger
# Copyright (c) 2025-2026 Arm Limited
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
from typing import List, Optional
import logging
import sys
import threading
from time import sleep, monotonic

from .base import SubcommandBase
from ..core import exceptions
from ..core.helpers import ConnectHelper
from ..core.session import Session
from ..core.target import Target
from ..coresight.generic_mem_ap import GenericMemAPTarget
from ..utility.cmdline import convert_session_options
from ..utility.timeout import Timeout
from ..utility.rtt_server import RTTServer
from ..utility.rtt_manager import RTTConfig, RTTManager
from ..utility.systemview import SystemViewConfig, SystemViewSVDat
from ..utility.stdio import StdioHandler
from ..debug import semihost
from ..trace.swv import SWVReader

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

        swv_reader = None
        systemview = None

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

        with session:
            # Increase log level to INFO if it is still at the default WARNING level
            root_logger = logging.getLogger()
            if root_logger.level == logging.WARNING:
                root_logger.setLevel(logging.INFO)

            # TODO: load support

            try:
                # Process RTT configuration
                rtt_config_list = {
                    core_number: RTTConfig(_session=session, _target=core_target, _core=core_number)
                    for core_number, core_target in session.board.target.cores.items()
                    if not isinstance(core_target, GenericMemAPTarget)
                }
            except Exception as e:
                LOG.warning("Exception occurred while processing RTT configuration: %s", e)

            try:
                # Process SystemView configuration
                systemview_config = SystemViewConfig(_session=session)
                if any(cfg.has_rtt_config and cfg.num_systemview_channels > 0 for cfg in rtt_config_list.values()):
                    systemview = SystemViewSVDat(session=session, rtt_configs=rtt_config_list,
                                                 systemview_config=systemview_config)
            except Exception as e:
                LOG.warning("Exception occurred while processing SystemView configuration: %s", e)

            # Check whether we are using the attach mode
            attached = session.options.get("connect_mode") == 'attach'

            try:
                # Halt all cores if required
                if attached:
                    for core in session.board.target.cores.values():
                        core.halt()

                # Initialize SWV reader
                if session.options.get("enable_swv"):
                    if "swv_system_clock" not in session.options:
                        LOG.warning("SWV not enabled; swv_system_clock option missing")
                    else:
                        sys_clock = int(session.options.get("swv_system_clock"))
                        swo_clock = int(session.options.get("swv_clock"))
                        swv_reader = SWVReader(session)
                        swv_reader.init(sys_clock, swo_clock, sys.stdout)

                # Reset the cores before starting the Run servers.
                for core in session.board.target.cores.values():
                    core.set_reset_catch()
                session.board.target.reset()
                for core in session.board.target.cores.values():
                    core.clear_reset_catch()

                # Start trace capture before running the target
                if session.board.target.trace_enabled:
                    session.board.target.trace_capture()

                # Resume target
                for core in session.board.target.cores.values():
                    core.resume()

                # Start the Run servers
                for core_number, core in session.board.target.cores.items():
                    # Don't create a server for CPU-less memory Access Port
                    if isinstance(session.board.target.cores[core_number], GenericMemAPTarget):
                        continue

                    run_server = RunServer(session=session,
                                           core=core_number,
                                           rtt_config=rtt_config_list[core_number],
                                           systemview_config=systemview_config,
                                           enable_eot=self._args.eot,
                                           shutdown_event=self.shared_shutdown)
                    self._run_servers.append(run_server)
                    run_server.start()

                # Wait for all servers to complete or timelimit to expire
                start_time = monotonic()
                timelimit = self._args.timelimit

                while any(server.is_alive() for server in self._run_servers):
                    # Check if timelimit has been exceeded
                    if timelimit is not None:
                        elapsed = monotonic() - start_time
                        if elapsed >= timelimit:
                            LOG.info("Time limit of %.1f seconds reached; shutting down all Run servers", timelimit)
                            self.shutdown()
                            break
                    sleep(0.1)

            except KeyboardInterrupt:
                LOG.info("KeyboardInterrupt received; shutting down Run servers")
                self.shutdown()
                return 0
            except Exception:
                LOG.exception("Unhandled exception in 'run' subcommand")
                self.shutdown()
                raise
            finally:
                if swv_reader:
                    swv_reader.stop()
                if session.board.target.trace_enabled:
                    session.board.target.trace_flush()
                if systemview:
                    systemview.assemble_file()

        return 0

    def shutdown(self):
        self.shared_shutdown.set()
        # Wait for servers to finish
        for server in self._run_servers:
            if server.is_alive():
                server.join(timeout=5.0)
            if server.is_alive():
                LOG.warning("Run server for core %d did not terminate cleanly", server.core)

class RunServer(threading.Thread):

    ## Interval for retrying automatic RTT discovery, in seconds.
    _RTT_DISCOVERY_INTERVAL = 0.010
    ## RTT channel polling interval used by the run thread, in seconds.
    _RTT_POLL_INTERVAL = 0.001
    ## Target state polling interval used by the run thread, in seconds.
    _TARGET_STATE_INTERVAL = 0.010

    def __init__(self, session: Session, core: Optional[int] = None, rtt_config: Optional[RTTConfig] = None,
                 systemview_config: Optional[SystemViewConfig] = None, enable_eot: bool = False,
                 shutdown_event: Optional[threading.Event] = None):
        super().__init__(daemon=True)
        self._session = session
        self._board = session.board
        if core is None:
            self.core = 0
            self._target = self._board.target
        else:
            self.core = core
            self._target = self._board.target.cores[core]
        self._target_context = self._target.get_target_context()

        self._shutdown_event = shutdown_event or threading.Event()
        self._enable_eot = enable_eot
        self._is_halted = False

        self.name = "run-server-%d" % self.core

        # Semihosting enabled by default,
        # but can be explicitly disabled via the 'enable_semihosting' option
        if session.options.is_set("enable_semihosting"):
            self._enable_semihosting = session.options.get("enable_semihosting")
        else:
            self._enable_semihosting = True

        # Use internal IO handler.
        semihost_io_handler = semihost.InternalSemihostIOHandler()

        self._stdio_handler = StdioHandler(session=session, core=self.core, eot_enabled=self._enable_eot)
        semihost_console = semihost.ConsoleIOHandler(self._stdio_handler)
        self._semihost = semihost.SemihostAgent(self._target_context, io_handler=semihost_io_handler, console=semihost_console)

        # Start RTT server and retain the manager for discovery retries.
        self._rtt_server: Optional[RTTServer] = None
        self._rtt_manager: Optional[RTTManager] = None
        if rtt_config is None:
            try:
                rtt_config = RTTConfig(_session=session, _target=self._target, _core=self.core)
            except Exception as error:
                LOG.error("RTT configuration failed for core %d: %s", self.core, error, exc_info=self._session.log_tracebacks)

        if rtt_config is not None and rtt_config.channels is not None:
            try:
                self._rtt_manager = RTTManager(session=session, core=self.core, rtt_config=rtt_config,
                                                systemview_config=systemview_config or SystemViewConfig(_session=session))
            except Exception as error:
                LOG.error("RTT configuration failed for core %d: %s", self.core, error, exc_info=self._session.log_tracebacks)

    def _start_rtt(self) -> None:
        """@brief Discover and configure RTT."""
        try:
            rtt_server = self._rtt_manager.start_server()
            if rtt_server is not None:
                if self._shutdown_event.is_set():
                    rtt_server.stop()
                    return
                self._rtt_server = rtt_server
                self._rtt_manager.configure_channels(stdio_handler=self._stdio_handler)
        except Exception as error:
            LOG.debug("RTT discovery failed for core %d: %s", self.core, error, exc_info=self._session.log_tracebacks)

    def _read_and_process_target_state(self) -> None:
        """@brief Process the observed target state, handle semihosting, and report halt and resume transitions."""
        state = self._target.get_state()
        if state == Target.State.HALTED:
            # Handle semihosting
            if self._enable_semihosting and self._semihost.check_and_handle_semihost_request():
                self._target.resume()
            elif not self._is_halted:
                self._is_halted = True
                pc = self._target_context.read_core_register('pc')
                LOG.warning("Target core %d unexpectedly halted at pc=0x%08x", self.core, pc)
        else:
            if self._is_halted:
                self._is_halted = False
                LOG.info("Target core %d resumed from halt", self.core)

    def _check_eot(self) -> bool:
        """@brief Stop all Run servers if EOT has been detected."""
        if self._stdio_handler and self._enable_eot:
            try:
                if self._stdio_handler.eot_seen:
                    LOG.info("EOT (0x04) character received for core %d; shutting down all Run servers", self.core)
                    self._shutdown_event.set()
                    return True
            except Exception as e:
                LOG.debug("Error while waiting for EOT (0x04): %s", e)
        return False

    def run(self):
        stdio_info = self._stdio_handler.info
        rtt_status = "enabled" if self._rtt_manager is not None else "disabled"
        LOG.info("Run server started for core %d; STDIO mode: %s; RTT: %s",
                self.core, stdio_info, rtt_status)

        eot_seen = False
        rtt_poll_error = False

        fault_retry_timeout = Timeout(self._session.options.get('live.status_fault_retry_timeout'))

        now = monotonic()
        if self._rtt_manager is not None and self._rtt_server is None:
            rtt_discovery_time = now
        else:
            rtt_discovery_time = float('inf')
        rtt_poll_time = float('inf')
        target_state_time = now

        while not self._shutdown_event.is_set():
            now = monotonic()

            # Discover RTT control block
            if now >= rtt_discovery_time:
                rtt_discovery_time = now + self._RTT_DISCOVERY_INTERVAL
                if self._rtt_manager is not None and self._rtt_server is None:
                    self._start_rtt()
                    if self._rtt_server is not None:
                        rtt_discovery_time = float('inf')
                        # Start polling RTT immediately after discovery.
                        rtt_poll_time = now

            # Poll RTT
            if now >= rtt_poll_time:
                rtt_poll_time = now + self._RTT_POLL_INTERVAL
                try:
                    self._rtt_server.poll()
                    if rtt_poll_error:
                        LOG.info("RTT poll recovered after error for core %d.", self.core)
                        rtt_poll_error = False
                except (exceptions.TransferError, exceptions.RTTError) as error:
                    if not rtt_poll_error:
                        LOG.warning("RTT poll failed for core %d: %s", self.core, error)
                        rtt_poll_error = True
                except Exception as error:
                    LOG.debug("RTT poll failed for core %d: %s", self.core, error, exc_info=self._session.log_tracebacks)
                # Check for EOT after polling RTT.
                if self._check_eot():
                    break

            # Check target and handle target state
            if now >= target_state_time:
                target_state_time = now + self._TARGET_STATE_INTERVAL
                if fault_retry_timeout.did_time_out:
                    # Transfer error persisted beyond the retry timeout.
                     # Shut down the Run server instance for this core.
                    LOG.error("Timeout expired after repeated transfer errors for core %d", self.core)
                    break
                try:
                    self._read_and_process_target_state()
                    if fault_retry_timeout.is_running:
                        # Target state read succeeded after a transfer error; clear the fault retry timeout.
                        LOG.info("Recovered after transfer error for core %d.", self.core)
                        fault_retry_timeout.clear()
                except exceptions.TransferError as error:
                    if not fault_retry_timeout.is_running:
                        # Start the timeout on the first fault; the next scheduled poll retries.
                        LOG.warning("Transfer error detected for core %d", self.core)
                        fault_retry_timeout.start()
                except Exception as error:
                    LOG.error("Unexpected error for core %d: %s",
                            self.core, error, exc_info=self._session.log_tracebacks)
                    break
                finally:
                    # Check for EOT.
                    eot_seen = self._check_eot()
                if eot_seen:
                    break

            wait_time = min(rtt_discovery_time, rtt_poll_time, target_state_time) - monotonic()
            if wait_time <= 0.0:
                wait_time = 0.001
            self._shutdown_event.wait(wait_time)

        LOG.debug("Exit Run server for core %d", self.core)

        # Cleanup resources for this RunServer.
        try:
            if self._rtt_server is not None:
                self._rtt_server.stop()
        except Exception as e:
            LOG.debug("Error closing RTT server for core %d: %s", self.core, e)

        try:
            if self._stdio_handler is not None:
                self._stdio_handler.shutdown()
        except Exception as e:
            LOG.debug("Error closing stdio handler for core %d: %s", self.core, e)
