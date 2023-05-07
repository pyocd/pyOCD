# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

import colorama
import io
import logging
import os
import traceback
from typing import (IO, Optional, Sequence, TYPE_CHECKING, Union)

from ..core.helpers import ConnectHelper
from ..core import (exceptions, session)
from ..probe.shared_probe_proxy import SharedDebugProbeProxy
from ..utility.cmdline import convert_session_options
from ..commands.repl import (PyocdRepl, ToolExitException)
from ..commands.execution_context import CommandExecutionContext

if TYPE_CHECKING:
    import argparse

LOG = logging.getLogger(__name__)

## Default SWD clock in Hz.
DEFAULT_CLOCK_FREQ_HZ = 1000000

class PyOCDCommander:
    """@brief Manages the commander interface.

    Responsible for connecting the execution context, REPL, and commands, and handles connection.

    Exit codes:
    - 0 = no errors
    - 1 = command error
    - 2 = transfer error
    - 3 = failed to create session (probe might not exist)
    - 4 = failed to open probe

    @todo Replace use of args from argparse with something cleaner.
    """

    CommandsListType = Sequence[Union[str, IO[str]]]

    ## Commands that can run without requiring a connection.
    _CONNECTIONLESS_COMMANDS = ('list', 'help', 'exit')

    def __init__(
                self,
                args: "argparse.Namespace",
                cmds: Optional[CommandsListType] = None
            ) -> None:
        """@brief Constructor."""
        # Read command-line arguments.
        self.args = args
        self.cmds: PyOCDCommander.CommandsListType = cmds or []

        self.context = CommandExecutionContext(no_init=self.args.no_init)
        self.context.command_set.add_command_group('commander')
        self.session: Optional[session.Session] = None
        self.exit_code: int = 0

    def run(self) -> int:
        """@brief Main entry point."""
        try:
            # If no commands, enter interactive mode. If there are commands, use the --interactive arg.
            enter_interactive = (not self.cmds) or self.args.interactive

            # Connect unless we are only running commands that don't require a connection.
            do_connect = enter_interactive or self._commands_require_connect()
            if do_connect and not self.connect():
                return self.exit_code

            # Run the list of commands we were given.
            if self.cmds:
                self.run_commands()

            # Enter the interactive REPL.
            if enter_interactive:
                assert self.session
                assert self.session.board
                assert self.context.target

                # Print connected message, unless not initing.
                if not self.args.no_init:
                    try:
                        # If the target is locked, we can't read the CPU state.
                        if self.session.target.is_locked():
                            status = "locked"
                        else:
                            try:
                                status = self.session.target.get_state().name.capitalize()
                            except (AttributeError, KeyError):
                                status = "<no core>"
                    except exceptions.TransferFaultError:
                        status = "<error>"
                else:
                    # Say what we're connected to, but without status.
                    status = "no init mode"

                # Say what we're connected to.
                print(colorama.Fore.GREEN + f"Connected to {self.session.target.part_number} " +
                        colorama.Fore.CYAN + f"[{status}]" +
                        colorama.Style.RESET_ALL + f": {self.session.board.unique_id}")

                # Run the REPL interface.
                console = PyocdRepl(self.context)
                console.run()

        except ToolExitException:
            self.exit_code = 0
        except exceptions.TransferError:
            print("Error: memory transfer failed")
            # Use get_current() in case our session hasn't been created yet.
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
            self.exit_code = 2
        except exceptions.CommandError as e:
            print("Error:", e)
            self.exit_code = 1
        finally:
            # Ensure the session is closed.
            if self.session is not None:
                self.session.close()

        return self.exit_code

    def _commands_require_connect(self) -> bool:
        """@brief Determine whether a connection is needed to run commands."""
        for args in self.cmds:
            # Always assume connection required for command files.
            if isinstance(args, io.IOBase):
                return True

            # Check for connectionless commands.
            else:
                assert isinstance(args, str)

                if not ((len(args) == 1) and (args[0].lower() in self._CONNECTIONLESS_COMMANDS)):
                    return True

        # No command was found that needs a connection.
        return False

    def run_commands(self) -> None:
        """@brief Run commands specified on the command line."""
        for args in self.cmds:
            # Open file containing commands.
            if isinstance(args, io.IOBase) and not isinstance(args, str):
                self.context.process_command_file(args)

            # List of command and argument strings.
            else:
                assert isinstance(args, str)

                # Skip empty args lists.
                if len(args) == 0:
                    continue

                # Run the command line.
                self.context.process_command_line(args)

    def connect(self) -> bool:
        """@brief Connect to the probe."""
        if (self.args.frequency is not None) and (self.args.frequency != DEFAULT_CLOCK_FREQ_HZ):
            self.context.writei("Setting SWD clock to %d kHz", self.args.frequency // 1000)

        options = convert_session_options(self.args.options)

        # Set connect mode. The --connect option takes precedence when set. Then, if --halt is set
        # then the connect mode is halt. If connect_mode is set through -O then use that.
        # Otherwise default to attach.
        if hasattr(self.args, 'connect_mode') and self.args.connect_mode is not None:
            connect_mode = self.args.connect_mode
        elif self.args.halt:
            connect_mode = 'halt'
        elif 'connect_mode' in options:
            connect_mode = None
        else:
            connect_mode = 'attach'

        # Connect to board.
        probe = ConnectHelper.choose_probe(
                        blocking=(not self.args.no_wait),
                        unique_id=self.args.unique_id,
                        )
        if probe is None:
            self.exit_code = 3
            return False

        # Create a proxy so the probe can be shared between the session and a possible probe server.
        probe_proxy = SharedDebugProbeProxy(probe)

        # Create the session.
        self.session = session.Session(probe_proxy,
                        project_dir=self.args.project_dir,
                        config_file=self.args.config,
                        user_script=self.args.script,
                        no_config=self.args.no_config,
                        pack=self.args.pack,
                        target_override=self.args.target_override,
                        connect_mode=connect_mode,
                        frequency=self.args.frequency,
                        options=options,
                        option_defaults={
                            'auto_unlock': False,
                            'resume_on_disconnect': False,
                            'debug.traceback': logging.getLogger('pyocd').isEnabledFor(logging.DEBUG),
                            }
                        )

        if not self._post_connect():
            self.exit_code = 4
            return False

        result = self.context.attach_session(self.session)
        if not result:
            self.exit_code = 1
        return result

    def _post_connect(self) -> bool:
        """@brief Finish the connect process.

        The session is opened. The `no_init` parameter passed to the constructor determines whether the
        board and target are initialized.

        If an ELF file was provided on the command line, it is set on the target.

        @param self This object.
        @param session A @ref pyocd.core.session.Session "Session" instance.
        @retval True Session attached and context state inited successfully.
        @retval False An error occurred when opening the session or initing the context state.
        """
        assert self.session is not None
        assert not self.session.is_open

        # Open the session.
        try:
            self.session.open(init_board=not self.args.no_init)
        except exceptions.TransferFaultError as e:
            if not self.session.target.is_locked():
                LOG.error("Transfer fault while initing board: %s", e, exc_info=self.session.log_tracebacks)
                return False
        except exceptions.Error as e:
            LOG.error("Error while initing target: %s", e, exc_info=self.session.log_tracebacks)
            return False

        # Set elf file if provided.
        if self.args.elf:
            self.session.target.elf = os.path.expanduser(self.args.elf)

        # Handle a device with flash security enabled.
        if not self.args.no_init and self.session.target.is_locked():
            self.context.write("Warning: Target is locked, limited operations available. Use 'unlock' "
                                "command to mass erase and unlock, then execute 'reinit'.")

        return True

