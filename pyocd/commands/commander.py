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

import logging
import os
import traceback

from ..core.helpers import ConnectHelper
from ..core import (exceptions, session)
from ..probe.shared_probe_proxy import SharedDebugProbeProxy
from ..utility.cmdline import convert_session_options
from ..commands.repl import (PyocdRepl, ToolExitException)
from ..commands.execution_context import CommandExecutionContext

LOG = logging.getLogger(__name__)

## Default SWD clock in Hz.
DEFAULT_CLOCK_FREQ_HZ = 1000000

class PyOCDCommander(object):
    """! @brief Manages the commander interface.
    
    Responsible for connecting the execution context, REPL, and commands, and handles connection.
    
    Exit codes:
    - 0 = no errors
    - 1 = command error
    - 2 = transfer error
    - 3 = failed to create session (probe might not exist)
    - 4 = failed to open probe
    
    @todo Replace use of args from argparse with something cleaner.
    """
    
    def __init__(self, args, cmds=None):
        """! @brief Constructor."""
        # Read command-line arguments.
        self.args = args
        self.cmds = cmds
        
        self.context = CommandExecutionContext(no_init=self.args.no_init)
        self.context.command_set.add_command_group('commander')
        self.session = None
        self.exit_code = 0
        
    def run(self):
        """! @brief Main entry point."""
        try:
            # If no commands, enter interactive mode.
            if self.cmds is None:
                if not self.connect():
                    return self.exit_code
                
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

                        # Say what we're connected to.
                        print("Connected to %s [%s]: %s" % (self.context.target.part_number,
                            status, self.session.board.unique_id))
                    except exceptions.TransferFaultError:
                        pass
                else:
                    # Say what we're connected to, but without status.
                    print("Connected to %s [no init mode]: %s" % (self.context.target.part_number,
                        self.session.board.unique_id))

                # Run the REPL interface.
                console = PyocdRepl(self.context)
                console.run()
                
            # Otherwise, run the list of commands we were given and exit. We only connect when
            # there is a command that requires a connection (most do).
            else:
                self.run_commands()

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
    
    def run_commands(self):
        """! @brief Run commands specified on the command line."""
        did_connect = False

        for args in self.cmds:
            # Extract the command name.
            cmd = args[0].lower()
            
            # Handle certain commands without connecting.
            needs_connect = (cmd not in ('list', 'help', 'exit'))

            # For others, connect first.
            if needs_connect and not did_connect:
                if not self.connect():
                    return self.exit_code
                did_connect = True
        
            # Merge commands args back to one string.
            # FIXME this is overly complicated
            cmdline = " ".join('"{}"'.format(a) for a in args)
        
            # Invoke action handler.
            result = self.context.process_command_line(cmdline)
            if result is not None:
                self.exit_code = result
                break

    def connect(self):
        """! @brief Connect to the probe."""
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
                        option_defaults=dict(
                            auto_unlock=False,
                            resume_on_disconnect=False,
                            )
                        )
        
        if not self._post_connect():
            self.exit_code = 4
            return False
        
        result = self.context.attach_session(self.session)
        if not result:
            self.exit_code = 1
        return result

    def _post_connect(self):
        """! @brief Finish the connect process.
        
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
                self.context.writei("Transfer fault while initing board: %s", e)
                if self.session.log_tracebacks:
                    self.context.write(traceback.format_exc())
                return False
        except exceptions.Error as e:
            self.context.writei("Exception while initing board: %s", e)
            if self.session.log_tracebacks:
                self.context.write(traceback.format_exc())
            return False

        # Set elf file if provided.
        if self.args.elf:
            self.session.target.elf = os.path.expanduser(self.args.elf)

        # Handle a device with flash security enabled.
        if not self.args.no_init and self.session.target.is_locked():
            self.context.write("Warning: Target is locked, limited operations available. Use 'unlock' "
                                "command to mass erase and unlock, then execute 'reinit'.")
        
        return True

