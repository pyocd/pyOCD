# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from ..core import exceptions
from ..commands.base import CommandBase
from ..utility.rtt_server import RTTServer

LOG = logging.getLogger(__name__)

class ThreadsCommand(CommandBase):
    INFO = {
            'names': ['threads'],
            'group': 'gdbserver',
            'category': 'threads',
            'nargs': 1,
            'usage': "{flush,enable,disable,status}",
            'help': "Control thread awareness.",
            }

    def parse(self, args):
        self.action = args[0]
        if self.action not in ('flush', 'enable', 'disable', 'status'):
            raise exceptions.CommandError("invalid action")

    def execute(self):
        # Get the gdbserver for the selected core.
        core_number = self.context.selected_core.core_number
        try:
            gdbserver = self.context.session.gdbservers[core_number]
        except KeyError:
            raise exceptions.CommandError("no gdbserver for core #%i" % core_number)

        if gdbserver.thread_provider is None:
            self.context.write("Threads are unavailable")
            return

        if self.action == 'flush':
            gdbserver.thread_provider.invalidate()
            self.context.write("Threads flushed")
        elif self.action == 'enable':
            gdbserver.thread_provider.read_from_target = True
            self.context.write("Threads enabled")
        elif self.action == 'disable':
            gdbserver.thread_provider.read_from_target = False
            self.context.write("Threads disabled")
        elif self.action == 'status':
            self.context.write("Threads are " +
                    ("enabled" if gdbserver.thread_provider.read_from_target else "disabled"))

class ArmSemihostingCommand(CommandBase):
    INFO = {
            'names': ['arm'],
            'group': 'gdbserver',
            'category': 'semihosting',
            'nargs': 2,
            'usage': "semihosting {enable,disable}",
            'help': "Enable or disable semihosting.",
            'extra_help': "Provided for compatibility with OpenOCD. The same functionality can be achieved "
                            "by setting the 'enable_semihosting' session option.",
            }

    def parse(self, args):
        if args[0] != 'semihosting':
            raise exceptions.CommandError("invalid action")
        if args[1] not in ('enable', 'disable'):
            raise exceptions.CommandError("invalid action")
        self.action = args[1]

    def execute(self):
        enable = (self.action == 'enable')
        self.context.session.options['enable_semihosting'] = enable

class GdbserverMonitorInitCommand(CommandBase):
    """@brief 'init' command for OpenOCD compatibility.

    Many default gdbserver configurations send an 'init' monitor command.
    """
    INFO = {
            'names': ['init'],
            'group': 'gdbserver',
            'category': 'openocd_compatibility',
            'nargs': 2,
            'usage': "",
            'help': "Ignored; for OpenOCD compatibility.",
            }

    def execute(self):
        pass

class GdbserverMonitorExitCommand(CommandBase):
    """@brief 'exit' command to cleanly shut down the gdbserver from an IDE.

    This command is primarily intended to be used by an IDE to tell the pyocd process to exit when
    the debug session is terminated.
    """
    INFO = {
            'names': ['exit'],
            'group': 'gdbserver',
            'category': 'gdbserver',
            'nargs': 0,
            'usage': "",
            'help': "Terminate running gdbservers in this session.",
            'extra_help':
                "For the pyocd gdbserver subcommand, terminating gdbservers will cause the process to exit. The "
                "effect when the gdbserver(s) are running in a different environment depends on that program. "
                "Note that gdb will still believe the connection to be valid after this command completes, so "
                "executing the 'disconnect' command is a necessity."
            }

    def execute(self):
        for server in self.context.session.gdbservers.values():
            server.stop(wait=False)

class RTTCommand(CommandBase):
    INFO = {
            'names': ['rtt'],
            'group': 'gdbserver',
            'category': 'rtt',
            'nargs': "*",
            'usage': "rtt {setup,start,stop,channels,server}",
            'help': "Control SEGGER RTT compatible interface.",
            }

    def parse(self, args):
        if len(args) < 1:
            raise exceptions.CommandError("too few arguments")

        if args[0] == 'setup':
            if len(args) < 4:
                raise exceptions.CommandError("too few arguments")

            try:
                self.addr = int(args[1], 0)
                self.size = int(args[2], 0)
                self.id = " ".join(args[3:]).encode("utf-8")
            except ValueError as e:
                raise exceptions.CommandError("invalid action") from e
        elif args[0] == 'start' or args[0] == 'stop' or args[0] == 'channels':
            if len(args) > 1:
                raise exceptions.CommandError("too many arguments")
        elif args[0] == 'server':
            if len(args) < 2:
                    raise exceptions.CommandError("too few arguments")

            if args[1] == 'start':
                if len(args) < 4:
                    raise exceptions.CommandError("too few arguments")
                elif len(args) > 4:
                    raise exceptions.CommandError("too many arguments")

                try:
                    self.port = int(args[2], 0)
                    self.channel = int(args[3], 0)
                except ValueError as e:
                    raise exceptions.CommandError("invalid action*") from e
            elif args[1] == 'stop':
                if len(args) < 3:
                    raise exceptions.CommandError("too few arguments")
                elif len(args) > 3:
                    raise exceptions.CommandError("too many arguments")

                try:
                    self.port = int(args[2], 0)
                except ValueError as e:
                    raise exceptions.CommandError("invalid action") from e
            else:
                raise exceptions.CommandError("invalid action")

            self.server_action = args[1]
        else:
            raise exceptions.CommandError("invalid action")

        self.action = args[0]

    def execute(self):
        # Get the gdbserver for the selected core.
        core_number = self.context.selected_core.core_number
        try:
            gdbserver = self.context.session.gdbservers[core_number]
        except KeyError:
            raise exceptions.CommandError("no gdbserver for core #%i" % core_number)

        if self.action == "setup":
            if gdbserver.rtt_server is not None:
                if gdbserver.rtt_server.running:
                    raise exceptions.CommandError("rtt is already running")
                else:
                    gdbserver.rtt_server = None

            try:
                gdbserver.rtt_server = RTTServer(gdbserver.target, address = self.addr,
                                                 size = self.size,
                                                 control_block_id = self.id)
            except exceptions.RTTError as e:
                raise exceptions.CommandError(str(e)) from e
        elif self.action == "start":
            if gdbserver.rtt_server is None:
                raise exceptions.CommandError("rtt is not configured")

            try:
                gdbserver.rtt_server.start()
            except exceptions.RTTError as e:
                raise exceptions.CommandError(str(e)) from e

            self.context.write(f"Found RTT control block.")
        elif self.action == "stop":
            if gdbserver.rtt_server is not None:
                gdbserver.rtt_server.stop()
        elif self.action == "channels":
            control_block = gdbserver.rtt_server.control_block
            self.context.write(f"Channels: up={len(control_block.up_channels)}, "
                               f"down={len(control_block.down_channels)}")
            self.context.write("Up-channels:")
            for i, chan in enumerate(control_block.up_channels):
                name = chan.name if chan.name is not None else ""
                self.context.write(f"{i}: {name} {chan.size}")
            self.context.write("Down-channels:")
            for i, chan in enumerate(control_block.up_channels):
                name = chan.name if chan.name is not None else ""
                self.context.write(f"{i}: {name} {chan.size}")
        elif self.action == "server":
            if gdbserver.rtt_server is None:
                raise exceptions.CommandError("rtt is not configured")
            elif not gdbserver.rtt_server.running:
                raise exceptions.CommandError("rtt is not yet started")

            if self.server_action == "start":
                try:
                    gdbserver.rtt_server.add_server(self.port, self.channel)
                except exceptions.RTTError as e:
                    raise exceptions.CommandError(str(e)) from e
            elif self.server_action == "stop":
                try:
                    gdbserver.rtt_server.stop_server(self.port)
                except exceptions.RTTError as e:
                    raise exceptions.CommandError(str(e)) from e
