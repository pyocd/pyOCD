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
