#!/usr/bin/env python
# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

from __future__ import print_function
import argparse
import logging
import sys

from .. import __version__
from ..probe.pydapaccess import DAPAccess
from ..commands.commander import (
    PyOCDCommander,
    DEFAULT_CLOCK_FREQ_HZ,
    )

LOG = logging.getLogger(__name__)

class PyOCDTool(object):
    def get_args(self):
        debug_levels = list(LEVELS.keys())

        epi = "Available commands:\n" + ', '.join(ALL_COMMANDS)

        parser = argparse.ArgumentParser(description='Target inspection utility', epilog=epi)
        parser.add_argument('--version', action='version', version=__version__)
        parser.add_argument('-j', '--dir', metavar="PATH", dest="project_dir",
            help="Set the project directory. Defaults to the directory where pyocd was run.")
        parser.add_argument('--config', metavar="PATH", default=None, help="Use a YAML config file.")
        parser.add_argument("--no-config", action="store_true", default=None, help="Do not use a configuration file.")
        parser.add_argument('--script', metavar="PATH",
            help="Use the specified user script. Defaults to pyocd_user.py.")
        parser.add_argument("--pack", metavar="PATH", help="Path to a CMSIS Device Family Pack")
        parser.add_argument("-H", "--halt", action="store_true", default=None, help="Halt core upon connect.")
        parser.add_argument("-N", "--no-init", action="store_true", help="Do not init debug system.")
        parser.add_argument('-k', "--clock", metavar='KHZ', default=(DEFAULT_CLOCK_FREQ_HZ // 1000), type=int, help="Set SWD speed in kHz. (Default 1 MHz.)")
        parser.add_argument('-b', "--board", action='store', dest="unique_id", metavar='ID', help="Use the specified board. Only a unique part of the board ID needs to be provided.")
        parser.add_argument('-t', "--target", action='store', metavar='TARGET', help="Override target.")
        parser.add_argument('-e', "--elf", metavar="PATH", help="Optionally specify ELF file being debugged.")
        parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='warning', help="Set the level of system logging output. Supported choices are: " + ", ".join(debug_levels), metavar="LEVEL")
        parser.add_argument("cmd", nargs='?', default=None, help="Command")
        parser.add_argument("args", nargs='*', help="Arguments for the command.")
        parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
        parser.add_argument("-O", "--option", dest="options", metavar="OPTION", action="append", help="Set session option of form 'OPTION=VALUE'.")
        parser.add_argument("-W", "--no-wait", action="store_true", help="Do not wait for a probe to be connected if none are available.")
        parser.add_argument("--no-deprecation-warning", action="store_true", help="Do not warn about pyocd-tool being deprecated.")
        return parser.parse_args()

    def configure_logging(self):
        level = LEVELS.get(self.args.debug_level, logging.WARNING)
        logging.basicConfig(level=level)

    def run(self):
        # Read command-line arguments.
        self.args = self.get_args()
        
        if self.args.cmd is not None:
            self.cmd = [[self.args.cmd] + self.args.args]
        else:
            self.cmd = None

        # Set logging level
        self.configure_logging()
        DAPAccess.set_args(self.args.daparg)
        
        if not self.args.no_deprecation_warning:
            LOG.warning("pyocd-tool is deprecated; please use the new combined pyocd tool.")
        
        # Convert args to new names.
        self.args.target_override = self.args.target
        self.args.frequency = self.args.clock * 1000

        commander = PyOCDCommander(self.args, self.cmd)
        return commander.run()


def main():
    sys.exit(PyOCDTool().run())


if __name__ == '__main__':
    main()
