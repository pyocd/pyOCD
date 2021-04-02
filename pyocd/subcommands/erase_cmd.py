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

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..flash.eraser import FlashEraser
from ..utility.cmdline import convert_session_options

LOG = logging.getLogger(__name__)

class EraseSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['erase']
    HELP = "Erase entire device flash or specified sectors."
    EPILOG = ("If no position arguments are listed, then no action will be taken unless the --chip or "
            "--mass-erase options are provided. Otherwise, the positional arguments should be the addresses of flash "
            "sectors or address ranges. The end address of a range is exclusive, meaning that it will not be "
            "erased. Thus, you should specify the address of the sector after the last one "
            "to be erased. If a '+' is used instead of '-' in a range, this indicates that the "
            "second value is a length rather than end address. "
            "Examples: 0x1000 (erase single sector starting at 0x1000) "
            "0x800-0x2000 (erase sectors starting at 0x800 up to but not including 0x2000) "
            "0+8192 (erase 8 kB starting at address 0)")
    DEFAULT_LOG_LEVEL = logging.WARNING
    
    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        erase_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        erase_options = erase_parser.add_argument_group("erase options")
        erase_options.add_argument("-c", "--chip", dest="erase_mode", action="store_const", const=FlashEraser.Mode.CHIP,
            help="Perform a chip erase.")
        erase_options.add_argument("-s", "--sector", dest="erase_mode", action="store_const", const=FlashEraser.Mode.SECTOR,
            help="Erase the sectors listed as positional arguments.")
        erase_options.add_argument("--mass", dest="erase_mode", action="store_const", const=FlashEraser.Mode.MASS,
            help="Perform a mass erase. On some devices this is different than a chip erase.")
        erase_options.add_argument("addresses", metavar="<sector-address>", action='append', nargs='*',
            help="List of sector addresses or ranges to erase.")
        
        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, erase_parser]
    
    def invoke(self) -> int:
        """! @brief Handle 'erase' subcommand."""
        self._increase_logging(["pyocd.flash.eraser"])
        
        # Display a nice, helpful error describing why nothing was done and how to correct it.
        if (self._args.erase_mode is None) or not self._args.addresses:
            LOG.error("No erase operation specified. Please specify one of '--chip', '--sector', "
                        "or '--mass' to indicate the desired erase mode. For sector erases, a list "
                        "of sector addresses to erase must be provided. "
                        "See 'pyocd erase --help' for more.")
            return 1
        
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=(not self._args.no_wait),
                            connect_mode=self._args.connect_mode,
                            options=convert_session_options(self._args.options))
        if session is None:
            LOG.error("No device available to erase")
            return 1
        with session:
            mode = self._args.erase_mode or FlashEraser.Mode.SECTOR
            eraser = FlashEraser(session, mode)
            
            addresses = self.flatten_args(self._args.addresses)
            eraser.erase(addresses)

        return 0


