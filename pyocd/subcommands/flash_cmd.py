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
from ..flash.file_programmer import FileProgrammer
from ..utility.cmdline import convert_session_options

LOG = logging.getLogger(__name__)

def int_base_0(x):
    """! @brief Converts a string to an int with support for base prefixes."""
    return int(x, base=0)

class FlashSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['flash']
    HELP = "Program an image to device flash."
    DEFAULT_LOG_LEVEL = logging.WARNING
    
    ## @brief Valid erase mode options.
    ERASE_OPTIONS = [
        'auto',
        'chip',
        'sector',
        ]

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        flash_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        flash_options = flash_parser.add_argument_group("flash options")
        flash_options.add_argument("-e", "--erase", choices=cls.ERASE_OPTIONS, default='sector',
            help="Choose flash erase method. Default is sector.")
        flash_options.add_argument("-a", "--base-address", metavar="ADDR", type=int_base_0,
            help="Base address used for the address where to flash a binary. Defaults to start of flash.")
        flash_options.add_argument("--trust-crc", action="store_true",
            help="Use only the CRC of each page to determine if it already has the same data.")
        flash_options.add_argument("--format", choices=("bin", "hex", "elf"),
            help="File format. Default is to use the file's extension.")
        flash_options.add_argument("--skip", metavar="BYTES", default=0, type=int_base_0,
            help="Skip programming the first N bytes. This can only be used with binary files.")
        flash_options.add_argument("file", metavar="PATH",
            help="File to program into flash.")
        
        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, flash_parser]
    
    def invoke(self) -> int:
        """! @brief Handle 'flash' subcommand."""
        self._increase_logging(["pyocd.flash.loader"])
        
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
            LOG.error("No device available to flash")
            return 1
        with session:
            programmer = FileProgrammer(session,
                            chip_erase=self._args.erase,
                            trust_crc=self._args.trust_crc)
            programmer.program(self._args.file,
                            base_address=self._args.base_address,
                            skip=self._args.skip,
                            file_format=self._args.format)

        return 0


