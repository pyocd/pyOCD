# pyOCD debugger
# Copyright (c) 2021-2022 Chris Reed
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
from pathlib import Path

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..flash.file_programmer import FileProgrammer
from ..utility.cmdline import (
    convert_session_options,
    int_base_0,
)

LOG = logging.getLogger(__name__)

class LoadSubcommand(SubcommandBase):
    """@brief `pyocd load` and `flash` subcommand."""

    NAMES = ['load', 'flash']
    HELP = "Load one or more images into target device memory."
    EPILOG = "Supported file formats are: binary, Intel hex, and ELF32."
    DEFAULT_LOG_LEVEL = logging.WARNING

    ## @brief Valid erase mode options.
    ERASE_OPTIONS = [
        'auto',
        'chip',
        'sector',
        ]

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""
        parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        parser_options = parser.add_argument_group("load options")
        parser_options.add_argument("-e", "--erase", choices=cls.ERASE_OPTIONS, default='sector',
            help="Choose flash erase method. Default is sector.")
        parser_options.add_argument("-a", "--base-address", metavar="ADDR", type=int_base_0,
            help="Base address used for the address where to write a binary. Defaults to start of flash. "
                 "Only allowed if a single binary file is being loaded.")
        parser_options.add_argument("--trust-crc", action="store_true",
            help="Use only the CRC of each page to determine if it already has the same data.")
        parser_options.add_argument("--format", choices=("bin", "hex", "elf"),
            help="File format. Default is to use the file's extension. If multiple files are provided, then "
                 "all must be of this type.")
        parser_options.add_argument("--skip", metavar="BYTES", default=0, type=int_base_0,
            help="Skip programming the first N bytes. Binary files only.")
        parser_options.add_argument("--no-reset", action="store_true",
            help="Specify to prevent resetting device after programming has finished.")

        parser.add_argument("file", metavar="<file-path>", nargs="+",
            help="File to write to memory. Binary files can have an optional base address appended to the file "
                 "name as '@<address>', for instance 'app.bin@0x20000'.")

        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, parser]

    def invoke(self) -> int:
        """@brief Handle 'load' subcommand."""
        self._increase_logging(["pyocd.flash.loader", __name__])

        # Validate arguments.
        if (self._args.base_address is not None) and (len(self._args.file) > 1):
            raise ValueError("--base-address cannot be set when loading more than one file; "
                    "use a base address suffix instead")

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
                            options=convert_session_options(self._args.options),
                            option_defaults=self._modified_option_defaults(),
                            )
        if session is None:
            LOG.error("No target device available")
            return 1
        with session:
            programmer = FileProgrammer(session,
                            chip_erase=self._args.erase,
                            trust_crc=self._args.trust_crc,
                            no_reset=self._args.no_reset)
            for filename in self._args.file:
                # Get an initial path with the argument as-is.
                file_path = Path(filename).expanduser()

                # Look for a base address suffix. If the supplied argument including an address suffix
                # references an existing file, then the address suffix is not extracted.
                if "@" in filename and not file_path.exists():
                    filename, suffix = filename.rsplit("@", 1)
                    try:
                        base_address = int_base_0(suffix)
                    except ValueError:
                        LOG.error(f'Base address suffix "{suffix}" on file "{filename}" is not a valid integer address')
                        return 1
                else:
                    base_address = self._args.base_address

                # Resolve our path.
                file_path = Path(filename).expanduser().resolve()
                filename = str(file_path)

                if base_address is None:
                    LOG.info("Loading %s", filename)
                else:
                    LOG.info("Loading %s at %#010x", filename, base_address)

                programmer.program(filename,
                                base_address=base_address,
                                skip=self._args.skip,
                                file_format=self._args.format)

        return 0


