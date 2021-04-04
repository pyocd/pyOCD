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
import json

from .base import SubcommandBase
from ..core.session import Session
from ..tools.lists import ListGenerator
from ..target.pack import pack_target
from ..utility.cmdline import convert_session_options
from .. import __version__

LOG = logging.getLogger(__name__)

class JsonSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['json']
    HELP = "Output information as JSON."
    DEFAULT_LOG_LEVEL = logging.FATAL + 1

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        json_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        json_options = json_parser.add_argument_group('json output')
        json_options.add_argument('-p', '--probes', action='store_true',
            help="List available probes.")
        json_options.add_argument('-t', '--targets', action='store_true',
            help="List all known targets.")
        json_options.add_argument('-b', '--boards', action='store_true',
            help="List all known boards.")
        json_options.add_argument('-f', '--features', action='store_true',
            help="List available features and options.")

        return [cls.CommonOptions.CONFIG, json_parser]
    
    @classmethod
    def customize_subparser(cls, subparser: argparse.ArgumentParser) -> None:
        """! @brief Optionally modify a subparser after it is created."""
        subparser.set_defaults(verbose=0, quiet=0)
    
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        
        # Disable all logging.
        logging.disable(logging.CRITICAL)
    
    def invoke(self) -> int:
        """! @brief Handle 'json' subcommand."""
        all_outputs = (self._args.probes, self._args.targets, self._args.boards, self._args.features)
        
        # Default to listing probes.
        if not any(all_outputs):
            self._args.probes = True
        
        # Check for more than one output option being selected.
        if sum(int(x) for x in all_outputs) > 1:
            # Because we're outputting JSON we can't just log the error, but must report the error
            # via the JSON format.
            obj = {
                'pyocd_version' : __version__,
                'version' : { 'major' : 1, 'minor' : 0 },
                'status' : 1,
                'error' : "More than one output data selected.",
                }

            print(json.dumps(obj, indent=4))
            return 0
        
        # Create a session with no device so we load any config.
        session = Session(None,
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            **convert_session_options(self._args.options)
                            )
        
        if self._args.targets or self._args.boards:
            # Create targets from provided CMSIS pack.
            if session.options['pack'] is not None:
                pack_target.PackTargets.populate_targets_from_pack(session.options['pack'])

        if self._args.probes:
            obj = ListGenerator.list_probes()
        elif self._args.targets:
            obj = ListGenerator.list_targets()
        elif self._args.boards:
            obj = ListGenerator.list_boards()
        elif self._args.features:
            obj = ListGenerator.list_features()
        else:
            assert False
        print(json.dumps(obj, indent=4))
        return 0

