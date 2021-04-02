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
from ..core.session import Session
from ..tools.lists import ListGenerator
from ..target.pack import pack_target
from ..utility.cmdline import convert_session_options

LOG = logging.getLogger(__name__)

class ListSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['list']
    HELP = "List information about probes, targets, or boards."
    
    ## @brief Map to convert plugin groups to user friendly names.
    PLUGIN_GROUP_NAMES = {
        'pyocd.probe': "Debug Probe",
        'pyocd.rtos': "RTOS",
        }

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        list_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)
        
        list_output = list_parser.add_argument_group("list output")
        list_output.add_argument('-p', '--probes', action='store_true',
            help="List available probes.")
        list_output.add_argument('-t', '--targets', action='store_true',
            help="List all known targets.")
        list_output.add_argument('-b', '--boards', action='store_true',
            help="List all known boards.")
        list_output.add_argument('--plugins', action='store_true',
            help="List available plugins.")
            
        list_options = list_parser.add_argument_group('list options')
        list_options.add_argument('-n', '--name',
            help="Restrict listing to items matching the given name. Applies to targets and boards.")
        list_options.add_argument('-r', '--vendor',
            help="Restrict listing to items whose vendor matches the given name. Applies to targets.")
        list_options.add_argument('-s', '--source', choices=('builtin', 'pack'),
            help="Restrict listing to targets from the specified source. Applies to targets.")
        list_options.add_argument('-H', '--no-header', action='store_true',
            help="Don't print a table header.")
        
        return [cls.CommonOptions.COMMON, list_parser]
    
    def invoke(self) -> int:
        """! @brief Handle 'list' subcommand."""
        all_outputs = (self._args.probes, self._args.targets, self._args.boards, self._args.plugins)
        
        # Default to listing probes.
        if not any(all_outputs):
            self._args.probes = True
        
        # Check for more than one output option being selected.
        if sum(int(x) for x in all_outputs) > 1:
            LOG.error("Only one of the output options '--probes', '--targets', '--boards', "
                      "or '--plugins' may be selected at a time.")
            return 1
        
        # Create a session with no device so we load any config.
        session = Session(None,
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            **convert_session_options(self._args.options)
                            )
        
        if self._args.probes:
            ConnectHelper.list_connected_probes()
        elif self._args.targets:
            # Create targets from provided CMSIS pack.
            if session.options['pack'] is not None:
                pack_target.PackTargets.populate_targets_from_pack(session.options['pack'])

            obj = ListGenerator.list_targets(name_filter=self._args.name,
                                            vendor_filter=self._args.vendor,
                                            source_filter=self._args.source)
            pt = self._get_pretty_table(["Name", "Vendor", "Part Number", "Families", "Source"])
            for info in sorted(obj['targets'], key=lambda i: i['name']):
                pt.add_row([
                            info['name'],
                            info['vendor'],
                            info['part_number'],
                            ', '.join(info['part_families']),
                            info['source'],
                            ])
            print(pt)
        elif self._args.boards:
            obj = ListGenerator.list_boards(name_filter=self._args.name)
            pt = self._get_pretty_table(["ID", "Name", "Target", "Test Binary"])
            for info in sorted(obj['boards'], key=lambda i: i['id']):
                pt.add_row([
                            info['id'],
                            info['name'],
                            info['target'],
                            info['binary']
                            ])
            print(pt)
        elif self._args.plugins:
            obj = ListGenerator.list_plugins()
            pt = self._get_pretty_table(["Type", "Plugin Name", "Version", "Description"])
            for group_info in sorted(obj['plugins'], key=lambda i: i['plugin_type']):
                for plugin_info in sorted(group_info['plugins'], key=lambda i: i['name']):
                    pt.add_row([
                                self.PLUGIN_GROUP_NAMES[group_info['plugin_type']],
                                plugin_info['name'],
                                plugin_info['version'],
                                plugin_info['description'],
                                ])
            print(pt)

        return 0

