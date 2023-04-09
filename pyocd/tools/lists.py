# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
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

import os
from importlib_metadata import entry_points

from .. import __version__
from ..core.session import Session
from ..core.helpers import ConnectHelper
from ..core import options
from ..target import TARGET
from ..target.builtin import BUILTIN_TARGETS
from ..board.board_ids import BOARD_ID_TO_INFO
from ..target.pack import pack_target
from ..probe.debug_probe import DebugProbe

class StubProbe(DebugProbe):
    @property
    def unique_id(self) -> str:
        return "0"

class ListGenerator(object):
    @staticmethod
    def list_probes():
        """@brief Generate dictionary with info about the connected debug probes.

        Output version history:
        - 1.0, initial version
        - 1.1, add 'board_vendor' key for each probe
        """
        status = 0
        error = ""
        try:
            probes = ConnectHelper.get_all_connected_probes(blocking=False)
        except Exception as e:
            probes = []
            status = 1
            error = str(e)

        probes_info_list = []
        obj = {
            'pyocd_version' : __version__,
            'version' : { 'major' : 1, 'minor' : 1 },
            'status' : status,
            'boards' : probes_info_list,
            }

        if status != 0:
            obj['error'] = error

        for probe in probes:
            board_info = probe.associated_board_info
            target_type_name = board_info.target if board_info else None
            board_name = board_info.name if board_info else "Generic"
            board_vendor = board_info.vendor if board_info else None

            if board_info and board_info.name:
                desc = f"{board_vendor} {board_name}" if board_vendor else board_name
            else:
                desc = f"{probe.vendor_name} {probe.product_name}"

            d = {
                'unique_id' : probe.unique_id,
                'info' : desc,
                'board_vendor': board_vendor,
                'board_name' : board_name,
                'target' : target_type_name or "cortex_m",
                'vendor_name' : probe.vendor_name,
                'product_name' : probe.product_name,
                }
            probes_info_list.append(d)

        return obj

    @staticmethod
    def list_boards(name_filter=None):
        """@brief Generate dictionary with info about supported boards.

        Output version history:
        - 1.0, initial version
        - 1.1, added is_target_builtin and is_target_supported keys
        """
        # Lowercase name and vendor arguments for case-insensitive comparison.
        if name_filter is not None:
            name_filter = name_filter.lower()

        boards = []
        obj = {
            'pyocd_version' : __version__,
            'version' : { 'major' : 1, 'minor' : 1 },
            'status' : 0,
            'boards' : boards
            }

        # Lowercase target names for comparison
        managed_targets = [dev.part_number.lower() for dev in pack_target.ManagedPacks.get_installed_targets()]
        builtin_target_names = [target_name.lower() for target_name in BUILTIN_TARGETS]
        target_names = [target_name.lower() for target_name in TARGET]

        for board_id, info in BOARD_ID_TO_INFO.items():
            # Filter by name.
            if name_filter and name_filter not in info.name.lower():
                continue
            d = {
                'id' : board_id,
                'name' : info.name,
                'target': info.target,
                'binary' : info.binary,
                'is_target_builtin': (info.target.lower() in builtin_target_names) \
                    if info.target else False,
                'is_target_supported': (info.target.lower() in target_names \
                    or info.target in managed_targets) if info.target else False,
                }
            boards.append(d)

        return obj

    @staticmethod
    def list_targets(name_filter=None, vendor_filter=None, source_filter=None):
        """@brief Generate dictionary with info about all supported targets.

        Output version history:
        - 1.0, initial version
        - 1.1, added part_families
        - 1.2, added source
        """
        # Lowercase name and vendor arguments for case-insensitive comparison.
        if name_filter is not None:
            name_filter = name_filter.lower()
        if vendor_filter is not None:
            vendor_filter = vendor_filter.lower()

        targets = []
        obj = {
            'pyocd_version' : __version__,
            'version' : { 'major' : 1, 'minor' : 2 },
            'status' : 0,
            'targets' : targets
            }

        for name in TARGET.keys():
            # Filter by name.
            if name_filter and name_filter not in name.lower():
                continue

            # Create session with a stub probe that allows us to instantiate the target. This will create
            # Board and Target instances of its own, so set some options to control that.
            s = Session(StubProbe(), no_config=True, target_override='cortex_m')
            t = TARGET[name](s)

            # Filter by vendor.
            if vendor_filter and vendor_filter not in t.vendor.lower():
                continue

            # Filter by source.
            source = 'pack' if hasattr(t, '_pack_device') else 'builtin'
            if source_filter and source_filter != source:
                continue

            d = {
                'name' : name,
                'vendor' : t.vendor,
                'part_families' : t.part_families,
                'part_number' : t.part_number,
                'source': source,
                }
            if t._svd_location is not None:
                svdPath = t._svd_location.filename
                if isinstance(svdPath, str) and os.path.exists(svdPath):
                    d['svd_path'] = svdPath
            targets.append(d)

        if not source_filter or source_filter == 'pack':
            # Add targets from cmsis-pack-manager cache.
            for dev in pack_target.ManagedPacks.get_installed_targets():
                try:
                    # Filter by name.
                    if name_filter and name_filter not in dev.part_number.lower():
                        continue
                    # Filter by vendor.
                    if vendor_filter and vendor_filter not in dev.vendor.lower():
                        continue
                    targets.append({
                        'name' : dev.part_number.lower(),
                        'part_families' : dev.families,
                        'part_number' : dev.part_number,
                        'vendor' : dev.vendor,
                        'source' : 'pack',
                        })
                except KeyError:
                    pass

        return obj

    @staticmethod
    def list_plugins():
        """@brief Generate dictionary with lists of available plugins.

        Output version history:
        - 1.0, initial version with debug probe and RTOS plugins
        """
        from ..probe.aggregator import PROBE_CLASSES
        from ..rtos import RTOS
        plugin_groups = [
                'pyocd.probe',
                'pyocd.rtos',
                ]
        plugin_groups_list = []
        obj = {
            'pyocd_version': __version__,
            'version': { 'major': 1, 'minor': 0 },
            'status': 0,
            'plugins': plugin_groups_list,
            }

        # Add plugins info
        for group_name in plugin_groups:
            plugin_list = []
            group_info = {
                'plugin_type': group_name,
                'plugins': plugin_list,
                }

            for entry_point in entry_points(group=group_name):
                klass = entry_point.load()
                plugin = klass()
                info = {
                    'name': plugin.name,
                    'version': plugin.version,
                    'description': plugin.description,
                    'classname': klass.__name__,
                    }
                plugin_list.append(info)
            plugin_groups_list.append(group_info)

        return obj

    @staticmethod
    def list_features():
        """@brief Generate dictionary with info about supported features and options.

        Output version history:
        - 1.1, added 'plugins' feature
        - 1.0, initial version
        """
        options_list = []
        plugins_list = []
        obj = {
            'pyocd_version' : __version__,
            'version' : { 'major' : 1, 'minor' : 1 },
            'status' : 0,
            'features' : [
                    {
                        'name': 'plugins',
                        'plugins': plugins_list,
                    },
                ],
            'options' : options_list,
            }

        # Add plugins
        plugins = ListGenerator.list_plugins()
        plugins_list.extend(plugins['plugins'])

        # Add options
        for option_name in options.OPTIONS_INFO.keys():
            info = options.OPTIONS_INFO[option_name]
            option_dict = {
                        'name' : option_name,
                        'default' : info.default,
                        'description' : info.help,
                        }
            try:
                types_list = []
                for t in info.type:
                    types_list.append(t.__name__)
            except TypeError:
                types_list = [info.type.__name__]
            option_dict['type'] = types_list
            options_list.append(option_dict)

        return obj
