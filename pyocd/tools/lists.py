# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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
import pkg_resources
import six
from .. import __version__
from ..core.session import Session
from ..core.helpers import ConnectHelper
from ..target import TARGET
from ..target.builtin import BUILTIN_TARGETS
from ..board.board_ids import BOARD_ID_TO_INFO
from ..target.pack import pack_target

class ListGenerator(object):
    @staticmethod
    def list_probes():
        """! @brief Generate dictionary with info about the connected debug probes.
        
        Output version history:
        - 1.0, initial version
        """
        try:
            all_mbeds = ConnectHelper.get_sessions_for_all_connected_probes(blocking=False)
            status = 0
            error = ""
        except Exception as e:
            all_mbeds = []
            status = 1
            error = str(e)
            if not self.args.output_json:
                raise

        boards = []
        obj = {
            'pyocd_version' : __version__,
            'version' : { 'major' : 1, 'minor' : 0 },
            'status' : status,
            'boards' : boards,
            }

        if status != 0:
            obj['error'] = error

        for mbed in all_mbeds:
            d = {
                'unique_id' : mbed.probe.unique_id,
                'info' : mbed.board.description,
                'board_name' : mbed.board.name,
                'target' : mbed.board.target_type,
                'vendor_name' : mbed.probe.vendor_name,
                'product_name' : mbed.probe.product_name,
                }
            boards.append(d)

        return obj

    @staticmethod
    def list_boards(name_filter=None):
        """! @brief Generate dictionary with info about supported boards.
        
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

        managed_targets = [dev.part_number.lower() for dev in pack_target.ManagedPacks.get_installed_targets()]

        for board_id, info in BOARD_ID_TO_INFO.items():
            # Filter by name.
            if name_filter and name_filter not in info.name.lower():
                continue
            d = {
                'id' : board_id,
                'name' : info.name,
                'target': info.target,
                'binary' : info.binary,
                'is_target_builtin': (info.target in BUILTIN_TARGETS),
                'is_target_supported': (info.target in TARGET or info.target in managed_targets)
                }
            boards.append(d)

        return obj

    @staticmethod
    def list_targets(name_filter=None, vendor_filter=None, source_filter=None):
        """! @brief Generate dictionary with info about all supported targets.
        
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
            
            s = Session(None) # Create empty session
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
                if isinstance(svdPath, six.string_types) and os.path.exists(svdPath):
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
