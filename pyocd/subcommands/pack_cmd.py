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
import re
import fnmatch

from .base import SubcommandBase
from ..core import exceptions
from ..target.pack import pack_target

try:
    import cmsis_pack_manager
    CPM_AVAILABLE = True
except ImportError:
    CPM_AVAILABLE = False

LOG = logging.getLogger(__name__)

class PackSubcommandBase(SubcommandBase):
    """! @brief Base class for `pyocd pack` subcommands."""
    
    # cmsis_pack_manager.Cache is used in quotes in the return type annotation because it may have
    # not been imported successfully.
    def _get_cache(self) -> "cmsis_pack_manager.Cache":
        """! @brief Handle 'clean' subcommand."""
        if not CPM_AVAILABLE:
            raise exceptions.CommandError("'pack' subcommand is not available because cmsis-pack-manager is not installed")
        
        verbosity = self._args.verbose - self._args.quiet
        return cmsis_pack_manager.Cache(verbosity < 0, False)

    def _get_matches(self, cache: "cmsis_pack_manager.Cache") -> set[str]:
        if not cache.index:
            LOG.info("No pack index present, downloading now...")
            cache.cache_descriptors()
        
        # Find matching part numbers.
        matches = set()
        for pattern in self._args.patterns:
            # Using fnmatch.fnmatch() was failing to match correctly.
            pat = re.compile(fnmatch.translate(pattern).rsplit('\\Z')[0], re.IGNORECASE)
            results = {name for name in cache.index.keys() if pat.search(name)}
            matches.update(results)
        
        if not matches:
            LOG.warning("No matching devices. Please make sure the pack index is up to date."),
        
        return matches

class PackSubcommand(PackSubcommandBase):
    """! @brief `pyocd pack` subcommand."""
    
    NAMES = ['pack']
    HELP = "Manage CMSIS-Packs for target support."
    
    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        pack_parser = argparse.ArgumentParser(description=cls.HELP, add_help=False)

        pack_operations = pack_parser.add_argument_group('pack operations')
        pack_operations.add_argument("-c", "--clean", action='store_true',
            help="Erase all stored pack information.")
        pack_operations.add_argument("-u", "--update", action='store_true',
            help="Update the pack index.")
        pack_operations.add_argument("-s", "--show", action='store_true',
            help="Show the list of installed packs.")
        pack_operations.add_argument("-f", "--find", dest="find_devices", metavar="GLOB", action='append',
            help="Report pack(s) in the index containing matching device part numbers.")
        pack_operations.add_argument("-i", "--install", dest="install_devices", metavar="GLOB", action='append',
            help="Download and install pack(s) containing matching device part numbers.")

        pack_options = pack_parser.add_argument_group('pack options')
        pack_options.add_argument("-n", "--no-download", action='store_true',
            help="Just list the pack(s) that would be downloaded, don't actually download anything.")
        pack_options.add_argument('-H', '--no-header', action='store_true',
            help="Don't print a table header.")
        
        return [cls.CommonOptions.LOGGING, pack_parser]
    
    def invoke(self) -> int:
        """! @brief Handle 'pack' subcommand."""

        cache = self._get_cache()
        
        if self._args.clean:
            LOG.info("Removing all pack data...")
            cache.cache_clean()
        
        if self._args.update:
            LOG.info("Updating pack index...")
            cache.cache_descriptors()
            print()
        
        if self._args.show:
            packs = pack_target.ManagedPacks.get_installed_packs(cache)
            pt = self._get_pretty_table(["Vendor", "Pack", "Version"])
            for ref in packs:
                pt.add_row([
                            ref.vendor,
                            ref.pack,
                            ref.version,
                            ])
            print(pt)

        if self._args.find_devices or self._args.install_devices:
            self._args.patterns = self._args.find_devices or self._args.install_devices
            
            matches = self._get_matches(cache)
            
            if self._args.find_devices:
                # Get the list of installed pack targets.
                installed_targets = pack_target.ManagedPacks.get_installed_targets(cache=cache)
                installed_target_names = [target.part_number.lower() for target in installed_targets]
                
                pt = self._get_pretty_table(["Part", "Vendor", "Pack", "Version", "Installed"])
                for name in sorted(matches):
                    info = cache.index[name]
                    ref, = cache.packs_for_devices([info])
                    pt.add_row([
                                info['name'],
                                ref.vendor,
                                ref.pack,
                                ref.version,
                                info['name'].lower() in installed_target_names,
                                ])
                print(pt)
            elif self._args.install_devices:
                devices = [cache.index[dev] for dev in matches]
                packs = cache.packs_for_devices(devices)
                if not self._args.no_download:
                    print("Downloading packs (press Control-C to cancel):")
                else:
                    print("Would download packs:")
                for pack in packs:
                    print("    " + str(pack))
                if not self._args.no_download:
                    cache.download_pack_list(packs)
                print()

        return 0

