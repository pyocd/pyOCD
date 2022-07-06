# pyOCD debugger
# Copyright (c) 2017-2020 Arm Limited
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
import os
from typing import (IO, TYPE_CHECKING, Callable, Iterable, List, Optional, Type, Union)

from .cmsis_pack import (CmsisPack, CmsisPackDevice, MalformedCmsisPackError)
from ..family import FAMILIES
from .. import TARGET
from ...coresight.coresight_target import CoreSightTarget
from ...debug.svd.loader import SVDFile
from .. import normalise_target_type_name

if TYPE_CHECKING:
    from zipfile import ZipFile
    from cmsis_pack_manager import CmsisPackRef
    from ...core.session import Session
    from ...utility.sequencer import CallSequence

try:
    import cmsis_pack_manager
    CPM_AVAILABLE = True
except ImportError:
    CPM_AVAILABLE = False

LOG = logging.getLogger(__name__)

class ManagedPacksStub:
    @staticmethod
    def get_installed_packs(cache: Optional[object] = None) -> List:
        return []

    @staticmethod
    def get_installed_targets(cache: Optional[object] = None) -> List:
        return []

    @staticmethod
    def populate_target(device_name: str) -> None:
        pass

class ManagedPacksImpl:
    """@brief Namespace for managed CMSIS-Pack utilities.

    By managed, we mean managed by the cmsis-pack-manager package. All the methods on this class
    apply only to those packs managed by cmsis-pack-manager, not any targets from packs specified
    by the user.
    """

    @staticmethod
    def get_installed_packs(cache: Optional[cmsis_pack_manager.Cache] = None) -> List["CmsisPackRef"]: # type:ignore
        """@brief Return a list containing CmsisPackRef objects for all installed packs."""
        if cache is None:
            cache = cmsis_pack_manager.Cache(True, True)
        results = []
        # packs_for_devices() returns only unique packs.
        for pack in cache.packs_for_devices(cache.index.values()):
            # Generate full path to the .pack file.
            pack_path = os.path.join(cache.data_path, pack.get_pack_name())

            # If the .pack file exists, the pack is installed.
            if os.path.isfile(pack_path):
                results.append(pack)
        return results

    @staticmethod
    def get_installed_targets(cache: Optional[cmsis_pack_manager.Cache] = None) -> List[CmsisPackDevice]: # type:ignore
        """@brief Return a list of CmsisPackDevice objects for installed pack targets."""
        if cache is None:
            cache = cmsis_pack_manager.Cache(True, True)
        results = []
        for pack in ManagedPacks.get_installed_packs(cache=cache):
            pack_path = os.path.join(cache.data_path, pack.get_pack_name())
            pack = CmsisPack(pack_path)
            results += list(pack.devices)
        return sorted(results, key=lambda dev:dev.part_number)

    @staticmethod
    def populate_target(device_name: str) -> None:
        """@brief Add targets from cmsis-pack-manager matching the given name.

        Targets are added to the `#TARGET` list. A case-insensitive comparison against the
        device part number is used to find the target to populate. If multiple packs are installed
        that provide the same part numbers, all matching targets will be populated.
        """
        device_name = normalise_target_type_name(device_name)
        targets = ManagedPacks.get_installed_targets()
        for dev in targets:
            if device_name == normalise_target_type_name(dev.part_number):
                PackTargets.populate_device(dev)

if CPM_AVAILABLE:
    ManagedPacks = ManagedPacksImpl
else:
    ManagedPacks = ManagedPacksStub

class _PackTargetMethods:
    """@brief Container for methods added to the dynamically generated pack target subclass."""

    @staticmethod
    def _pack_target__init__(self, session: "Session") -> None: # type:ignore
        """@brief Constructor for dynamically created target class."""
        super(self.__class__, self).__init__(session, self._pack_device.memory_map)

        self.vendor = self._pack_device.vendor
        self.part_families = self._pack_device.families
        self.part_number = self._pack_device.part_number

        self._svd_location = SVDFile(filename=self._pack_device.svd)

    @staticmethod
    def _pack_target_create_init_sequence(self) -> "CallSequence": # type:ignore
        """@brief Creates an init task to set the default reset type."""
        seq = super(self.__class__, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_cores',
                            ('set_default_reset_type', self.set_default_reset_type)
                            )
            )
        return seq

    @staticmethod
    def _pack_target_set_default_reset_type(self) -> None: # type:ignore
        """@brief Set's the first core's default reset type to the one specified in the pack."""
        if 0 in self.cores:
            self.cores[0].default_reset_type = self._pack_device.default_reset_type

class PackTargets:
    """@brief Namespace for CMSIS-Pack target generation utilities. """

    @staticmethod
    def _find_family_class(dev: CmsisPackDevice) -> Type[CoreSightTarget]:
        """@brief Search the families list for matching entry."""
        for familyInfo in FAMILIES:
            # Skip if wrong vendor.
            if dev.vendor != familyInfo.vendor:
                continue

            # Scan each level of family plus part number, from specific to generic.
            for compare_name in reversed(dev.families + [dev.part_number]):
                # Require the regex to match the entire family name.
                match = familyInfo.matches.match(compare_name)
                if match and match.span() == (0, len(compare_name)):
                    return familyInfo.klass

        # Didn't match, so return default target superclass.
        return CoreSightTarget

    @staticmethod
    def _generate_pack_target_class(dev: CmsisPackDevice) -> Optional[type]:
        """@brief Generates a new target class from a CmsisPackDevice.

        @param dev A CmsisPackDevice object.
        @return A new subclass of either CoreSightTarget or one of the family classes.
        """
        try:
            # Look up the target family superclass.
            superklass = PackTargets._find_family_class(dev)

            # Replace spaces and dashes with underscores on the new target subclass name.
            subclassName = normalise_target_type_name(dev.part_number).capitalize()

            # Create a new subclass for this target.
            targetClass = type(subclassName, (superklass,), {
                        "_pack_device": dev,
                        "__init__": _PackTargetMethods._pack_target__init__,
                        "create_init_sequence": _PackTargetMethods._pack_target_create_init_sequence,
                        "set_default_reset_type": _PackTargetMethods._pack_target_set_default_reset_type,
                    })
            return targetClass
        except (MalformedCmsisPackError, FileNotFoundError) as err:
            LOG.warning(err)
            return None

    @staticmethod
    def populate_device(dev: CmsisPackDevice) -> None:
        """@brief Generates and populates the target defined by a CmsisPackDevice.

        The new target class is added to the `#TARGET` list.

        @param dev A CmsisPackDevice object.
        """
        try:
            tgt = PackTargets._generate_pack_target_class(dev)
            if tgt is None:
                return
            part = normalise_target_type_name(dev.part_number)

            # Make sure there isn't a duplicate target name.
            if part not in TARGET:
                TARGET[part] = tgt
            else:
                LOG.debug("did not populate %s because there is already a %s target installed", dev.part_number, part)
        except (MalformedCmsisPackError, FileNotFoundError) as err:
            LOG.warning(err)

    PackReferenceType = Union[CmsisPack, str, "ZipFile", IO[bytes]]

    @staticmethod
    def process_targets_from_pack(
            pack_list: Union[PackReferenceType, Iterable[PackReferenceType]],
            cb: Callable[[CmsisPackDevice], None]
        ) -> None:
        """@brief Invoke a callable on devices defined in the provided CMSIS-Pack(s).

        @param pack_list Sequence of strings that are paths to .pack files, file objects,
            ZipFile instances, or CmsisPack instance. May also be a single object of one of
            the accepted types.
        @param cb Callable to run. Must take a CmsisPackDevice object as the sole parameter and return None.
        """
        if not isinstance(pack_list, (list, tuple)):
            pack_list = [pack_list]
        for pack_or_path in pack_list:
            if isinstance(pack_or_path, CmsisPack):
                pack = pack_or_path
            else:
                pack = CmsisPack(pack_or_path)
            for dev in pack.devices:
                cb(dev)

    @staticmethod
    def populate_targets_from_pack(pack_list: Union[PackReferenceType, Iterable[PackReferenceType]]) -> None:
        """@brief Adds targets defined in the provided CMSIS-Pack.

        Targets are added to the `#TARGET` list.

        @param pack_list Sequence of strings that are paths to .pack files, file objects,
            ZipFile instances, or CmsisPack instance. May also be a single object of one of
            the accepted types.
        """
        PackTargets.process_targets_from_pack(pack_list, PackTargets.populate_device)

def is_pack_target_available(target_name: str, session: "Session") -> bool:
    """@brief Test whether a given target type is available."""
    # Create targets from provided CMSIS pack.
    if session.options['pack'] is not None:
        target_types = []
        def collect_target_type(dev: CmsisPackDevice) -> None:
            part = normalise_target_type_name(dev.part_number)
            target_types.append(part)
        PackTargets.process_targets_from_pack(session.options['pack'], collect_target_type)
        return target_name.lower() in target_types

    # Check whether a managed pack contains the target.
    return any(
                (target_name.lower() == dev.part_number.lower())
                for dev in ManagedPacks.get_installed_targets()
                )


