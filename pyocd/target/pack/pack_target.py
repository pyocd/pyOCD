# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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
import logging
import six

from .cmsis_pack import (CmsisPack, MalformedCmsisPackError)
from ..family import FAMILIES
from .. import TARGET
from ...core.coresight_target import CoreSightTarget
from ...debug.svd import SVDFile

LOG = logging.getLogger(__name__)

def _pack_target__init__(self, session):
    """! @brief Constructor for dynamically created target class."""
    super(self.__class__, self).__init__(session, self._pack_device.memory_map)
    
    self.vendor = self._pack_device.vendor
    self.part_families = self._pack_device.families
    self.part_number = self._pack_device.part_number
    
    self._svd_location = SVDFile(filename=self._pack_device.svd, is_local=True)

def _pack_target_create_init_sequence(self):
    """! @brief Creates an init task to set the default reset type."""
    seq = super(self.__class__,self).create_init_sequence()
    seq.insert_after('create_cores',
        ('set_default_reset_type', self.set_default_reset_type))
    return seq

def _pack_target_set_default_reset_type(self):
    """! @brief Set's the first core's default reset type to the one specified in the pack."""
    if 0 in self.cores:
        self.cores[0].default_reset_type = self._pack_device.default_reset_type

def _find_family_class(dev):
    """! @brief Search the families list for matching entry."""
    for familyInfo in FAMILIES:
        # Skip if wrong vendor.
        if dev.vendor != familyInfo.vendor:
            continue
        
        # Scan each level of families
        for familyName in dev.families:
            for regex in familyInfo.matches:
                # Require the regex to match the entire family name.
                match = regex.match(familyName)
                if match and match.span() == (0, len(familyName)):
                    return familyInfo.klass
    else:
        # Default target superclass.
        return CoreSightTarget

def _create_targets_from_pack(pack_or_path):
    """! @brief Iterator yielding parsed targets for all devices defined by the given pack.
    
    @param pack_or_path May be a string which is a path to a .pack file, a file object, or
        a ZipFile instance.
    @return Each yielded result is a 2-tuple of the target's part number string, plus a
        dynamically created subclass of CmsisPackTarget for the target.
    """
    try:
        if isinstance(pack_or_path, six.string_types):
            LOG.info("Loading CMSIS-Pack: %s", pack_or_path)
        pack = CmsisPack(pack_or_path)
        for dev in pack.devices:
            # Look up the target family superclass.
            superklass = _find_family_class(dev)
            
            # Replace spaces with underscores on the target class name.
            subclassName = dev.part_number.replace(' ', '_')
            
            # Create a new subclass for this target.
            targetClass = type(dev.part_number, (superklass,), {
                        "_pack_device": dev,
                        "__init__": _pack_target__init__,
                        "create_init_sequence": _pack_target_create_init_sequence,
                        "set_default_reset_type": _pack_target_set_default_reset_type,
                    })
            yield (dev.part_number, targetClass)
    except MalformedCmsisPackError as err:
        LOG.warning(err)
        return

def populate_targets_from_pack(pack_list):
    """! @brief Adds targets defined in the provided CMSIS-Pack.
    
    Targets are added to the `#TARGET` list.
    
    @param pack_list Sequence of strings that are paths to .pack files, file objects, or
        ZipFile instances. May also be a single object of one of the accepted types.
    """
    if not isinstance(pack_list, (list, tuple)):
        pack_list = [pack_list]
    for pack_or_path in pack_list:
        for part, tgt in _create_targets_from_pack(pack_or_path):
            part = part.lower()
        
            # Make sure there isn't a duplicate target name.
            if part not in TARGET:
                TARGET[part] = tgt
        

