# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

from ..core import exceptions
from .ap import (APv1Address, APv2Address, AccessPort)
from .dap import (ADIVersion, APAccessMemoryInterface)
from .rom_table import (CoreSightComponentID, ROMTable)
from . import (cortex_m, cortex_m_v8m)
from ..utility.sequencer import CallSequence

LOG = logging.getLogger(__name__)

class CoreSightDiscovery(object):
    """! @brief Base class for discovering CoreSight components in a target."""

    def __init__(self, target):
        """! @brief Constructor."""
        self._target = target
    
    @property
    def target(self):
        return self._target
    
    @property
    def dp(self):
        return self.target.dp
    
    @property
    def session(self):
        return self.target.session

    def discover(self):
        """! @brief Init task for component discovery.
        @return CallSequence for the discovery process.
        """
        raise NotImplementedError()

    def _create_component(self, cmpid):
        try:
            LOG.debug("Creating %s component", cmpid.name)
            cmp = cmpid.factory(cmpid.ap, cmpid, cmpid.address)
            cmp.init()
        except exceptions.Error as err:
            LOG.error("Error attempting to create component %s: %s", cmpid.name, err,
                    exc_info=self.session.log_tracebacks)

    def _create_cores(self):
        self._apply_to_all_components(self._create_component,
            filter=lambda c: c.factory in (cortex_m.CortexM.factory, cortex_m_v8m.CortexM_v8M.factory))

    def _create_components(self):
        self._apply_to_all_components(self._create_component,
            filter=lambda c: c.factory is not None
                and c.factory not in (cortex_m.CortexM.factory, cortex_m_v8m.CortexM_v8M.factory))
    
    def _apply_to_all_components(self, action, filter=None):
        # Iterate over every top-level ROM table.
        for ap in [x for x in self.dp.aps.values() if x.rom_table]:
            ap.rom_table.for_each(action, filter)

class ADIv5Discovery(CoreSightDiscovery):
    """! @brief Component discovery process for ADIv5.
    
    Component discovery for ADIv5 proceeds as follows. Each of the steps is labeled with the name
    of the init task for that step.
    
    1. `find_aps`: Perform an AP scan. Probe each AP at APSEL=0..255. By default the scan stops on
        the first invalid APSEL, as determined by testing the IDR value (0 is invalid). This can be
        overridden by a session option.
    2. `create_aps`: Create all APs and add them to the DP.
    3. `find_components`: For each AP, read the associated ROM table(s) and identify CoreSight
        components.
    4. `create_cores`: Create any discovered core (CPU) components. The cores are created first to
        ensure that other components have a core to which they may be connected.
    5. `create_components`: Create remaining discovered components.
    """

    ## APSEL is 8-bit, thus there are a maximum of 256 APs.
    MAX_APSEL = 255

    def discover(self):
        return CallSequence(
            ('find_aps',            self._find_aps),
            ('create_aps',          self._create_aps),
            ('find_components',     self._find_components),
            ('create_cores',        self._create_cores),
            ('create_components',   self._create_components),
            )

    def _find_aps(self):
        """! @brief Find valid APs using the ADIv5 method.
        
        Scans for valid APs starting at APSEL=0. The default behaviour is to stop after reading
        0 for the AP's IDR twice in succession. If the `scan_all_aps` session option is set to True,
        then the scan will instead probe every APSEL from 0-255.
        
        If there is already a list of valid APs defined for the @ref pyocd.coresight.dap.DebugPort
        DebugPort (the `valid_aps` attribute), then scanning is not performed. This is to allow a
        predetermined list of valid APSELs to be used in place of a scan. A few MCUs will lock up
        when accessing invalid APs. On those devices, scanning with the method used here cannot be
        done.
        """
        # Don't perform the AP scan if there is already a list of valid APs. This is to allow
        # skipping the AP scan by providing a predetermined list of valid APSELs.
        if self.dp.valid_aps is not None:
            return
        
        ap_list = []
        apsel = 0
        invalid_count = 0
        while apsel < self.MAX_APSEL:
            try:
                isValid = AccessPort.probe(self.dp, apsel)
                if isValid:
                    ap_list.append(apsel)
                    invalid_count = 0
                elif not self.session.options.get('scan_all_aps'):
                    invalid_count += 1
                    if invalid_count == self.session.options.get('adi.v5.max_invalid_ap_count'):
                        break
            except exceptions.Error as e:
                LOG.error("Exception while probing AP#%d: %s", apsel, e,
                    exc_info=self.session.log_tracebacks)
                break
            apsel += 1
        
        # Update the AP list once we know it's complete.
        self.dp.valid_aps = ap_list

    def _create_aps(self):
        """! @brief Init task that returns a call sequence to create APs.
        
        For each AP in the #valid_aps list, an AccessPort object is created. The new objects
        are added to the #aps dict, keyed by their AP number.
        """
        seq = CallSequence()
        for apsel in self.dp.valid_aps:
            seq.append(
                ('create_ap.{}'.format(apsel), lambda apsel=apsel: self._create_1_ap(apsel))
                )
        return seq
    
    def _create_1_ap(self, apsel):
        """! @brief Init task to create a single AP object."""
        try:
            ap_address = APv1Address(apsel)
            ap = AccessPort.create(self.dp, ap_address)
            self.dp.aps[ap_address] = ap
        except exceptions.Error as e:
            LOG.error("Exception reading AP#%d IDR: %s", apsel, e,
                exc_info=self.session.log_tracebacks)
    
    def _find_components(self):
        """! @brief Init task that generates a call sequence to ask each AP to find its components."""
        seq = CallSequence()
        for ap in [x for x in self.dp.aps.values() if x.has_rom_table]:
            seq.append(
                ('init_ap.{}'.format(ap.address.apsel), ap.find_components)
                )
        return seq

class ADIv6Discovery(CoreSightDiscovery):
    """! @brief Component discovery process for ADIv6.
    
    The process for discovering components in ADIv6 proceeds as follows. Each of the steps is
    labeled with the name of the init task for that step.
    
    1. `find_root_components`: Examine the component pointed to by the DP BASEPTR register(s). If
        it's a ROM table, read it and examine components pointed to by the entries. This creates the
        AP instances.
    2. `find_components`: For each AP, read the associated ROM table(s) and identify CoreSight
        components.
    3. `create_cores`: Create any discovered core (CPU) components. The cores are created first to
        ensure that other components have a core to which they may be connected.
    4. `create_components`: Create remaining discovered components.
    
    Note that nested APs are not supported.
    """

    def __init__(self, target):
        """! @brief Constructor."""
        super(ADIv6Discovery, self).__init__(target)
        self._top_rom_table = None

    def discover(self):
        return CallSequence(
            ('find_root_components',    self._find_root_components),
            ('find_components',         self._find_components_on_aps),
            ('create_cores',            self._create_cores),
            ('create_components',       self._create_components),
            )

    def _find_root_components(self):
        """! @brief Read top-level ROM table pointed to by the DP."""
        # There's not much we can do if we don't have a base address.
        if self.dp.base_address is None:
            return
        
        # Create a temporary memory interface.
        mem_interface = self.dp.apacc_memory_interface
        
        # Examine the base component.
        cmpid = CoreSightComponentID(None, mem_interface, self.dp.base_address)
        cmpid.read_id_registers()
        LOG.debug("Base component: %s", cmpid)
        
        if cmpid.is_rom_table:
            self._top_rom_table = ROMTable.create(mem_interface, cmpid)
            self._top_rom_table.init()
            
            # Create components defined in the DP ROM table.
            self._top_rom_table.for_each(self._create_1_ap,
                    filter=lambda c: c.factory == AccessPort.create)
            
            # Create non-AP components in the DP ROM table.
            self._top_rom_table.for_each(self._create_root_component,
                    filter=lambda c: (c.factory is not None) and (c.factory != AccessPort.create))
        elif cmpid.factory == AccessPort.create:
            self._create_1_ap(cmpid)
        else:
            self._create_root_component(cmpid)
    
    def _create_1_ap(self, cmpid):
        """! @brief Init task to create a single AP object."""
        try:
            ap_address = APv2Address(cmpid.address)
            ap = AccessPort.create(self.dp, ap_address, cmpid=cmpid)
            self.dp.aps[ap_address] = ap
        except exceptions.Error as e:
            LOG.error("Exception reading AP@0x%08x IDR: %s", cmpid.address, e,
                    exc_info=self.session.log_tracebacks)
    
    def _create_root_component(self, cmpid):
        """! @brief Init task to create a component attached directly to the DP.
        
        The newly created component is attached directly to the target instance (i.e.,
        CoreSightTarget or subclass) in the object graph.
        """
        try:
            # Create a memory interface for this component.
            ap_address = APv2Address(cmpid.address)
            memif = APAccessMemoryInterface(self.dp, ap_address)
            
            # Instantiate the component and attach to the target.
            component = cmpid.factory(memif, cmpid, cmpid.address)
            self.target.add_child(component)
            component.init()
        except exceptions.Error as e:
            LOG.error("Exception creating root component at address 0x%08x: %s", cmpid.address, e,
                    exc_info=self.session.log_tracebacks)
    
    def _find_components_on_aps(self):
        """! @brief Init task that generates a call sequence to ask each AP to find its components."""
        seq = CallSequence()
        for ap in [x for x in self.dp.aps.values() if x.has_rom_table]:
            seq.append(
                ('init_ap.{}'.format(str(ap.address)), ap.find_components)
                )
        return seq

## Map from ADI version to the discovery class.
ADI_DISCOVERY_CLASS_MAP = {
        ADIVersion.ADIv5: ADIv5Discovery,
        ADIVersion.ADIv6: ADIv6Discovery,
    }
