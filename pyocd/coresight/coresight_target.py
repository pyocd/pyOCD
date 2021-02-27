# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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
import six
from inspect import getfullargspec

from ..core.target import Target
from ..core.memory_map import MemoryType
from ..core.soc_target import SoCTarget
from ..core import exceptions
from . import (dap, discovery)
from ..debug.svd.loader import SVDLoader
from ..utility.sequencer import CallSequence
from ..target.pack.flash_algo import PackFlashAlgo

LOG = logging.getLogger(__name__)

class CoreSightTarget(SoCTarget):
    """! @brief Represents an SoC that uses CoreSight debug infrastructure.
    
    This class adds Arm CoreSight-specific discovery and initialization code to SoCTarget.
    """
    
    def __init__(self, session, memory_map=None):
        super(CoreSightTarget, self).__init__(session, memory_map)
        self.dp = dap.DebugPort(session.probe, self)
        self._svd_load_thread = None
        self._irq_table = None
        self._discoverer = None

    @property
    def aps(self):
        return self.dp.aps

    @property
    def svd_device(self):
        """! @brief Waits for SVD file to complete loading before returning."""
        if not self._svd_device and self._svd_load_thread:
            LOG.debug("Waiting for SVD load to complete")
            self._svd_device = self._svd_load_thread.device
        return self._svd_device

    def load_svd(self):
        def svd_load_completed_cb(svdDevice):
            self._svd_device = svdDevice
            self._svd_load_thread = None

        if not self._svd_device and self._svd_location:
            # Spawn thread to load SVD in background.
            self._svd_load_thread = SVDLoader(self._svd_location, svd_load_completed_cb)
            self._svd_load_thread.load()

    def create_init_sequence(self):
        seq = CallSequence(
            ('load_svd',            self.load_svd),
            ('pre_connect',         self.pre_connect),
            ('dp_init',             self.dp.create_connect_sequence),
            ('create_discoverer',   self.create_discoverer),
            ('discovery',           lambda : self._discoverer.discover()),
            ('check_for_cores',     self.check_for_cores),
            ('halt_on_connect',     self.perform_halt_on_connect),
            ('post_connect',        self.post_connect),
            ('post_connect_hook',   self.post_connect_hook),
            ('create_flash',        self.create_flash),
            ('notify',              lambda : self.session.notify(Target.Event.POST_CONNECT, self))
            )
        
        return seq
            
    def create_discoverer(self):
        """! @brief Init task to create the discovery object.
        
        Instantiates the appropriate @ref pyocd.coresight.discovery.CoreSightDiscovery
        CoreSightDiscovery subclass for the target's ADI version.
        """
        self._discoverer = discovery.ADI_DISCOVERY_CLASS_MAP[self.dp.adi_version](self)

    def pre_connect(self):
        """! @brief Handle some of the connect modes.
        
        This init task performs a connect pre-reset or asserts reset if the connect mode is
        under-reset.
        """
        mode = self.session.options.get('connect_mode')
        if mode == 'pre-reset':
            LOG.info("Performing connect pre-reset")
            self.dp.reset()
        elif mode == 'under-reset':
            LOG.info("Asserting reset prior to connect")
            self.dp.assert_reset(True)
    
    def perform_halt_on_connect(self):
        """! @brief Halt cores.
        
        This init task performs a connect pre-reset or asserts reset if the connect mode is
        under-reset.
        """
        mode = self.session.options.get('connect_mode')
        if mode != 'attach':
            if mode == 'under-reset':
                LOG.debug("Setting reset catch")
            # Apply to all cores.
            for core in self.cores.values():
                try:
                    if mode == 'under-reset':
                        core.set_reset_catch()
                    else:
                        core.halt()
                except exceptions.Error as err:
                    LOG.warning("Could not halt core #%d: %s", core.core_number, err,
                        exc_info=self.session.log_tracebacks)
    
    def post_connect(self):
        """! @brief Handle cleaning up some of the connect modes.
        
        This init task de-asserts reset if the connect mode is under-reset.
        """
        mode = self.session.options.get('connect_mode')
        if mode == 'under-reset':
            LOG.info("Deasserting reset post connect")
            self.dp.assert_reset(False)

            LOG.debug("Clearing reset catch")
            # Apply to all cores.
            for core in self.cores.values():
                try:
                    core.clear_reset_catch()
                except exceptions.Error as err:
                    LOG.warning("Could not halt core #%d: %s", core.core_number, err,
                        exc_info=self.session.log_tracebacks)
    
    def create_flash(self):
        """! @brief Instantiates flash objects for memory regions.
        
        This init task iterates over flash memory regions and for each one creates the Flash
        instance. It uses the flash_algo and flash_class properties of the region to know how
        to construct the flash object.
        """
        for region in self.memory_map.iter_matching_regions(type=MemoryType.FLASH):
            # If the region doesn't have an algo dict but does have an FLM file, try to load
            # the FLM and create the algo dict.
            if (region.algo is None) and (region.flm is not None):
                if isinstance(region.flm, six.string_types):
                    flmPath = self.session.find_user_file(None, [region.flm])
                    if flmPath is not None:
                        LOG.info("creating flash algo from: %s", flmPath)
                        packAlgo = PackFlashAlgo(flmPath)
                    else:
                        LOG.warning("Failed to find FLM file: %s", region.flm)
                        break
                elif isinstance(region.flm, PackFlashAlgo):
                    packAlgo = region.flm
                else:
                    LOG.warning("flash region flm attribute is unexpected type")
                    break

                # Create the algo dict from the FLM.
                if self.session.options.get("debug.log_flm_info"):
                    LOG.debug("Flash algo info: %s", packAlgo.flash_info)
                page_size = packAlgo.page_size
                if page_size <= 32:
                    page_size = min(s[1] for s in packAlgo.sector_sizes)
                algo = packAlgo.get_pyocd_flash_algo(
                        page_size,
                        self.memory_map.get_default_region_of_type(MemoryType.RAM))
                
                # If we got a valid algo from the FLM, set it on the region. This will then
                # be used below.
                if algo is not None:
                    region.algo = algo
            
            # If the constructor of the region's flash class takes the flash_algo arg, then we
            # need the region to have a flash algo dict to pass to it. Otherwise we assume the
            # algo is built-in.
            klass = region.flash_class
            argspec = getfullargspec(klass.__init__)
            if 'flash_algo' in argspec.args:
                if region.algo is not None:
                    obj = klass(self, region.algo)
                else:
                    LOG.warning("flash region '%s' has no flash algo" % region.name)
                    continue
            else:
                obj = klass(self)
            
            # Set the region in the flash instance.
            obj.region = region
            
            # Store the flash object back into the memory region.
            region.flash = obj

    def check_for_cores(self):
        """! @brief Init task: verify that at least one core was discovered."""
        if not len(self.cores):
            # Allow the user to override the exception to enable uses like chip bringup.
            if self.session.options.get('allow_no_cores'):
                LOG.error("No cores were discovered!")
            else:
                raise exceptions.DebugError("No cores were discovered!")
    @property
    def irq_table(self):
        if self._irq_table is None:
            if self.svd_device is not None:
                self._irq_table = {i.value : i.name for i in
                    [i for p in self.svd_device.peripherals for i in p.interrupts]}
        return self._irq_table
    
        
