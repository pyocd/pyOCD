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
from inspect import getfullargspec
from pathlib import PurePath
from typing import (Callable, Dict, Optional, TYPE_CHECKING, cast)

from ..core.target import Target
from ..core.memory_map import (FlashRegion, MemoryType, RamRegion, DeviceRegion, MemoryMap)
from ..core.soc_target import SoCTarget
from ..core import exceptions
from . import (dap, discovery)
from ..debug.svd.loader import SVDLoader
from ..utility.sequencer import CallSequence
from ..target.pack.flash_algo import PackFlashAlgo

if TYPE_CHECKING:
    from ..core.session import Session
    from ..core.memory_map import MemoryMap
    from .ap import (APAddressBase, AccessPort)
    from ..debug.svd.model import SVDDevice

LOG = logging.getLogger(__name__)

class CoreSightTarget(SoCTarget):
    """@brief Represents an SoC that uses CoreSight debug infrastructure.

    This class adds Arm CoreSight-specific discovery and initialization code to SoCTarget.
    """

    def __init__(self, session: "Session", memory_map: Optional["MemoryMap"] = None) -> None:
        # Supply a default memory map.
        if (memory_map is None) or (memory_map.region_count == 0):
            memory_map = self._create_default_cortex_m_memory_map()
            LOG.debug("Using default Cortex-M memory map (no memory map supplied)")

        super().__init__(session, memory_map)
        assert session.probe
        self.dp = dap.DebugPort(session.probe, self)
        self._svd_load_thread: Optional[SVDLoader] = None
        self._irq_table: Optional[Dict[int, str]] = None
        self._discoverer: Optional[Callable] = None

    @property
    def aps(self) -> Dict["APAddressBase", "AccessPort"]:
        return self.dp.aps

    @property
    def svd_device(self) -> Optional["SVDDevice"]:
        """@brief Waits for SVD file to complete loading before returning."""
        if not self._svd_device and self._svd_load_thread:
            LOG.debug("Waiting for SVD load to complete")
            self._svd_device = self._svd_load_thread.device
        return self._svd_device

    def _create_default_cortex_m_memory_map(self) -> MemoryMap:
        """@brief Create a MemoryMap for the Cortex-M system address map."""
        return MemoryMap(
                RamRegion(name="Code",          start=0x00000000, length=0x20000000, access='rwx'),
                RamRegion(name="SRAM",          start=0x20000000, length=0x20000000, access='rwx'),
                DeviceRegion(name="Peripheral", start=0x40000000, length=0x20000000, access='rw'),
                RamRegion(name="RAM1",          start=0x60000000, length=0x20000000, access='rwx'),
                RamRegion(name="RAM2",          start=0x80000000, length=0x20000000, access='rwx'),
                DeviceRegion(name="Device1",    start=0xA0000000, length=0x20000000, access='rw'),
                DeviceRegion(name="Device2",    start=0xC0000000, length=0x20000000, access='rw'),
                DeviceRegion(name="PPB",        start=0xE0000000, length=0x20000000, access='rw'),
                )

    def load_svd(self) -> None:
        def svd_load_completed_cb(svdDevice):
            self._svd_device = svdDevice
            self._svd_load_thread = None

        if not self._svd_device and self._svd_location:
            # Spawn thread to load SVD in background.
            self._svd_load_thread = SVDLoader(self._svd_location, svd_load_completed_cb)
            self._svd_load_thread.load()

    def create_init_sequence(self) -> CallSequence:
        seq = CallSequence(
            ('load_svd',            self.load_svd),
            ('pre_connect',         self.pre_connect),
            ('dp_init',             self.dp.create_connect_sequence),
            ('create_discoverer',   self.create_discoverer),
            ('discovery',           lambda : self._discoverer.discover() if self._discoverer else None),
            ('check_for_cores',     self.check_for_cores),
            ('halt_on_connect',     self.perform_halt_on_connect),
            ('post_connect',        self.post_connect),
            ('post_connect_hook',   self.post_connect_hook),
            ('create_flash',        self.create_flash),
            ('notify',              lambda : self.session.notify(Target.Event.POST_CONNECT, self))
            )

        return seq

    def disconnect(self, resume: bool = True) -> None:
        """@brief Disconnect from the target.

        Same as SoCTarget.disconnect(), except that it asks the DebugPort to power down.
        """
        self.session.notify(Target.Event.PRE_DISCONNECT, self)
        self.call_delegate('will_disconnect', target=self, resume=resume)
        for core in self.cores.values():
            core.disconnect(resume)
        # Only disconnect the DP if resuming; otherwise it will power down debug and potentially
        # let the core continue running.
        if resume:
            self.dp.disconnect()
        self.call_delegate('did_disconnect', target=self, resume=resume)

    def create_discoverer(self) -> None:
        """@brief Init task to create the discovery object.

        Instantiates the appropriate @ref pyocd.coresight.discovery.CoreSightDiscovery
        CoreSightDiscovery subclass for the target's ADI version.
        """
        self._discoverer = discovery.ADI_DISCOVERY_CLASS_MAP[self.dp.adi_version](self)

    def pre_connect(self) -> None:
        """@brief Handle some of the connect modes.

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

    def perform_halt_on_connect(self) -> None:
        """@brief Halt cores.

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
                        core.set_reset_catch(Target.ResetType.HW)
                    else:
                        core.halt()
                except exceptions.Error as err:
                    LOG.warning("Could not halt core #%d: %s", core.core_number, err,
                        exc_info=self.session.log_tracebacks)

    def post_connect(self) -> None:
        """@brief Handle cleaning up some of the connect modes.

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
                    core.clear_reset_catch(Target.ResetType.HW)
                except exceptions.Error as err:
                    LOG.warning("Could not halt core #%d: %s", core.core_number, err,
                        exc_info=self.session.log_tracebacks)

    def create_flash(self) -> None:
        """@brief Instantiates flash objects for memory regions.

        This init task iterates over flash memory regions and for each one creates the Flash
        instance. It uses the flash_algo and flash_class properties of the region to know how
        to construct the flash object.
        """
        for region in self.memory_map.iter_matching_regions(type=MemoryType.FLASH):
            region = cast(FlashRegion, region)
            # If the region doesn't have an algo dict but does have an FLM file, try to load
            # the FLM and create the algo dict.
            if (region.algo is None) and (region.flm is not None):
                if isinstance(region.flm, (str, PurePath)):
                    flm_path = self.session.find_user_file(None, [str(region.flm)])
                    if flm_path is not None:
                        LOG.info("creating flash algo for region %s from: %s", region.name, flm_path)
                        pack_algo = PackFlashAlgo(flm_path)
                    else:
                        LOG.warning("Failed to find FLM file: %s", region.flm)
                        break
                elif isinstance(region.flm, PackFlashAlgo):
                    pack_algo = region.flm
                else:
                    LOG.warning("flash region flm attribute is unexpected type")
                    break

                # Create the algo dict from the FLM.
                if self.session.options.get("debug.log_flm_info"):
                    LOG.debug("Flash algo info: %s", pack_algo.flash_info)
                page_size = pack_algo.page_size
                if page_size <= 32:
                    page_size = min(s[1] for s in pack_algo.sector_sizes)
                algo = pack_algo.get_pyocd_flash_algo(
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
                obj = klass(self) # type:ignore

            # Set the region in the flash instance.
            obj.region = region

            # Store the flash object back into the memory region.
            region.flash = obj

    def check_for_cores(self) -> None:
        """@brief Init task: verify that at least one core was discovered."""
        if not len(self.cores):
            # Allow the user to override the exception to enable uses like chip bringup.
            if self.session.options.get('allow_no_cores'):
                LOG.error("No cores were discovered!")
            else:
                raise exceptions.DebugError("No cores were discovered!")

    @property
    def irq_table(self) -> Dict[int, str]:
        if (self._irq_table is None):
            if (self.svd_device is not None) and (self.svd_device.peripherals is not None):
                peripherals = [
                        p for p in self.svd_device.peripherals
                        if p.interrupts is not None
                        ]
                self._irq_table = {
                        i.value : i.name
                        for p in peripherals
                            for i in p.interrupts
                        }
            else:
                self._irq_table = {}
        return self._irq_table

    # Override this method from SoCTarget so we can use the DP for hardware resets when there isn't a
    # valid core (instead of the probe), so reset notifications will be sent. We can't use the DP in
    # SoCTarget because it is only created by this class.
    def reset(self, reset_type=None):
        # Use the DP to reset if there is not a core.
        if (self.selected_core is None) and (self.dp is not None):
            self.dp.reset()
        else:
            super().reset(reset_type)


