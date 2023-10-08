# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

import logging
from inspect import getfullargspec
from typing import (Callable, Dict, Optional, TYPE_CHECKING, cast)

from ..core.target import Target
from ..core.memory_map import (FlashRegion, MemoryType, RamRegion, DeviceRegion, MemoryMap)
from ..core.soc_target import SoCTarget
from ..core import exceptions
from . import (dap, discovery)
from ..debug.svd.loader import SVDLoader
from ..utility.sequencer import CallSequence
from ..target.pack.flm_region_builder import FlmFlashRegionBuilder

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

        self.session.context_state.is_performing_pre_reset = False

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
            ('unlock_device',       self.unlock_device),
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

    def init(self) -> None:
        """@brief CoreSight specific target init.

        Connects this object's delegates, including a debug sequence delegate, to the DP.
        """
        # Set delegates on the DP.
        self.dp.delegate = self.delegate
        if self.debug_sequence_delegate:
            self.dp.debug_sequence_delegate = self.debug_sequence_delegate

        super().init()

    def disconnect(self, resume: bool = True) -> None:
        """@brief Disconnect from the target.

        Same as SoCTarget.disconnect(), except that it asks the DebugPort to power down.
        """
        self.session.notify(Target.Event.PRE_DISCONNECT, self)
        self.call_delegate('will_disconnect', target=self, resume=resume)
        for core in self.cores.values():
            core.disconnect(resume)
        # Only disconnect the DP if resuming; if not resuming we need to keep debug powered up so
        # the core can stay halted.
        if resume:
            self.dp.disconnect()
        self.call_delegate('did_disconnect', target=self, resume=resume)

    @property
    def primary_core_pname(self) -> str:
        """@brief Returns the pname for the `primary_core` option.

        This property is expected to be used prior to discovery. After discovery is complete, the
        node name of the `.primary_core` property can be used.

        This property is used rarely, so is not cached.

        @exception KeyError if `primary_core` is invalid.
        @exception AssertionError The device is not DFP based.
        """
        # The `primary_core` is an index into available cores, not necessarily the same as the AP
        # address and always different in the case of ADIv6. So we must use the DFP's list of APs
        # and processors to reconstruct the core order we will find during discovery.
        assert self.debug_sequence_delegate
        pack_device = self.debug_sequence_delegate.cmsis_pack_device
        ap_map = pack_device.processors_ap_map
        primary_core = self.session.options.get('primary_core')
        for i, proc_info in enumerate(sorted(ap_map.values(), key=lambda p: p.ap_address)):
            if i == primary_core:
                return proc_info.name
        else:
            raise exceptions.Error(f"invalid 'primary_core' session option '{primary_core}' "
                           f"(valid values are {', '.join(str(i) for i, _ in enumerate(ap_map.values()))})")

    def call_pre_discovery_debug_sequence(self, sequence: str) -> bool:
        """@brief Run a debug sequence before discovery has been performed.

        The primary core's pname cannot be looked up via the `node_name` property of the core
        object because that core object doesn't yet exist at the time this method is called.
        """
        if self.debug_sequence_delegate:
            # Try to get the pname to use.
            try:
                pcore_pname = self.primary_core_pname
            except exceptions.Error as err:
                LOG.warning("%s", err)
            else:
                if self.has_debug_sequence(sequence, pname=pcore_pname):
                    self.debug_sequence_delegate.run_sequence(sequence, pname=pcore_pname)
                    return True

        # Sequence wasn't run.
        return False

    def unlock_device(self) -> None:
        """@brief Hook to unlock the debug.

        The default implementation of this hook calls the delegate `unlock_device()` method or `DebugDeviceUnlock`
        debug sequence, if they exist, checked in this order.
        """
        if self.delegate_implements('unlock_device'):
            self.call_delegate('unlock_device')
        else:
            self.call_pre_discovery_debug_sequence('DebugDeviceUnlock')

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
            try:
                # Set the state variable indicating we're running ResetHardware for pre-reset, used
                # by the debug sequence delegate's get_connection_type() method.
                self.session.context_state.is_performing_pre_reset = True
                if not self.call_pre_discovery_debug_sequence('ResetHardware'):
                    self.dp.reset()
            finally:
                self.session.context_state.is_performing_pre_reset = False
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

        This init task iterates over flash memory regions and for each one finishes its setup and creates
        the Flash instance. It uses the flash_algo and flash_class properties of the region to know how
        to construct the flash object.
        """
        flm_builder = FlmFlashRegionBuilder(self, self.memory_map)
        for region in self.memory_map.iter_matching_regions(type=MemoryType.FLASH):
            region = cast(FlashRegion, region)

            # Load FLM file if needed, and create subregions for sector sizes.
            if not flm_builder.finalise_region(region):
                # Some error occurred, skip this region.
                continue

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

        # Update the memory map in each core.
        for core in self.cores.values():
            core.memory_map = self.memory_map

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

    @property
    def first_ap(self) -> Optional["AccessPort"]:
        if len(self.aps) == 0:
            return None
        return sorted(self.aps.values(), key=lambda v: v.address)[0]

    def trace_start(self):
        result = self.call_delegate('trace_start', target=self, mode=0)
        if not result and self.has_debug_sequence('TraceStart', pname=self.selected_core_or_raise.node_name):
            assert self.debug_sequence_delegate
            self.debug_sequence_delegate.run_sequence('TraceStart',
                    pname=self.selected_core_or_raise.node_name)
            result = True
        return result

    def trace_stop(self):
        result = self.call_delegate('trace_stop', target=self, mode=0)
        if not result and self.has_debug_sequence('TraceStop', pname=self.selected_core_or_raise.node_name):
            assert self.debug_sequence_delegate
            self.debug_sequence_delegate.run_sequence('TraceStop',
                    pname=self.selected_core_or_raise.node_name)
            result = True
        return result

