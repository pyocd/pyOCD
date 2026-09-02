# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
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

"""
RISC-V SoC target for pyOCD.

Bridges pyOCD's SoCTarget interface to RISC-V Debug Module infrastructure.
This is the RISC-V equivalent of CoreSightTarget.

Architecture mapping:
    CoreSightTarget → RISCVTarget
    DAP/AP discovery → DebugModule init + hart discovery
    ROM table scanning → DMSTATUS/DMCONTROL enumeration
"""

import logging
from typing import Callable, List, Optional

from ...core.soc_target import SoCTarget
from ...core.core_target import CoreTarget
from ...core.target import Target
from ...core.memory_map import MemoryMap, MemoryType
from ...utility.sequencer import CallSequence

from ..dm.debug_module import DebugModule
from ..core.riscv import RISCVCore
from ..core.debug_context import RiscvDebugContext

LOG = logging.getLogger(__name__)


class RISCVTarget(SoCTarget):
    """RISC-V SoC target using Debug Module infrastructure.

    Replaces CoreSightTarget for RISC-V targets. Uses DebugModule
    for DTM/DMI/DM initialization and hart discovery instead of
    Arm DAP/AP/ROM table scanning.

    Subclasses should define MEMORY_MAP with target-specific memory regions.

    Usage:
        class MyTarget(RISCVTarget):
            MEMORY_MAP = MemoryMap(
                RamRegion("RAM", start=0x10000000, length=0x10000),
            )

        # Registered as: 'my_target': MyTarget
    """

    def __init__(self, session, memory_map: Optional[MemoryMap] = None):
        """Initialize RISC-V target.

        Args:
            session: pyOCD Session instance
            memory_map: Optional memory map override
        """
        super().__init__(session, memory_map)

        # DebugModule is created but NOT initialized until init()
        # Determine cJTAG mode from dap_protocol session option
        protocol_name = self.session.options.get('dap_protocol').strip().lower()
        is_cjtag = None  # auto-detect by default
        if protocol_name == 'cjtag':
            is_cjtag = True
        elif protocol_name == 'jtag':
            is_cjtag = False
        self.dm = DebugModule(session.probe, is_cjtag=is_cjtag)

        # RISC-V does not use ARM DAP/AP architecture.
        # Empty dict for pyOCD command context compatibility.
        self._aps = {}

        # Hooks called before hart discovery in DebugModule.init().
        self._pre_hart_discover_hooks: List[Callable] = []

    @property
    def aps(self):
        """Access Ports dict.

        RISC-V does not use ARM DAP/AP architecture.
        Returns empty dict for pyOCD command context compatibility.
        """
        return self._aps

    def create_init_sequence(self) -> CallSequence:
        """Create the RISC-V target initialization sequence.

        Replaces CoreSightTarget's 9-step ARM sequence with RISC-V DM sequence.
        DebugModule.init() handles DTM init, DM activation, capability detection,
        and hart discovery internally.
        """
        return CallSequence(
            ('pre_connect', self._pre_connect),
            ('debug_module_init', self._debug_module_init),
            ('create_cores', self._create_cores),
            ('register_reset_hooks', self._register_reset_hooks),
            ('halt_on_connect', self._halt_on_connect),
            ('init_core_triggers', self._init_core_triggers),
            ('pre_flash_init', self._pre_flash_init),
            ('create_flash', self._create_flash),
            ('notify_connect', self._notify_connect),
        )

    def _pre_connect(self) -> None:
        """Connect probe in JTAG or cJTAG mode before DTM initialization.

        This is the RISC-V equivalent of CoreSightTarget's 'dp_init' step.
        ARM targets use DAP.create_connect_sequence() which calls probe.connect().
        RISC-V targets must call probe.connect(JTAG) explicitly to switch the
        CMSIS-DAP firmware from default mode to JTAG mode.

        Protocol selection prefers 'dap_protocol' session option ('jtag' or 'cjtag')
        when set; otherwise auto-detects via probe firmware cJTAG capability (bit 9),
        falling back to classic JTAG.
        """
        from ...probe.debug_probe import DebugProbe

        protocol_name = self.session.options.get('dap_protocol').strip().lower()
        if protocol_name in ('jtag', 'cjtag'):
            protocol = DebugProbe.PROTOCOL_NAME_MAP[protocol_name]
            LOG.info("Connecting probe in %s mode for RISC-V debug (user specified)",
                     protocol_name.upper())
        else:
            protocol = DebugProbe.Protocol.JTAG
            if hasattr(self.session.probe, 'has_cjtag') and self.session.probe.has_cjtag:
                protocol = DebugProbe.Protocol.CJTAG
                LOG.info("Connecting probe in cJTAG mode for RISC-V debug (auto-detected)")
            else:
                LOG.info("Connecting probe in JTAG mode for RISC-V debug")

        self.session.probe.connect(protocol)

    def register_pre_hart_discover_hook(self, callback: Callable) -> None:
        """Register a callback to run before hart discovery.

        Called between DM capability detection and hart enumeration.
        Used for SoC-specific actions like releasing secondary cores
        from reset so they appear as available harts.
        """
        self._pre_hart_discover_hooks.append(callback)

    def get_hart_memory_map(self, hart_index: int) -> MemoryMap:
        """Return memory map for a specific hart.

        Default returns the shared SoC memory map. Override in targets
        where SBA uses hart-local addressing (e.g., some dual-core targets).
        """
        return self.memory_map

    def _debug_module_init(self) -> None:
        """Initialize DebugModule (DTM + DM + capabilities + hart discovery).

        DebugModule.init() performs DTM init (TAP reset, IDCODE, DTMCS), DM
        activation (dmactive=1, verify), capability detection (datacount,
        progbufsize, SBA), then hart discovery (hartsellen, enumerate, select
        hart 0).
        """
        LOG.info("Initializing RISC-V DebugModule")
        pre_hook = self._pre_hart_discover_hooks if self._pre_hart_discover_hooks else None
        self.dm.init(pre_hart_discover=pre_hook)

        caps = self.dm.capabilities
        LOG.info("DM capabilities: datacount=%d, progbufsize=%d, impebreak=%s, "
                 "has_sba=%s, hasresethaltreq=%s, num_harts=%d",
                 caps['datacount'], caps['progbufsize'], caps['impebreak'],
                 caps['has_sba'], caps['hasresethaltreq'], caps['num_harts'])

    def _create_cores(self) -> None:
        """Create RISCVCore instances for each discovered hart."""
        caps = self.dm.capabilities
        num_harts = caps['num_harts']

        for hart_index in range(num_harts):
            if not self.dm.hart_enabled(hart_index):
                LOG.debug("Hart %d: skipped (not enabled)", hart_index)
                continue

            core = RISCVCore(
                session=self.session,
                dm=self.dm,
                hart_id=hart_index,
                memory_map=self.memory_map,
                target=self,
            )

            # Use our custom debug context instead of default CachingDebugContext
            ctx = RiscvDebugContext(core)
            core.set_target_context(ctx)

            self.add_core(core)

            # Initialize core (register index, SW BP, trigger module discovery)
            core.init()

            LOG.info("Created core %d for hart %d", hart_index, hart_index)

    def add_core(self, core: CoreTarget) -> None:
        """Add a core without creating CachingDebugContext.

        Overrides SoCTarget.add_core() to preserve our RiscvDebugContext.
        The base class creates CachingDebugContext which hardcodes
        CortexMCoreRegisterInfo, incompatible with RISC-V registers.
        """
        core.delegate = self.delegate
        if self.debug_sequence_delegate:
            core.debug_sequence_delegate = self.debug_sequence_delegate
        # Skip CachingDebugContext creation - RiscvDebugContext already set
        self.cores[core.core_number] = core
        self.add_child(core)
        if self.selected_core is None:
            self.selected_core = core.core_number

    def _register_reset_hooks(self) -> None:
        """Register post-reset hooks on cores. Override in subclasses.

        Subclasses with SoC-specific reset requirements (e.g., releasing
        secondary cores held in reset after reset) should override this
        to call core.register_post_reset_hook() on the relevant cores.
        The hook is called in reset()/reset_and_halt() after clearing reset.
        """
        pass

    def _halt_on_connect(self) -> None:
        """Halt cores based on connect_mode setting."""
        try:
            connect_mode = self.session.options.get('connect_mode')
        except KeyError:
            connect_mode = 'default'

        if connect_mode in ('halt', 'default', 'pre-reset', 'under-reset'):
            for core_num, core in self.cores.items():
                try:
                    core.halt()
                    LOG.info("Halted core %d (connect_mode=%s)", core_num, connect_mode)
                except Exception as e:
                    LOG.warning("Failed to halt core %d: %s", core_num, e)

    def _init_core_triggers(self) -> None:
        """Initialize hardware triggers for all cores.

        Must run after halt_on_connect because trigger CSR access via
        abstract commands requires the hart to be halted.
        """
        for core_num, core in self.cores.items():
            try:
                core.init_triggers()
            except Exception as e:
                LOG.warning("Core %d trigger init failed: %s", core_num, e)

    def _pre_flash_init(self) -> None:
        """SoC-specific initialization before flash operations.

        Override in subclasses to enable clocks, configure peripherals,
        or perform other setup required before the flash controller
        can be used. Runs after halt and trigger init, before flash
        adapter creation.
        """
        pass

    def _create_flash(self) -> None:
        """Instantiate flash objects for memory regions with algo dicts.

        Iterates flash regions in the memory map and creates RiscvFlashAdapter
        instances for any region that has a flash algo dictionary defined.
        This is the RISC-V equivalent of CoreSightTarget.create_flash().

        For RISC-V targets, the flash_class defaults to RiscvFlashAdapter.
        Target definitions can override flash_class in the region attrs.
        """
        from ..flash.riscv_adapter import RiscvFlashAdapter

        for region in self.memory_map.iter_matching_regions(type=MemoryType.FLASH):
            if region.algo is None:
                continue

            flash_class = region.flash_class
            # Default to RiscvFlashAdapter if flash_class is the base Flash
            from ...flash.flash import Flash
            if flash_class is Flash:
                flash_class = RiscvFlashAdapter

            try:
                obj = flash_class(self, region.algo)
                obj.region = region
                region.flash = obj
                LOG.info("Flash region '%s': created %s at 0x%08x (%d bytes)",
                         region.name, flash_class.__name__,
                         region.start, region.length)
            except Exception as e:
                LOG.warning("Failed to create flash for region '%s': %s",
                            region.name, e)

    def _notify_connect(self) -> None:
        """Notify listeners that connection is complete."""
        self.session.notify(Target.Event.POST_CONNECT, self)

    def disconnect(self, resume: bool = True) -> None:
        """Disconnect from target.

        Args:
            resume: If True, resume all halted cores before disconnect
        """
        self.session.notify(Target.Event.PRE_DISCONNECT, self)

        for core_num, core in self.cores.items():
            try:
                core.disconnect(resume=resume)
            except Exception as e:
                LOG.warning("Error disconnecting core %d: %s", core_num, e)

    @property
    def supported_reset_types(self):
        """Delegate to first core's supported_reset_types.

        RISC-V reset is hart-level; the core knows which reset
        types are available via its debug hardware.
        """
        if self.cores:
            core = next(iter(self.cores.values()))
            return core.supported_reset_types
        return set()

    def _maybe_pulse_srst(self, reset_type: Optional[Target.ResetType]) -> None:
        """Pulse hardware SRST once per SoC reset if the resolved type is a
        hardware reset and the DM is SRST-eligible.

        Sets ``self.dm._srst_pulsed`` so the per-core ``reset()`` invoked via
        ``super().reset()`` skips its own SRST fire (dual-core must not
        double-pulse SRST on the same wire). The flag is cleared in the
        ``finally`` of the calling ``reset()`` / ``reset_and_halt()`` so the
        next SoC reset starts from a clean state even if this one raised.

        If ``selected_core`` is None (no core yet), return without pulsing to
        preserve the existing ``SoCTarget.reset`` no-core -> probe.reset path.
        """
        core = self.selected_core
        if core is None:
            return
        actual = core._get_actual_reset_type(reset_type)
        if (actual in (Target.ResetType.HARDWARE, Target.ResetType.NSRST)
                and self.dm.srst_eligible()):
            self.dm._srst_pulsed = False  # clear stale state from prior crash
            self.dm.perform_srst_prelude()
            self.dm._srst_pulsed = True

    def reset(self, reset_type: Optional[Target.ResetType] = None) -> None:
        """SoC-level reset: pulse hardware SRST once, then delegate to the
        per-core reset (ndmreset + post-hooks) via ``SoCTarget.reset``.
        """
        self._maybe_pulse_srst(reset_type)
        try:
            super().reset(reset_type)
        finally:
            self.dm._srst_pulsed = False

    def reset_and_halt(self, reset_type: Optional[Target.ResetType] = None) -> None:
        """SoC-level reset-and-halt: pulse hardware SRST once, then delegate
        to the per-core reset_and_halt via ``SoCTarget.reset_and_halt``.
        """
        self._maybe_pulse_srst(reset_type)
        try:
            super().reset_and_halt(reset_type)
        finally:
            self.dm._srst_pulsed = False

    @property
    def supported_security_states(self):
        """RISC-V does not use Arm security states."""
        return []
