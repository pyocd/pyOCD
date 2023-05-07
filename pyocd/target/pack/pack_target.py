# pyOCD debugger
# Copyright (c) 2017-2020 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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

from __future__ import annotations

import logging
import os
from typing import (cast, Callable, Dict, IO, Iterable, List, Optional, Set, Tuple, Type, Union, TYPE_CHECKING)


from .cmsis_pack import (CmsisPack, CmsisPackDevice, MalformedCmsisPackError)
from .reset_sequence_maps import (RESET_SEQUENCE_TO_TYPE_MAP, RESET_TYPE_TO_SEQUENCE_MAP)
from ..family import FAMILIES
from .. import (normalise_target_type_name, TARGET)
from ...core import exceptions
from ...core.target import Target
from ...coresight.ap import APv1Address
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM
from ...debug.sequences.delegates import DebugSequenceDelegate
from ...debug.sequences.functions import DebugSequenceCommonFunctions
from ...debug.sequences.sequences import (Block, DebugSequence, DebugSequenceExecutionContext)
from ...debug.sequences.scope import Scope
from ...debug.svd.loader import SVDFile
from ...core.session import Session
from ...probe.debug_probe import DebugProbe

if TYPE_CHECKING:
    from zipfile import ZipFile
    from cmsis_pack_manager import CmsisPackRef
    from ...utility.sequencer import CallSequence
    from ...core.core_target import CoreTarget
    from ...commands.execution_context import CommandSet
    from ...utility.notification import Notification

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
    def get_installed_packs(cache: Optional[cmsis_pack_manager.Cache] = None) -> List[CmsisPackRef]: # type:ignore
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
            try:
                pack_path = os.path.join(cache.data_path, pack.get_pack_name())
                pack = CmsisPack(pack_path)
                results += list(pack.devices)
            except Exception as err:
                LOG.error("failure to access managed CMSIS-Pack: %s",
                        err, exc_info=Session.get_current().log_tracebacks)
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

class PackDebugSequenceDelegate(DebugSequenceDelegate):
    """! @brief Main delegate for debug sequences."""

    ## Map from pyocd reset types to the __connection variable reset type field.
    #
    # 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
    RESET_TYPE_MAP = {
        Target.ResetType.HW: 1,
        Target.ResetType.SW: 2, # TODO pick default sw reset type
        Target.ResetType.SW_SYSRESETREQ: 2,
        Target.ResetType.SW_VECTRESET: 3,
        Target.ResetType.SW_EMULATED: 2, # no direct match
    }

    def __init__(self, target: CoreSightTarget, device: CmsisPackDevice) -> None:
        self._target = target
        self._session = target.session
        self._pack_device = device
        self._sequences: Set[DebugSequence] = device.sequences
        self._debugvars: Optional[Scope] = None
        self._functions = DebugSequenceCommonFunctions()

        self._session.options.subscribe(self._debugvars_did_change, 'pack.debug_sequences.debugvars')

    @property
    def all_sequences(self) -> Set[DebugSequence]:
        return self._sequences

    @property
    def cmsis_pack_device(self) -> CmsisPackDevice:
        """@brief Accessor for the pack device that contains the sequences."""
        return self._pack_device

    def get_root_scope(self, context: DebugSequenceExecutionContext) -> Scope:
        """@brief Return a scope that will be used as the parent of sequences."""
        # TODO should a fresh exec context be used? debugvars aren't supposed to depend on any
        # runtime debug settings nor do they even have access to those variables.
        if self._debugvars is not None:
            return self._debugvars

        # Populate a scope with definitions from the <debugvars> element, if defined. If not defined,
        # the the scope will be empty.
        self._debugvars = Scope(name="debugvars")
        debugvars_block = self._pack_device.debug_vars_sequence
        if debugvars_block is not None:
            # This is the only case where a Block will be pushed to the context stack.
            with context.push(debugvars_block, self._debugvars):
                debugvars_block.execute(context)

        # Now run the debugvars session option, if defined, as a block to override default
        # debugvars values from the <debugvars> element.
        debugvars_option = self._session.options.get('pack.debug_sequences.debugvars')
        if (debugvars_option is not None) and (debugvars_option.strip() != ""):
            debugvars_option_block = Block(debugvars_option)
            # This is the only case where a Block will be pushed to the context stack.
            with context.push(debugvars_option_block, self._debugvars):
                debugvars_option_block.execute(context)

        # Make all vars read-only.
        self._debugvars.freeze()

        # Debug log all debugvar values.
        if LOG.isEnabledFor(logging.INFO):
            for name in sorted(self._debugvars.variables):
                value = self._debugvars.get(name)
                LOG.info(f"debugvar '{name}' = {value:#x} ({value:d})")

        return self._debugvars

    def _debugvars_did_change(self, notification: Notification) -> None:
        """@brief Notification handler for change to pack.debug_sequences.debugvars option."""
        # Clear the cached debugvars scope to force it to be rebuilt.
        self._debugvars = None

    def _is_sequence_manually_disabled(self, name: str, pname: Optional[str] = None) -> bool:
        """@brief Check session options to see if the sequence has been disabled by the user."""
        disabled_seqs = self._session.options.get('pack.debug_sequences.disabled_sequences')
        if not disabled_seqs:
            return False

        name = name.casefold()
        if pname is not None:
            pname = pname.casefold()

        for dseq in disabled_seqs:
            if ':' in dseq:
                dseq, core_name = dseq.split(':')
                core_name = core_name.casefold()
            else:
                core_name = None
            dseq = dseq.casefold()

            if (name == dseq) and ((core_name is None) or (pname == core_name)):
                return True

        return False

    def run_sequence(self, name: str, pname: Optional[str] = None) -> Optional[Scope]:
        """@brief Run a top level debug sequence.

        @return The scope created while running the sequence is returned. If the sequence wasn't executed
            for some reason, e.g. it was disabled, then None is returned instead.
        """
        pname_desc = f" ({pname})" if (pname and LOG.isEnabledFor(logging.DEBUG)) else ""

        # Handle global debug sequence enable.
        if not self._session.options.get('pack.debug_sequences.enable'):
            LOG.debug("Not running debug sequence '%s'%s because all sequences are disabled",
                    name, pname_desc)
            return None

        # Error out for invalid sequence.
        if not self.has_sequence_with_name(name, pname):
            raise NameError(name)

        # Get the sequence object.
        seq = self.get_sequence_with_name(name, pname)

        # If the sequence is disabled, we won't run it.
        if not seq.is_enabled:
            LOG.debug("Not running disabled debug sequence '%s'%s", name, pname_desc)
            return None
        # Check for manual disabling of this sequence.
        if self._is_sequence_manually_disabled(name, pname):
            LOG.debug("Not running debug sequence '%s'%s because it was manually disabled", name, pname_desc)
            return None

        LOG.debug("Running debug sequence '%s'%s", name, pname_desc)

        # Create runtime context and contextified functions instance.
        context = DebugSequenceExecutionContext(self._session, self, pname)

        # Map optional pname to AP address. If the pname is not specified, then use the device's
        # first available AP. If no APs are known (eg haven't been discovered yet) then use 0.
        if pname:
            proc_map = self._pack_device.processors_map
            ap_address = proc_map[pname].ap_address
        else:
            ap = self._target.first_ap
            if ap is not None:
                ap_address = ap.address
            else:
                ap_address = APv1Address(0)

        # Set the default AP in the exec context.
        context.default_ap = ap_address

        # Activate the context while running this sequence, making the context available
        # to sequence functions.
        with context:
            try:
                executed_scope = seq.execute(context)
            except exceptions.Error as err:
                if pname:
                    LOG.error("Error while running debug sequence '%s' (core %s): %s", name, pname, err)
                else:
                    LOG.error("Error while running debug sequence '%s': %s", name, err)
                raise

        return executed_scope

    def sequences_for_pname(self, pname: Optional[str]) -> Dict[str, DebugSequence]:
        # Return *only* sequences with no Pname when passed pname=None. Otherwise we'd have
        # to mangle the dict keys to include pname since there can be multiple sequences with
        # the same name but different
        return {
            seq.name: seq
            for seq in self._sequences
            if (seq.pname is None) or (seq.pname == pname)
        }

    def has_sequence_with_name(self, name: str, pname: Optional[str] = None) -> bool:
        return name in self.sequences_for_pname(pname)

    def get_sequence_with_name(self, name: str, pname: Optional[str] = None) -> DebugSequence:
        return self.sequences_for_pname(pname)[name]

    def get_protocol(self) -> int:
        """@brief Return the value for the __protocol variable.
        __protocol fields:
        - [15:0] 0=error, 1=JTAG, 2=SWD, 3=cJTAG
        - [16] SWJ-DP present?
        - [17] switch through dormant state?
        """
        session = self._target.session
        assert session.probe, "must have a valid probe"
        # Not having a wire protocol set is allowed if performing pre-reset since it will only
        # execute ResetHardware (or equivalent), which can only access pins and such (theoretically).
        assert self._session.context_state.is_performing_pre_reset or session.probe.wire_protocol, \
            "must have valid, connected probe"
        if session.probe.wire_protocol == DebugProbe.Protocol.JTAG:
            protocol = 1
        elif session.probe.wire_protocol == DebugProbe.Protocol.SWD:
            protocol = 2
        else:
            protocol = 0 # Error
        if session.options.get('dap_swj_enable'):
            protocol |= 1 << 16
        if session.options.get('dap_swj_use_dormant'):
            protocol |= 1 << 17
        return protocol

    def get_connection_type(self) -> int:
        """@brief Return the value for the __connection variable.
        __connection fields:
        - [7:0] connection type: 0=error/disconnected, 1=for debug, 2=for flashing
        - [15:8] reset type: 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
        - [16] connect under reset?
        - [17] pre-connect reset?
        """
        ctype = 1
        ctype |= self.RESET_TYPE_MAP.get(self._session.options.get('reset_type'), 0) << 8

        connect_mode = self._target.session.options.get('connect_mode')
        if connect_mode == 'under-reset':
            ctype |= 1 << 16

        # The pre-reset bit should only be set when running ResetHardware for a connect pre-reset.
        # This is stored in the is_performing_pre_reset session state variable, set by CoreSightTarget's
        # pre_connect() method.
        if self._session.context_state.is_performing_pre_reset:
            ctype |= 1 << 17
        return ctype

    def get_traceout(self) -> int:
        """@brief Return the value for the __traceout variable.
        __traceout fields:
        - [0] SWO enabled?
        - [1] parallel trace enabled?
        - [2] trace buffer enabled?
        - [21:16] selected parallel trace port size
        """
        # Set SWO bit depending on the option value.
        return 1 if self._target.session.options.get('enable_swv') else 0

    def get_sequence_functions(self) -> DebugSequenceCommonFunctions:
        return self._functions

class _PackTargetMethods:
    """@brief Container for methods added to the dynamically generated pack target subclass.

    We can't just make a subclass of CoreSightTarget out of these methods, because the superclass
    is variable based on the possible family class.
    """

    @staticmethod
    def _pack_target__init__(self, session: Session) -> None: # type:ignore
        """@brief Constructor for dynamically created target class."""
        super(self.__class__, self).__init__(session, self._pack_device.memory_map)

        self.vendor = self._pack_device.vendor
        self.part_families = self._pack_device.families
        self.part_number = self._pack_device.part_number

        self._svd_location = SVDFile(filename=self._pack_device.svd)

        self.debug_sequence_delegate = PackDebugSequenceDelegate(self, self._pack_device)

    @staticmethod
    def _pack_target_create_init_sequence(self) -> CallSequence: # type:ignore
        """@brief Creates an init task to set the default reset type."""
        seq = super(self.__class__, self).create_init_sequence()

        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_cores',
                            ('configure_core_reset', self.configure_core_reset)
                            )
            )
        return seq

    @staticmethod
    def _pack_target_configure_core_reset(self) -> None: # type:ignore
        """@brief Init sequence method to configure resets for all cores.

        This init sequence method is designed to run after the cores have been created by standard
        discovery.

        Sets each core's default reset type to the one specified in the pack, and configures the
        list of enabled reset types.
        """
        for core_num, core in self.cores.items():
            # Look up the processor info for this core.
            core_ap_addr = core.ap.address
            try:
                proc_info = self._pack_device.processors_ap_map[core_ap_addr]
            except KeyError:
                LOG.debug("core #%d not specified in DFP", core_num)
                continue

            # Get this processor's list of sequences.
            sequences = self.debug_sequence_delegate.sequences_for_pname(proc_info.name)

            def is_reset_sequence_enabled(name: str) -> bool:
                return (name not in sequences) or sequences[name].is_enabled

            # Set the supported reset types by filtering existing supported reset types.
            updated_reset_types: Set[Target.ResetType] = set()
            for resettype in core._supported_reset_types:
                # These two types are not in the map, and should always be present.
                if resettype in (Target.ResetType.SW, Target.ResetType.SW_EMULATED):
                    updated_reset_types.add(resettype)
                    continue

                resettype_sequence_name = RESET_TYPE_TO_SEQUENCE_MAP[resettype]
                if is_reset_sequence_enabled(resettype_sequence_name):
                    updated_reset_types.add(resettype)

            # Special case to enable processor reset even when the core doesn't support VECTRESET, if
            # there is a non-default ResetProcessor sequence definition.
            if ((Target.ResetType.SW_CORE not in updated_reset_types) # type:ignore
                    and ('ResetProcessor' in sequences)
                    and sequences['ResetProcessor'].is_enabled):
                updated_reset_types.add(Target.ResetType.SW_CORE) # type:ignore

            core._supported_reset_types = updated_reset_types
            LOG.debug(f"updated DFP core #{core_num} reset types: {core._supported_reset_types}")

            default_reset_seq = proc_info.default_reset_sequence

            # Check that the default reset sequence is a standard sequence. The specification allows for
            # custom reset sequences to be used, but that is not supported by pyocd yet.
            # TODO support custom default reset sequences (requires a new reset type)
            if default_reset_seq not in RESET_SEQUENCE_TO_TYPE_MAP:
                if default_reset_seq in sequences:
                    # Custom reset sequence, not yet supported by pyocd.
                    LOG.warning("DFP device definition error: custom reset sequences are not yet supported "
                                "by pyocd; core #%d (%s) requested default reset sequence %s",
                                core_num, proc_info.name, default_reset_seq)
                else:
                    # Invalid/unknown default reset sequence.
                    LOG.warning("DFP device definition error: specified default reset sequence %s "
                                "for core #%d (%s) does not exist",
                                default_reset_seq, core_num, proc_info.name)

            # Handle multicore debug mode causing secondary cores to default to processor reset.
            did_force_core_reset = False
            if (self.session.options.get('enable_multicore_debug')
                    and (core_num != self.session.options.get('primary_core'))):
                if not is_reset_sequence_enabled('ResetProcessor'):
                    LOG.warning("Multicore debug mode cannot select processor reset for secondary core "
                                "#%d (%s) because it is disabled by the DFP; using emulated processor "
                                "reset instead", core_num, proc_info.name)
                    core.default_reset_type = Target.ResetType.SW_EMULATED
                    continue
                else:
                    default_reset_seq = 'ResetProcessor'
                    did_force_core_reset = True

            # Verify that the specified default reset sequence hasn't been disabled.
            if not is_reset_sequence_enabled(default_reset_seq):
                # Only log a warning if we didn't decide to use core reset due to multicore mode.
                if not did_force_core_reset:
                    LOG.warning("DFP device definition conflict: specified default reset sequence %s "
                            "for core #%d (%s) is disabled by the DFP",
                            default_reset_seq, core_num, proc_info.name)

                # Map from disabled default to primary and secondary fallbacks.
                RESET_FALLBACKS: Dict[str, Tuple[str, str]] = {
                    'ResetSystem':      ('ResetProcessor', 'ResetHardware'),
                    'ResetHardware':    ('ResetSystem', 'ResetProcessor'),
                    'ResetProcessor':   ('ResetSystem', 'ResetHardware'),
                }

                # Select another default.
                fallbacks = RESET_FALLBACKS[default_reset_seq]
                if is_reset_sequence_enabled(fallbacks[0]):
                    default_reset_seq = fallbacks[0]
                elif is_reset_sequence_enabled(fallbacks[1]):
                    default_reset_seq = fallbacks[1]
                else:
                    LOG.warning("DFP device definition conflict: all reset types are disabled for "
                            "core #%d (%s) by the DFP; using emulated core reset",
                            default_reset_seq, core_num)
                    core.default_reset_type = Target.ResetType.SW_EMULATED
                    continue

            LOG.info("Setting core #%d (%s) default reset sequence to %s",
                    core_num, proc_info.name, default_reset_seq)
            core.default_reset_type = RESET_SEQUENCE_TO_TYPE_MAP[default_reset_seq]

    @staticmethod
    def _pack_target_add_core(_self, core: CoreTarget) -> None:
        """@brief Override to set node name of added core to its pname."""
        pname = _self._pack_device.processors_ap_map[cast(CortexM, core).ap.address].name
        core.node_name = pname
        CoreSightTarget.add_core(_self, core)

    @staticmethod
    def _pack_target_add_target_command_groups(_self, command_set: CommandSet):
        """@brief Add pack related commands to the command set."""
        command_set.add_command_group('pack-target')


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
                    LOG.debug("using family class %s for %s (matched against %s)",
                            familyInfo.klass.__name__, dev.part_number, compare_name)
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
                        "configure_core_reset": _PackTargetMethods._pack_target_configure_core_reset,
                        "add_core": _PackTargetMethods._pack_target_add_core,
                        "add_target_command_groups": _PackTargetMethods._pack_target_add_target_command_groups,
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
            # Check if we're even going to populate this target before bothing to build the class.
            part = normalise_target_type_name(dev.part_number)
            if part in TARGET:
                LOG.debug("did not populate target for DFP part number %s because there is already "
                        "a %s target installed", dev.part_number, part)
                return

            # Generate target subclass and install it.
            tgt = PackTargets._generate_pack_target_class(dev)
            if tgt:
                TARGET[part] = tgt
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
            pack_list = [pack_list] # type:ignore
        for pack_or_path in pack_list: # type:ignore
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

def is_pack_target_available(target_name: str, session: Session) -> bool:
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


