# pyOCD debugger
# Copyright (c) 2025 Arm Limited
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
import yaml
import os
import io
import platform

from pathlib import Path
from copy import deepcopy
from dataclasses import dataclass
from typing import (cast, Optional, Set, Dict, List, Tuple, IO, Any)
from .flash_algo import PackFlashAlgo
from .reset_sequence_maps import (RESET_SEQUENCE_TO_TYPE_MAP, RESET_TYPE_TO_SEQUENCE_MAP)
from .. import (normalise_target_type_name, TARGET)
from ...coresight.cortex_m import CortexM
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.ap import (APAddressBase, APv1Address, APv2Address)
from ...core import exceptions
from ...core.target import Target
from ...core.session import Session
from ...core.core_target import CoreTarget
from ...core.memory_map import (MemoryMap, MemoryType, MEMORY_TYPE_CLASS_MAP)
from ...utility.sequencer import CallSequence
from ...probe.debug_probe import DebugProbe
from ...debug.svd.loader import SVDFile
from ...debug.sequences.scope import Scope
from ...debug.sequences.delegates import DebugSequenceDelegate
from ...debug.sequences.functions import DebugSequenceCommonFunctions
from ...debug.sequences.sequences import (
    Block,
    DebugSequence,
    DebugSequenceNode,
    IfControl,
    WhileControl,
    DebugSequenceExecutionContext
)

LOG = logging.getLogger(__name__)

class CbuildRunError(exceptions.Error):
    """Custom exception for errors encountered during processing of .cbuild-run.yml"""
    pass

@dataclass
class ProcessorInfo:
    """@brief Descriptor for a processor defined in a DFP."""
    ## The Pname attribute, or Dcore if not Pname was provided.
    name: str = "Unknown"
    ## PE unit number within an MPCore. For single cores this will be 0.
    unit: int = 0
    ## Total number of cores in an MPCore.
    total_units: int = 1
    ## Address of AP through which the PE can be accessed.
    ap_address: APAddressBase = APv1Address(-1)
    ## Base address of the PE's memory mapped debug registers. Not used and 0 for M-profile.
    address: int = 0
    ## SVD file path relative to the pack.
    svd_path: Optional[str] = None
    ## Default reset sequence name.
    default_reset_sequence: str = "ResetSystem"


class CbuildRunTargetMethods:
    """@brief Namespace of static methods to dynamically configure CoreSight targets.

    These methods are used to generate and initialize runtime targets from a .cbuild-run.yml file,
    including memory mapping, core reset configuration, and processor name updates.
    """
    @staticmethod
    def _cbuild_target_init(self, session: Session) -> None:
        """@brief Initializes a target dynamically based on a parsed .cbuild-run.yml description.

        Sets memory maps, SVD files, and debug sequence delegates.
        """
        super(self.__class__, self).__init__(session, self._cbuild_device.memory_map)
        self.vendor = self._cbuild_device.vendor
        self.part_number = self._cbuild_device.target
        self._svd_location = SVDFile(filename=self._cbuild_device.svd)
        self.debug_sequence_delegate = CbuildRunDebugSequenceDelegate(self, self._cbuild_device)

    @staticmethod
    def _cbuild_target_create_init_sequence(self) -> CallSequence:
        """@brief Creates an initialization call sequence for runtime-configured targets.

        Extends the standard discovery sequence to configure processor names
        and reset behavior after core discovery.
        """
        seq = super(self.__class__, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_cores',
                            ('update_processor_name', self.update_processor_name),
                            ('update_primary_core', self.update_primary_core),
                            ('configure_core_reset', self.configure_core_reset)
                            )
            )
        return seq

    @staticmethod
    def _cbuild_target_update_processor_name(self) -> None:
        """@brief Updates processor names post-discovery based on Access Port (AP) addresses.

        Maps discovered cores to known processors to ensure consistent naming.
        """
        processors_map = {}
        for core in self.cores.values():
            if core.node_name is None or core.node_name == 'Unknown':
                core.node_name = core.name

            for proc in self._cbuild_device.processors_map.values():
                if ('Unknown' in proc.name) and (proc.ap_address == core.ap.address):
                    proc.name = core.name
                    processors_map[core.name] = proc
                    break

            if LOG.isEnabledFor(logging.INFO):
                core_info = f"core {core.core_number}: {core.name} r{core.cpu_revision}p{core.cpu_patch}"
                if core.node_name != core.name:
                    core_info += f", pname: {core.node_name}"
                LOG.info(core_info)

        if processors_map:
            self._cbuild_device.processors_map = processors_map

    @staticmethod
    def _cbuild_target_start_processor(self) -> None:
        """@brief Updates the primary processor, based on 'start-pname' node in .cbuild-run.yml"""
        start_pname = self._cbuild_device.start_pname
        if start_pname is not None and self.primary_core_pname != start_pname:
            core_number = next((core.core_number for core in self.cores.values() if core.node_name == start_pname), None)
            if core_number is not None:
                self.session.options['primary_core'] = core_number
                self.selected_core = core_number

    @staticmethod
    def _cbuild_target_configure_core_reset(self) -> None:
        """@brief Configures supported and default reset types for each core.

        Based on the debug sequences defined in the .cbuild-run.yml, updates each core's
        reset capabilities and selects fallback mechanisms if needed.
        """
        for core_num, core in self.cores.items():
            core_ap_addr = core.ap.address
            try:
                proc_info = self._cbuild_device.processors_ap_map[core_ap_addr]
            except KeyError:
                LOG.debug("core %d not specified", core_num)
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
            LOG.debug("Updated core %d reset types: %s", core_num, core._supported_reset_types)

            default_reset_seq = proc_info.default_reset_sequence

            # Check that the default reset sequence is a standard sequence. The specification allows for
            # custom reset sequences to be used, but that is not supported by pyocd yet.
            # TODO support custom default reset sequences (requires a new reset type)
            if default_reset_seq not in RESET_SEQUENCE_TO_TYPE_MAP:
                if default_reset_seq in sequences:
                    # Custom reset sequence, not yet supported by pyocd.
                    LOG.warning("DFP device definition error: custom reset sequences are not yet supported "
                                "by pyocd; core %d requested default reset sequence %s",
                                core_num, default_reset_seq)
                else:
                    # Invalid/unknown default reset sequence.
                    LOG.warning("DFP device definition error: specified default reset sequence %s "
                                "for core %d does not exist",
                                default_reset_seq, core_num)

            # Handle multicore debug mode causing secondary cores to default to processor reset.
            did_force_core_reset = False
            if (self.session.options.get('enable_multicore_debug')
                    and (core_num != self.session.options.get('primary_core'))):
                if not is_reset_sequence_enabled('ResetProcessor'):
                    LOG.warning("Multicore debug mode cannot select processor reset for secondary core "
                                "%d because it is disabled by the DFP; using emulated processor "
                                "reset instead", core_num)
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
                            "for core #%d is disabled by the DFP",
                            default_reset_seq, core_num)

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
                            "core %d by the DFP; using emulated core reset",
                            default_reset_seq, core_num)
                    core.default_reset_type = Target.ResetType.SW_EMULATED
                    continue

            LOG.debug("Setting core %d default reset sequence to %s", core_num, default_reset_seq)
            core.default_reset_type = RESET_SEQUENCE_TO_TYPE_MAP[default_reset_seq]

    @staticmethod
    def _cbuild_target_add_core(_self, core: CoreTarget) -> None:
        """@brief Override to set node name of added core to its pname."""
        pname = _self._cbuild_device.processors_ap_map[cast(CortexM, core).ap.address].name
        core.node_name = pname
        CoreSightTarget.add_core(_self, core)

    @staticmethod
    def _cbuild_target_get_gdbserver_port(self, pname: str) -> Optional[int]:
        """@brief GDB Server port for processor name."""
        assert pname
        server_map = self._cbuild_device.debugger.get('gdbserver', [])
        if any('pname' in server for server in server_map):
            port = next((i['port'] for i in server_map if i.get('pname') == pname), None)
        else:
            port = next((i['port'] for i in server_map), None)
        return port

    @staticmethod
    def _cbuild_target_get_output(self) -> Dict[str, Optional[int]]:
        return self._cbuild_device.output


class CbuildRun:
    """@brief Parser for the .cbuild-run.yml file (CSolution Run and Debug Management)."""
    def __init__(self, yml_path: str) -> None:
        """@brief Reads a .cbuild-run.yml file and validates its content."""
        self._data: Dict[str, Any] = {}
        self._valid: bool = False
        self._device: Optional[str] = None
        self._vendor: Optional[str] = None
        self._vars: Optional[Dict[str, str]] = None
        self._sequences: Optional[List[dict]] = None
        self._debugger: Optional[Dict[str, Any]] = None
        self._debug_topology: Optional[Dict[str, Any]] = None
        self._memory_map: Optional[MemoryMap] = None
        self._programming: Optional[List[dict]] = None
        self._valid_dps: List[int] = []
        self._apids: Dict[int, APAddressBase] = {}
        self._uses_apv2: bool = False
        self._built_apid_map: bool = False
        self._processors_map: Dict[str, ProcessorInfo] = {}
        self._processors_ap_map: Dict[APAddressBase, ProcessorInfo] = {}
        self._use_default_memory_map: bool = True
        self._system_resources: Optional[Dict[str, list]] = None
        self._system_descriptions: Optional[List[dict]] = None
        self._device_pack: Optional[List[str]] = None

        try:
            # Normalize the path to ensure compatibility across platforms.
            yml_path = os.path.normpath(yml_path)
            with open(yml_path, 'r') as yml_file:
                yml_data = yaml.safe_load(yml_file)
            if 'cbuild-run' in yml_data:
                self._data = yml_data['cbuild-run']
                self._cmsis_pack_root()
                self._valid = True
            else:
                raise CbuildRunError(f"Invalid .cbuild-run.yml file '{yml_path}'")
            # Set cbuild-run path as the current working directory.
            base_path = Path(yml_path).parent
            os.chdir(base_path)
            LOG.debug("Working directory set to: '%s'", os.getcwd())
        except IOError as err:
            LOG.error("Error attempting to access .cbuild-run.yml file '%s': %s", yml_path, err)

    def _cmsis_pack_root(self) -> None:
        """@brief Sets the CMSIS_PACK_ROOT environment variable if not already set.

        Platform dependant default values are defined in:
        https://open-cmsis-pack.github.io/cmsis-toolbox/installation/#environment-variables
        """
        # Check if the CMSIS_PACK_ROOT environment variable is already set.
        # This variable specifies the root directory for CMSIS packs, which are essential for device support.
        if 'CMSIS_PACK_ROOT' in os.environ:
            return

        # Get the system platform
        system = platform.system()

        # Set the CMSIS_PACK_ROOT environment variable based on the platform
        if system == 'Windows':
            # Windows detected, set the Windows default path
            os.environ['CMSIS_PACK_ROOT'] = os.path.expandvars("${LOCALAPPDATA}\\Arm\\Packs")
        elif system in {'Linux', 'Darwin'}:
            # Note: WSL is treated as 'Linux'
            # Linux or macOS detected, set the Linux/macOS default path
            os.environ['CMSIS_PACK_ROOT'] = os.path.expandvars("${HOME}/.cache/arm/packs")
        else:
            raise CbuildRunError(f"Unsupported platform '{system}' for CMSIS_PACK_ROOT. "
                                 "Please set the CMSIS_PACK_ROOT environment variable manually.")
        LOG.debug("CMSIS_PACK_ROOT set to: '%s'", os.environ['CMSIS_PACK_ROOT'])

    @property
    def target(self) -> str:
        """@brief Target identifier string.

        Read `device` field from .cbuild-run.yml file, without 'vendor'.
        """
        if self._device is None:
            device = self._data.get('device', '')
            self._device = device.split('::')[1] if '::' in device else device
            LOG.info("Target device: %s", self._device)
        return self._device

    @property
    def part_number(self) -> str:
        return self.target

    @property
    def vendor(self) -> str:
        """@brief Vendor identifier string.

        Read 'vendor' part of `device` field from .cbuild-run.yml file.
        """
        if self._vendor is None:
            device = self._data.get('device', '')
            self._vendor = device.split('::')[0] if '::' in device else ''
            LOG.debug("Vendor: %s", self._vendor)
        return self._vendor

    @property
    def families(self) -> List[str]:
        """@brief List of target device families.

        Currently unsupported in cbuild-run. Returns an empty list.
        """
        return []

    @property
    def memory_map(self) -> MemoryMap:
        """@brief Returns the parsed memory map for the device.

        Memory regions are constructed by merging default maps with user-defined regions,
        and flash algorithms are applied where appropriate.
        """
        if self._memory_map is None:
            self._build_memory_map()
        return self._memory_map

    @property
    def svd(self) -> Optional[IO[bytes]]:
        """@brief File-like object for the device's SVD file."""
        #TODO handle multicore devices
        try:
            for desc in self.system_descriptions:
                if desc['type'] == 'svd':
                    norm_path = os.path.normpath(desc['file'])
                    svd_path = Path(os.path.expandvars(norm_path))
                    LOG.debug("SVD path: %s", svd_path)
                    return io.BytesIO(svd_path.read_bytes())
        except (KeyError, IndexError):
            LOG.error("Could not locate SVD in cbuild-run system-descriptions.")
        return None

    @property
    def output(self) -> Dict[str, Optional[int]]:
        """@brief Set of loadable output files (file, offset)."""
        if not self._valid:
            return {}

        # Supported loadable files
        f_type = {'elf', 'hex', 'bin'}

        # Filter only loadable supported files from the output node
        loadable_files = [f for f in self._data.get('output', [])
                          if 'image' in f.get('load', '') and f.get('type') in f_type]

        load_files = {}
        for f in loadable_files:
            # Get load offset (None if not specified)
            offset = f.get('load-offset')
            # Add filename and it's offset to return value
            load_files[f['file']] = offset
            LOG.debug("Loadable file: %s", f['file'])
        return load_files

    @property
    def debug_sequences(self) -> List[dict]:
        """@brief Debug sequences node."""
        if self._sequences is None:
            self._sequences = self._data.get('debug-sequences', [])
            LOG.debug("Read %d debug sequences", len(self._sequences))
        return self._sequences

    @property
    def debug_vars(self) -> Dict[str, str]:
        """@brief Debug variables."""
        if self._vars is None:
            self._vars = self._data.get('debug-vars', {})
            LOG.debug("Read debug variables")
        return self._vars

    @property
    def valid_dps(self) -> List[int]:
        """@brief List of valid debug ports."""
        if not self._valid_dps:
            self._build_aps_map()
        return self._valid_dps

    @property
    def uses_apid(self) -> bool:
        """@brief Accessport V2 apid is used."""
        if not self._built_apid_map:
            self._build_aps_map()
        return self._uses_apv2

    @property
    def apid_map(self) -> Dict[int, APAddressBase]:
        """@brief Map of apid and AP address objects."""
        if not self._built_apid_map:
            self._build_aps_map()
        return self._apids

    @property
    def processors_map(self) -> Dict[str, ProcessorInfo]:
        """@brief Map of processor names and processor info objects."""
        if not self._processors_map:
            self._build_aps_map()
        return self._processors_map

    @processors_map.setter
    def processors_map(self, proc_map: Dict[str, ProcessorInfo]) -> None:
        self._processors_map = proc_map
        LOG.debug("Updated processors map")

    @property
    def processors_ap_map(self) -> Dict[APAddressBase, ProcessorInfo]:
        """@brief Map of AP address objects and processor info objects."""
        if not self._processors_ap_map:
            self._processors_ap_map = {
                proc.ap_address: proc
                for proc in self.processors_map.values()
            }
        return self._processors_ap_map

    @property
    def programming(self) -> List[dict]:
        """@brief Programming section of cbuild-run."""
        if self._programming is None:
            self._programming = self._data.get('programming', [])
            LOG.debug("Read %d programming algorithms", len(self._programming))
        return self._programming

    @property
    def debugger(self) -> Dict[str, Any]:
        """@brief Debugger section of cbuild-run."""
        if self._debugger is None:
            self._debugger = self._data.get('debugger', {})
            LOG.debug("Read debugger configuration: %s", self._debugger)
        return self._debugger

    @property
    def debugger_clock(self) -> Optional[int]:
        """@brief Debugger clock frequency in Hz."""
        _debugger_clock = self.debugger.get('clock')
        if _debugger_clock is not None:
            LOG.debug("Debugger clock frequency: %s Hz", _debugger_clock)
        return _debugger_clock

    @property
    def start_pname(self) -> Optional[str]:
        """@brief Selected start processor name."""
        _start_pname = self.debugger.get('start-pname')
        if _start_pname is not None:
           LOG.info("start-pname: %s", _start_pname)
        return _start_pname

    @property
    def system_resources(self) -> Dict[str, list]:
        """@brief System Resources section of cbuild-run."""
        if self._system_resources is None:
            self._system_resources = self._data.get('system-resources', {})
            LOG.debug("Read system resources")
        return self._system_resources

    @property
    def system_descriptions(self) -> List[dict]:
        """@brief System Descriptions section of cbuild-run."""
        if self._system_descriptions is None:
            self._system_descriptions = self._data.get('system-descriptions', [])
            LOG.debug("Read system description files")
        return self._system_descriptions

    @property
    def debug_topology(self) -> Dict[str, Any]:
        """@brief Debug Topology section of cbuild-run."""
        if self._debug_topology is None:
            self._debug_topology = self._data.get('debug-topology', {})
            LOG.debug("Read debug topology")
        return self._debug_topology

    @property
    def device_pack(self) -> List[str]:
        """@brief Value of 'device-pack' (DFP) prefixed with CMSIS_PACK_ROOT."""
        if self._device_pack is None:
            if 'device-pack' in self._data:
                vendor, _pack = self._data['device-pack'].split('::', 1)
                name, version = _pack.split('@', 1)
                pack = os.path.normpath(f"${{CMSIS_PACK_ROOT}}/{vendor}/{name}/{version}")
                self._device_pack = [os.path.expandvars(pack)]
            else:
                self._device_pack = []
            LOG.debug("Device pack: %s", self._device_pack)
        return self._device_pack

    def populate_target(self, target: Optional[str] = None) -> None:
        """@brief Generates and populates the target defined by the .cbuild-run.yml file."""
        if not self._valid:
            return

        if target is None:
            target = normalise_target_type_name(self.target)
        elif target != normalise_target_type_name(self.target):
            return

        # Check if we're overwriting an existing target.
        if target in TARGET:
            LOG.info("Internal target %s already exists, overwriting with cbuild-run target", target)

        # Generate target subclass and install it.
        tgt = type(target.capitalize(), (CoreSightTarget,), {
                    "_cbuild_device": self,
                    "debugger_clock": self.debugger_clock,
                    "__init__": CbuildRunTargetMethods._cbuild_target_init,
                    "create_init_sequence": CbuildRunTargetMethods._cbuild_target_create_init_sequence,
                    "update_processor_name" : CbuildRunTargetMethods._cbuild_target_update_processor_name,
                    "update_primary_core" : CbuildRunTargetMethods._cbuild_target_start_processor,
                    "configure_core_reset": CbuildRunTargetMethods._cbuild_target_configure_core_reset,
                    "add_core": CbuildRunTargetMethods._cbuild_target_add_core,
                    "get_gdbserver_port": CbuildRunTargetMethods._cbuild_target_get_gdbserver_port,
                    "get_output": CbuildRunTargetMethods._cbuild_target_get_output
        })
        TARGET[target] = tgt

    def _get_memory_to_process(self) -> List[dict]:
        DEFAULT_MEMORY_MAP = sorted([
            {"name": "Code",                 "access": "rx",  "start": 0x00000000, "size": 0x20000000},
            {"name": "SRAM",                 "access": "rwx", "start": 0x20000000, "size": 0x20000000},
            {"name": "Peripherals",          "access": "rwp", "start": 0x40000000, "size": 0x20000000},
            {"name": "RAM1",                 "access": "rwx", "start": 0x60000000, "size": 0x20000000},
            {"name": "RAM2",                 "access": "rwx", "start": 0x80000000, "size": 0x20000000},
            {"name": "Devices-Shareable",    "access": "rwp", "start": 0xA0000000, "size": 0x20000000},
            {"name": "Devices-NonShareable", "access": "rwp", "start": 0xC0000000, "size": 0x20000000},
            {"name": "System-Peripherals",   "access": "rwp", "start": 0xE0000000, "size": 0x20000000}
        ], key=lambda mem: mem['start'])

        def _fill_memory_gap(region: dict, start: int, end: int) -> dict:
            _memory = region.copy()
            _memory['start'] = start
            _memory['size'] = end - start
            return _memory

        # Create a copy of PDSC and user-defined memory regions from system resources
        defined_memory = deepcopy(self.system_resources.get('memory', []))
        LOG.debug("Read defined memory regions")
        # Mark memory as 'defined'
        for memory in defined_memory:
            memory['defined'] = True
        # Filter out memory regions that have alias and start at the same address ('s'/'n' access)
        alias_memory = {(m['alias'], m['start']) for m in defined_memory if 'alias' in m}
        if alias_memory:
            defined_memory = [m for m in defined_memory if (m['name'], m['start']) not in alias_memory]
        # Check if default memory map should be used
        if self._use_default_memory_map:
            # If no user-defined memory is present, use only the default memory map
            if not defined_memory:
                memory_to_process = DEFAULT_MEMORY_MAP
            else:
                memory_to_process = []
                # Sort PDSC and user-defined memory by start address
                defined_memory.sort(key=lambda mem: mem['start'])
                # Get first defined memory
                mem_iter = iter(defined_memory)
                memory = next(mem_iter, None)
                # Start from beginning of the address space
                next_memory_start = 0x00000000
                # Loop over the default memory regions
                for default_memory in DEFAULT_MEMORY_MAP:
                    default_memory_end = default_memory['start'] + default_memory['size']
                    # Search for region overlaps with PDSC and user-defined memory regions
                    while next_memory_start < default_memory_end:
                        if memory is not None:
                            # Exact match: insert defined memory region
                            if next_memory_start == memory['start']:
                                memory.pop('pname', None)
                                memory_to_process.append(memory)
                                next_memory_start = memory['start'] + memory['size']
                                while memory is not None and memory['start'] < next_memory_start:
                                    memory = next(mem_iter, None)
                                continue
                            # Partial overlap: fill gap to next defined memory region with default memory region
                            if next_memory_start <= memory['start'] < default_memory_end:
                                _memory = _fill_memory_gap(default_memory, next_memory_start, memory['start'])
                                memory_to_process.append(_memory)
                                next_memory_start = memory['start']
                                continue
                        # No region overlap: use default memory region
                        _memory = _fill_memory_gap(default_memory, next_memory_start, default_memory_end)
                        memory_to_process.append(_memory)
                        next_memory_start = default_memory_end
            return memory_to_process
        else:
            # If default map is not used, return only PDSC and user-defined memory regions
            return defined_memory

    def _build_memory_map(self) -> None:
        """@brief Constructs the device's memory map including flash and RAM segmentation.

        Processes defined regions, fills gaps, and handles flash algorithm overlays.
        """
        regions = []
        memory_to_process = self._get_memory_to_process()

        def _memory_slice(memory: dict, start: int, size: int) -> None:
            # Create a copy of current memory and amend region start and length
            # and add updated memory to list of memories to process.
            _memory = memory.copy()
            _memory['start'] = start
            _memory['size'] = size
            memory_to_process.append(_memory)

        while memory_to_process:
            memory = memory_to_process.pop()
            # Determine memory type based on access permissions
            if 'p' in memory['access']:
                memory_type = MemoryType.DEVICE
            elif 'w' in memory['access']:
                memory_type = MemoryType.RAM
            else:
                memory_type = MemoryType.ROM

            # Define attributes for memory region
            attrs = {
                'name': memory['name'],
                'start': memory['start'],
                'length': memory['size'],
                'access': memory['access'],
                'pname': memory.get('pname'),
                'alias': memory.get('alias'),
            }

            if memory.get('defined', False):
                for algorithm in self.programming:
                    if 'pname' in memory and 'pname' in algorithm:
                        if memory['pname'] != algorithm['pname']:
                            # Skip this algorithm if 'Pname' exists and does not match
                            continue

                    memory_end = memory['start'] + memory['size']
                    algorithm_end = algorithm['start'] + algorithm['size']

                    if (memory['start'] < algorithm_end) and (algorithm['start'] < memory_end):
                        # Create a local copy of attributes
                        flash_attrs = attrs.copy()
                        # If memory region and algorithm overlap, classify this part of region as FLASH
                        memory_type = MemoryType.FLASH
                        # Split memory into covered and uncovered section
                        flash_start = max(memory['start'], algorithm['start'])
                        flash_end = min(memory_end, algorithm_end)
                        if memory['start'] < algorithm['start']:
                            _memory_slice(memory, memory['start'], algorithm['start'] - memory['start'])
                        if memory_end > algorithm_end:
                            _memory_slice(memory, algorithm_end, memory_end - algorithm_end)
                        # Update flash attributes
                        flash_attrs['start'] = flash_start
                        flash_attrs['length'] = flash_end - flash_start
                        # Amend region 'pname' attribute if it is not already set
                        if (flash_attrs['pname'] is None) and ('pname' in algorithm):
                            flash_attrs['pname'] = algorithm['pname']
                        # Add additional attributes related to the algorithm
                        if 'ram-start' in algorithm:
                            flash_attrs['_RAMstart'] = algorithm['ram-start']
                        if 'ram-size' in algorithm:
                            flash_attrs['_RAMsize'] = algorithm['ram-size']
                        if ('_RAMstart' not in flash_attrs) or ('_RAMsize' not in flash_attrs):
                            LOG.error("Flash algorithm '%s' has no RAMstart or RAMsize", algorithm['algorithm'])
                        algorithm_path = os.path.normpath(algorithm['algorithm'])
                        flash_attrs['flm'] = PackFlashAlgo(os.path.expandvars(algorithm_path))
                        # Set sector size to a fixed value to prevent any possibility of infinite recursion due to
                        # the default lambdas for sector_size and blocksize returning each other's value.
                        flash_attrs['sector_size'] = 0
                        # Create appropriate memory region object and store it
                        regions.append(MEMORY_TYPE_CLASS_MAP[memory_type](**flash_attrs))
                        # Stop searching for algorithms if one without pname was found
                        if flash_attrs['pname'] is None:
                            break

            if memory_type != MemoryType.FLASH:
                # Create appropriate memory region object and store it
                regions.append(MEMORY_TYPE_CLASS_MAP[memory_type](**attrs))

        self._memory_map = MemoryMap(regions)

    def _build_aps_map(self) -> None:
        """@brief Builds mappings between Access Ports (APs) and processor descriptions.

        Populates valid APs, processor maps, and resolves SVD paths for debug topology.
        """
        self._built_apid_map = True

        def get_svd_path(pname: Optional[str] = None) -> Optional[str]:
            svd_path = None
            for item in self.system_descriptions:
                if item['type'] == 'svd':
                    if (pname is not None) and (item.get('pname') not in (None, pname)):
                        continue
                    norm_path = os.path.normpath(item['file'])
                    svd_path = os.path.expandvars(norm_path)
                    break
            return svd_path

        _processors = {}
        for processor in self.debug_topology.get('processors', {}):
            apid = processor.get('apid')
            pname = processor.get('pname', 'Unknown')
            reset_sequence = processor.get('reset-sequence', 'ResetSystem')
            if apid is not None:
                _processors[apid] = (pname, reset_sequence)

        for debugport in self.debug_topology.get('debugports', {}):
            dpid = debugport.get('dpid', 0)
            self._valid_dps.append(dpid)
            for accessport in debugport.get('accessports', {}):
                apid = accessport.get('apid', 0)

                if 'address' in accessport:
                    self._uses_apv2 = True
                    ap_address = APv2Address(accessport['address'], dpid, apid)
                elif 'index' in accessport:
                    ap_address = APv1Address(accessport['index'], dpid, apid)
                else:
                    ap_address = APv1Address(0, dpid, apid)

                self._apids[apid] = ap_address
                pname, reset_sequence = _processors.get(apid, (f'Unknown{apid}', 'ResetSystem'))
                self._processors_map[pname] = ProcessorInfo(name=pname,
                                                            ap_address=ap_address,
                                                            svd_path=get_svd_path(pname),
                                                            default_reset_sequence=reset_sequence)
        if not self._valid_dps:
            # Use default __dp of 0.
            self._valid_dps.append(0)
        # At least one processor must have been defined.
        if not self._processors_map:
            # Add dummy processor.
            self._processors_map['Unknown'] = ProcessorInfo(name='Unknown',
                                                            ap_address=APv1Address(0),
                                                            svd_path=get_svd_path())


class CbuildRunSequences:
    """@brief Parses debug sequences and debug variable definitions from .cbuild-run.yml."""
    def __init__(self, device: CbuildRun) -> None:
        self._cbuild_vars = device.debug_vars
        self._cbuild_debugger = device.debugger
        self._cbuild_sequences = device.debug_sequences

        self._debugvars: Optional[Block] = None
        self._debugvars_conf: Optional[Block] = None
        self._sequences: Set[DebugSequence] = set()
        self._control_nodes = {'if', 'while'}

    @property
    def variables(self) -> Optional[Block]:
        if (self._debugvars is None) and (self._cbuild_vars.get('vars') is not None):
            self._debugvars = Block(self._cbuild_vars['vars'], info='debugvars')
        return self._debugvars

    @property
    def dbgconf_variables(self) -> Optional[Block]:
        if self._debugvars_conf is None:
            self._dbgconf_variables()
        return self._debugvars_conf

    @property
    def sequences(self) -> Set[DebugSequence]:
        if self._sequences == set():
            self._build_sequences()
        return self._sequences

    def _dbgconf_variables(self) -> Optional[Block]:
        dbgconf_file = self._cbuild_debugger.get('dbgconf')
        if dbgconf_file is not None:
            try:
                with open(dbgconf_file) as f:
                    dbgconf = f.read()
                    self._debugvars_conf = Block(dbgconf, info='dbgconf')
            except FileNotFoundError:
                LOG.warning("dbgconf file '%s' was not found", dbgconf_file)

    def _build_sequences(self) -> None:
        for elem in self._cbuild_sequences:
            name = elem.get('name')
            if name is None:
                LOG.warning("invalid debug sequence; missing name")
                continue

            pname = elem.get('pname')
            info = elem.get('info', '')
            sequence = DebugSequence(name, True, pname, info)

            if 'blocks' in elem:
                for child in elem['blocks']:
                    self._build_sequence_node(sequence, child)
            self._sequences.add(sequence)

    def _build_sequence_node(self, parent: DebugSequenceNode, elem: dict) -> None:
        info = elem.get('info', "")
        if any(node in elem for node in self._control_nodes):
            if 'if' in elem:
                node = IfControl(str(elem['if']), info)
            elif 'while' in elem:
                node = WhileControl(str(elem['while']), info, int(elem.get('timeout', 0)))

            parent.add_child(node)

            if 'blocks' in elem:
                for child in elem['blocks']:
                    self._build_sequence_node(node, child)
            elif 'execute' in elem:
                child = {k: v for k, v in elem.items() if k not in self._control_nodes}
                self._build_sequence_node(node, child)
        else:
            if 'execute' in elem:
                is_atomic = True if 'atomic' in elem else False
                node = Block(elem['execute'], is_atomic, info)
                parent.add_child(node)


class CbuildRunDebugSequenceDelegate(DebugSequenceDelegate):
    """@brief Delegate class for running debug sequences parsed from cbuild-run files.

    Responsible for:
    - Managing debug variables and overrides from .dbgconf files.
    - Providing runtime execution contexts for sequences.
    - Handling pyOCD wire protocols and connection parameters.
    """
    ## Map from pyocd reset types to the __connection variable reset type field.
    # 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
    RESET_TYPE_MAP = {
        Target.ResetType.HW: 1,
        Target.ResetType.SW: 2, # TODO pick default sw reset type
        Target.ResetType.SW_SYSRESETREQ: 2,
        Target.ResetType.SW_VECTRESET: 3,
        Target.ResetType.SW_EMULATED: 2, # no direct match
    }

    def __init__(self, target: CoreSightTarget, device: CbuildRun) -> None:
        self._target = target
        self._session = target.session
        self._device = device
        self._cbuild_sequences = CbuildRunSequences(device)
        self._sequences: Set[DebugSequence] = self._cbuild_sequences.sequences
        self._debugvars: Optional[Scope] = None
        self._functions = DebugSequenceCommonFunctions()

    @property
    def all_sequences(self) -> Set[DebugSequence]:
        return self._sequences

    @property
    def cmsis_pack_device(self) -> CbuildRun:
        return self._device

    def get_root_scope(self, context: DebugSequenceExecutionContext) -> Scope:
        if self._debugvars is not None:
            return self._debugvars

        # Populate default debugvars with values from *.cbuild-run.yml file.
        self._debugvars = Scope(name='debugvars')
        debugvars_block = self._cbuild_sequences.variables
        if debugvars_block is not None:
            with context.push(debugvars_block, self._debugvars):
                debugvars_block.execute(context)

        # Override default debugvars with values from *.dbgconf file.
        debugvars_conf_block = self._cbuild_sequences.dbgconf_variables
        if debugvars_conf_block is not None:
            with context.push(debugvars_conf_block, self._debugvars):
                debugvars_conf_block.execute(context)

        # Make all vars read-only.
        self._debugvars.freeze()

        if LOG.isEnabledFor(logging.DEBUG):
            for name in sorted(self._debugvars.variables):
                value = self._debugvars.get(name)
                LOG.debug("debugvar '%s' = %#x (%d)", name, value, value)

        return self._debugvars

    def run_sequence(self, name: str, pname: Optional[str] = None) -> Optional[Scope]:
        """@brief Executes a debug sequence by name for the specified processor."""
        pname_desc = f" ({pname})" if (pname and LOG.isEnabledFor(logging.DEBUG)) else ""

        # Error out for invalid sequence.
        if not self.has_sequence_with_name(name, pname):
            raise NameError(name)

        # Get sequence object.
        seq = self.get_sequence_with_name(name, pname)

        LOG.debug("Running debug sequence '%s'%s", name, pname_desc)

        # Create runtime context and contextified functions instance.
        context = DebugSequenceExecutionContext(self._session, self, pname)

        # Map optional pname to AP address. If the pname is not specified, then use the device's
        # first available AP. If not APs are known (eg haven't been discovered yet) then use 0.
        if pname:
            proc_map = self._device.processors_map
            ap_address = proc_map[pname].ap_address
        else:
            ap = self._target.first_ap
            if ap is not None:
                ap_address = ap.address
            else:
                ap_address = APv1Address(0)

        # Set the default AP in the exec context.
        context.default_ap = ap_address

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
        if self._device.debug_topology.get('swj', True):
            protocol |= 1 << 16
        if self._device.debug_topology.get('dormant', False):
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
