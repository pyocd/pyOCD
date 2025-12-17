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

from __future__ import annotations

import logging
import yaml
import os
import io
import platform

from pathlib import Path
from copy import deepcopy
from dataclasses import dataclass
from typing import (cast, Optional, Set, Dict, List, Tuple, Union, IO, Any, TYPE_CHECKING)

from .flash_algo import PackFlashAlgo
from .. import (normalise_target_type_name, TARGET)
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.ap import (APAddressBase, APv1Address, APv2Address)
from ...core import exceptions
from ...core.target import Target
from ...core.memory_map import (MemoryMap, MemoryType, MEMORY_TYPE_CLASS_MAP)
from ...coresight.cortex_m import CortexM
from ...probe.debug_probe import DebugProbe
from ...debug.svd.loader import SVDFile
from ...utility.cmdline import convert_reset_type
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

if TYPE_CHECKING:
    from ...core.session import Session
    from ...coresight.cortex_m import CortexM
    from ...core.core_target import CoreTarget
    from ...utility.sequencer import CallSequence
    from ...commands.execution_context import CommandSet

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
    def _cbuild_target_init(self, session: "Session") -> None:
        """@brief Initializes a target dynamically based on a parsed .cbuild-run.yml description.

        Sets memory maps, SVD files, and debug sequence delegates.
        """
        super(self.__class__, self).__init__(session, self._cbuild_device.memory_map)
        self.vendor = self._cbuild_device.vendor
        self.part_number = self._cbuild_device.target
        if session.command not in ('load', 'erase', 'reset'):
            # SVD file is not required for load/erase/reset commands
            _svd = self._cbuild_device.svd
            self._svd_location = SVDFile(filename=_svd) if _svd else None
        self.debug_sequence_delegate = CbuildRunDebugSequenceDelegate(self, self._cbuild_device)

    @staticmethod
    def _cbuild_target_create_init_sequence(_self) -> CallSequence:
        """@brief Creates an initialization call sequence for runtime-configured targets.

        Extends the standard discovery sequence to configure processor names
        and reset behavior after core discovery.
        """
        seq = super(_self.__class__, _self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_cores',
                            ('update_processor_name', _self.update_processor_name),
                            ('configure_core_reset', _self.configure_core_reset)
                            )
            )
        return seq

    @staticmethod
    def _cbuild_target_update_processor_name(_self) -> None:
        """@brief Updates processor names post-discovery based on Access Port (AP) addresses.

        Maps discovered cores to known processors to ensure consistent naming.
        """
        ap_to_proc = {proc.ap_address: proc for proc in _self._cbuild_device.processors_map.values()}
        info_logging_enabled = LOG.isEnabledFor(logging.INFO)

        for core in _self.cores.values():
            if core.node_name in ('Unknown', None):
                core.node_name = core.name

            proc = ap_to_proc.get(core.ap.address)
            if proc is not None and 'Unknown' in proc.name:
                # Remove old processor entry with 'Unknown' name
                _self._cbuild_device.processors_map.pop(proc.name, None)
                # Update processor name
                proc.name = core.name
                # Insert new processor entry with correct name
                _self._cbuild_device.processors_map[core.name] = proc

            if info_logging_enabled:
                core_info = f"core {core.core_number}: {core.name} r{core.cpu_revision}p{core.cpu_patch}"
                if core.node_name != core.name:
                    core_info += f", pname: {core.node_name}"
                LOG.info(core_info)

    @staticmethod
    def _cbuild_target_configure_core_reset(_self) -> None:
        """@brief Configures default reset types for each core, based on .cbuild-run.yml."""
        reset_configuration = _self._cbuild_device.debugger.get('reset', [])
        if not reset_configuration:
            # No reset configuration provided.
            return None

        for core in _self.cores.values():
            if any('pname' in r for r in reset_configuration):
                reset = next((r['type'] for r in reset_configuration if r.get('pname') == core.node_name), None)
            else:
                reset = next((r['type'] for r in reset_configuration), None)
            if reset is not None:
                reset_type = convert_reset_type(reset)
                if reset_type is not None:
                    core.default_reset_type = reset_type
        return None

    @staticmethod
    def _cbuild_target_add_core(_self, core: CoreTarget) -> None:
        """@brief Override to set node name of added core to its pname."""
        proc = _self._cbuild_device.processors_ap_map.get(cast(CortexM, core).ap.address)
        if proc is not None:
            core.node_name = proc.name
            CoreSightTarget.add_core(_self, core)
        else:
            LOG.info("Skipping core not described in debug topology")

    @staticmethod
    def _cbuild_target_get_output(_self) -> Dict[str, Tuple[str, Optional[int]]]:
        return _self._cbuild_device.output

    @staticmethod
    def _cbuild_target_add_target_command_groups(_self, command_set: CommandSet):
        """@brief Add pack related commands to the command set."""
        command_set.add_command_group('pack-target')

class CbuildRun:
    """@brief Parser for the .cbuild-run.yml file (CSolution Run and Debug Management)."""
    def __init__(self, yml_path: str) -> None:
        """@brief Reads a .cbuild-run.yml file and validates its content."""
        self._data: Dict[str, Any] = {}
        self._cbuild_name: str = ""
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
        self._sorted_processors: List[ProcessorInfo] = []
        self._use_default_memory_map: bool = True
        self._system_resources: Optional[Dict[str, list]] = None
        self._system_descriptions: Optional[List[dict]] = None
        self._required_packs: Dict[str, Optional[Path]] = {}

        try:
            # Convert to Path object early and resolve to absolute path
            yml_file_path = Path(yml_path).resolve()

            with yml_file_path.open('r') as yml_file:
                yml_data = yaml.safe_load(yml_file)
            if 'cbuild-run' in yml_data:
                self._data = yml_data['cbuild-run']
                self._cbuild_name = yml_file_path.stem.split('.cbuild-run')[0]
                # Ensure CMSIS_PACK_ROOT is set
                self._cmsis_pack_root()
            else:
                raise CbuildRunError(f"Invalid .cbuild-run.yml file '{yml_file_path}'")

            # Set cbuild-run path as the current working directory
            base_path = yml_file_path.parent
            os.chdir(base_path)
            LOG.debug("Working directory set to: '%s'", os.getcwd())
        except OSError as err:
            if yml_path == "":
                raise CbuildRunError("Cannot access *.cbuild-run.yml file: no path provided")
            else:
                raise CbuildRunError(f"Cannot access *.cbuild-run.yml file '{yml_path}': {err.strerror}") from err

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
            cmsis_pack_root = Path(os.path.expandvars("${LOCALAPPDATA}\\Arm\\Packs")).expanduser().resolve()
        elif system in {'Linux', 'Darwin'}:
            # Linux or macOS detected, set the Linux/macOS default path
            # Note: WSL is treated as 'Linux'
            cmsis_pack_root = Path(os.path.expandvars("${HOME}/.cache/arm/packs")).expanduser().resolve()
        else:
            raise CbuildRunError(f"Unsupported platform '{system}' for CMSIS_PACK_ROOT. "
                                 "Please set the CMSIS_PACK_ROOT environment variable manually.")

        os.environ['CMSIS_PACK_ROOT'] = str(cmsis_pack_root)
        LOG.debug("CMSIS_PACK_ROOT set to: '%s'", os.environ['CMSIS_PACK_ROOT'])

    def _get_required_packs(self) -> None:
        """@brief Determines required CMSIS packs from the .cbuild-run.yml file."""
        if not self._required_packs:
            cmsis_pack_root = Path(os.environ['CMSIS_PACK_ROOT']).expanduser().resolve()

            def _pack_path(cmsis_pack: str) -> Optional[Path]:
                try:
                    vendor, pack = cmsis_pack.split('::', 1)
                    name, version = pack.split('@', 1)
                except ValueError:
                    LOG.error("Invalid pack format '%s'. Expected 'Vendor::Pack@Version'", cmsis_pack)
                    return None

                return cmsis_pack_root / vendor / name / version

            for pack_type in ('device-pack', 'board-pack'):
                pack = self._data.get(pack_type)
                if pack is not None:
                    self._required_packs[pack] = _pack_path(pack)

    def _check_path(self, file_path: Path, required: bool = False) -> Path:
        """@brief Checks if the required files are accessible and verifies pack installation if needed."""
        file_path = Path(os.path.expandvars(str(file_path))).expanduser().resolve()
        # If the file exists, we don't need to do any further checks
        if file_path.is_file():
            return file_path

        def _is_under(parent: Path, child: Path) -> bool:
            try:
                child.relative_to(parent)
                return True
            except ValueError:
                return False

        # Select appropriate logging level and error message based on whether the file is required
        if required:
            log = LOG.error
            err = f"File '{file_path}' is required but not found"
        else:
            log = LOG.warning
            err = f"File '{file_path}' not found"

        self._get_required_packs()
        # Verify pack installation only if the file is located within a required pack.
        for pack, pack_path in self._required_packs.items():
            if pack_path is not None and _is_under(pack_path, file_path):
                if not pack_path.exists():
                    log("Pack '%s' is required but not installed. "
                              "Install with: cpackget add %s", pack, pack)
                else:
                    log("Installed pack '%s' is corrupted or incomplete. "
                          "Reinstall with: cpackget add -F %s", pack, pack)
                # We've found the relevant pack, no need to check further
                break

        raise CbuildRunError(err)

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
    def svd(self) -> Optional[str]:
        """@brief Path to the SVD file for the target device."""
        #TODO handle multicore devices
        try:
            for desc in self.system_descriptions:
                if desc['type'] == 'svd':
                    svd_path = self._check_path(Path(desc['file']))
                    LOG.debug("SVD path: %s", svd_path)
                    return str(svd_path)
        except CbuildRunError as err:
            LOG.warning("SVD file error: %s", err)
        except (KeyError, IndexError):
            LOG.warning("Could not locate SVD in cbuild-run system-descriptions.")
        return None

    @property
    def output(self) -> Dict[str, Tuple[str, Optional[int]]]:
        """@brief Set of loadable output files (file, [type, offset])."""
        # Supported loadable files
        FILE_TYPE = {'elf', 'hex', 'bin'}

        # Filter only loadable supported files from the output node
        loadable_files = [f for f in self._data.get('output', [])
                          if 'image' in f.get('load', '') and f.get('type') in FILE_TYPE]

        load_files = {}
        for f in loadable_files:
            # Get file type
            _type = f.get('type')
            # Get load offset (None if not specified)
            _offset = f.get('load-offset')
            # Add filename, it's type and offset to return value
            load_files[f['file']] = (_type, _offset)
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
    def sorted_processors(self) -> List[ProcessorInfo]:
        """@brief List of processors sorted by AP address."""
        if not self._sorted_processors:
            self._sorted_processors = sorted(self.processors_ap_map.values(), key=lambda p: p.ap_address.address)
        return self._sorted_processors

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
    def debugger_protocol(self) -> Optional[str]:
        """@brief Debugger protocol."""
        _debugger_protocol = self.debugger.get('protocol')
        if _debugger_protocol is not None:
            LOG.debug("Debugger protocol: %s", _debugger_protocol)
        return _debugger_protocol

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
    def swj_enable(self) -> bool:
        """@brief SWJ (Serial Wire JTAG) enable flag from debug topology."""
        return self.debug_topology.get('swj', True)

    @property
    def dormant(self) -> bool:
        """@brief Dormant mode enable flag from debug topology."""
        return self.debug_topology.get('dormant', False)

    @property
    def primary_core(self) -> Optional[int]:
        """@brief Primary core number from debugger settings."""
        start_pname = self.debugger.get('start-pname')
        if start_pname is not None:
            LOG.info("start-pname: %s", start_pname)
            return next((i for i, proc_info in enumerate(self.sorted_processors)
                        if proc_info.name == start_pname), None)
        return None

    @property
    def pre_load_halt(self) -> bool:
        """@brief Pre-load halt flag from debugger settings."""
        return self.debugger.get('load-setup', {}).get('halt', True)

    @property
    def pre_reset(self) -> Optional[str]:
        """@brief Pre-reset type from debugger settings."""
        reset = self.debugger.get('load-setup', {}).get('pre-reset')
        reset = 'off' if reset is False else reset # PyYAML: value 'off' maps to boolean False
        if reset not in {'off', 'hardware', 'system', 'core', None}:
            LOG.warning("Invalid pre-reset type '%s' in cbuild-run, defaulting to 'reset_type'", reset)
            reset = None
        return reset

    @property
    def post_reset(self) -> Optional[str]:
        """@brief Post-reset type from debugger settings."""
        reset = self.debugger.get('load-setup', {}).get('post-reset', 'hardware')
        reset = 'off' if reset is False else reset # PyYAML: value 'off' maps to boolean False
        if reset not in {'off', 'hardware', 'system', 'core'}:
            LOG.warning("Invalid post-reset type '%s' in cbuild-run, defaulting to 'hardware'", reset)
            reset = 'hardware'
        return reset

    @property
    def connect_mode(self) -> str:
        """@brief Connection mode from debugger section."""
        connect = self.debugger.get('connect', 'attach')
        if connect not in {'pre-reset', 'under-reset', 'halt', 'attach'}:
            LOG.warning("Invalid connect mode '%s' in cbuild-run, defaulting to 'attach'", connect)
            connect = 'attach'
        return connect

    @property
    def gdbserver_ports(self) -> Optional[Tuple]:
        """@brief GDB server port assignments from debugger section.
            The method will not be called frequently, so performance is not critical.
        """
        return self._get_server_ports('gdbserver')

    @property
    def telnet_ports(self) -> Optional[Tuple]:
        """@brief Telnet server port assignments from debugger section.
            The method will not be called frequently, so performance is not critical.
        """
        return self._get_server_ports('telnet')

    @property
    def telnet_modes(self) -> Tuple:
        """@brief Telnet server mode assignments from debugger section.
            The method will not be called frequently, so performance is not critical.
        """
        SUPPORTED_MODES = { 'off', 'telnet', 'file', 'console' }
        MODE_ALIASES = { False: 'off',
                        'monitor': 'telnet',
                        'server': 'telnet'
                      }
        # Get telnet configuration from debugger section
        telnet_config = self.debugger.get('telnet') or []
        valid_config = any('mode' in t for t in telnet_config)
        # Determine global mode if specified, default to 'off' otherwise
        global_mode = next((t.get('mode') for t in telnet_config if 'pname' not in t), 'off')
        global_mode = MODE_ALIASES.get(global_mode, global_mode)
        # Build list of telnet modes for each core
        telnet_modes = []
        for core in self.sorted_processors:
            mode = next((t.get('mode') for t in telnet_config if t.get('pname') == core.name), global_mode)
            mode = MODE_ALIASES.get(mode, mode)
            if mode not in SUPPORTED_MODES:
                if valid_config:
                    LOG.warning("Invalid telnet mode '%s' for core '%s' in cbuild-run, defaulting to '%s'",
                            mode, core.name, global_mode)
                mode = global_mode
            telnet_modes.append(mode)

        return tuple(telnet_modes)

    @property
    def telnet_files(self) -> Dict[str, Optional[Tuple]]:
        """@brief Telnet file path assignments from debugger section.
            The method will not be called frequently, so performance is not critical.
        """
        # Get telnet configuration from debugger section
        telnet_config = self.debugger.get('telnet') or []
        telnet_modes = self.telnet_modes

        if not any(mode == 'file' for mode in telnet_modes):
            # No telnet file paths needed
            return {'in': None, 'out': None}

        def _resolve_path(file_path: Optional[str], strict: bool = False) -> Optional[str]:
            if file_path is None:
                return None
            resolved_path = Path(os.path.expandvars(str(file_path))).expanduser().resolve()
            # In strict mode check if the file exists
            if strict and not resolved_path.is_file():
                LOG.warning("Telnet file '%s' not found", resolved_path)

            return str(resolved_path)

        in_files = []
        out_files = []

        # Per pname configuration
        config_by_pname = {t['pname']: t for t in telnet_config if 'pname' in t}

        if config_by_pname:
            # Build config per pname
            for proc_info, mode in zip(self.sorted_processors, telnet_modes):
                if mode != 'file':
                    in_files.append(None)
                    out_files.append(None)
                    continue

                config = config_by_pname.get(proc_info.name, {})
                # Check for file-in and file-out, use defaults if not provided
                in_file = _resolve_path(config.get('file-in'), strict=True)
                if in_file is None:
                    in_file = f"{self._cbuild_name}.{proc_info.name}.in"
                in_files.append(in_file)
                out_file = _resolve_path(config.get('file-out'))
                if out_file is None:
                    out_file = f"{self._cbuild_name}.{proc_info.name}.out"
                out_files.append(out_file)
        else:
            config = next((t for t in telnet_config if t.get('mode') == 'file'), None)
            if config is not None:
                if len(self.sorted_processors) > 1:
                    LOG.warning("Ignoring invalid telnet file configuration for multicore target in cbuild-run")
                    for proc_info, mode in zip(self.sorted_processors, telnet_modes):
                        if mode != 'file':
                            in_files.append(None)
                            out_files.append(None)
                        else:
                            in_files.append(f"{self._cbuild_name}.{proc_info.name}.in")
                            out_files.append(f"{self._cbuild_name}.{proc_info.name}.out")
                else:
                    in_file = _resolve_path(config.get('file-in'), strict=True)
                    if in_file is None:
                        in_file = f"{self._cbuild_name}.in"
                    in_files.append(in_file)
                    out_file = _resolve_path(config.get('file-out'))
                    if out_file is None:
                        out_file = f"{self._cbuild_name}.out"
                    out_files.append(out_file)

        return {'in': tuple(in_files) if any(in_files) else None,
                'out': tuple(out_files) if any(out_files) else None}

    def populate_target(self, target: Optional[str] = None) -> None:
        """@brief Generates and populates the target defined by the .cbuild-run.yml file."""
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
                    "__init__": CbuildRunTargetMethods._cbuild_target_init,
                    "create_init_sequence": CbuildRunTargetMethods._cbuild_target_create_init_sequence,
                    "update_processor_name" : CbuildRunTargetMethods._cbuild_target_update_processor_name,
                    "configure_core_reset": CbuildRunTargetMethods._cbuild_target_configure_core_reset,
                    "add_core": CbuildRunTargetMethods._cbuild_target_add_core,
                    "get_output": CbuildRunTargetMethods._cbuild_target_get_output,
                    "add_target_command_groups": CbuildRunTargetMethods._cbuild_target_add_target_command_groups,
        })
        TARGET[target] = tgt

    def _get_server_ports(self, server_type: str) -> Optional[Tuple]:
        """@brief Generic method to get server port assignments from debugger section."""
        server_config = self.debugger.get(server_type, [])
        if not server_config:
            # No server configuration provided.
            return None

        ports = []
        if any('pname' in server for server in server_config):
            for proc_info in self.sorted_processors:
                ports.append(next((s.get('port') for s in server_config if s.get('pname') == proc_info.name), None))
        else:
            port = next((s.get('port') for s in server_config), None)
            if port is not None:
                if len(self.sorted_processors) > 1:
                    LOG.warning("Ignoring invalid %s port configuration for multicore target in cbuild-run", server_type)
                    return None
                ports.append(port)
            else:
                return None

        return tuple(ports)

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
                        algorithm_path = self._check_path(Path(algorithm['algorithm']), required=True)
                        flash_attrs['flm'] = PackFlashAlgo(str(algorithm_path))
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
                    svd_path = str(Path(os.path.expandvars(item['file'])).expanduser().resolve())
                    break
            return svd_path

        _processors = {}
        for processor in self.debug_topology.get('processors', []):
            apid = processor.get('apid')
            pname = processor.get('pname', 'Unknown')
            reset_sequence = processor.get('reset-sequence', 'ResetSystem')
            if apid is not None:
                _processors[apid] = (pname, reset_sequence)

        for debugport in self.debug_topology.get('debugports', []):
            dpid = debugport.get('dpid', 0)
            self._valid_dps.append(dpid)
            for accessport in debugport.get('accessports', []):
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
        if not self._sequences:
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
    # 0=error, 1=HARDWARE, 2=SYSRESETREQ, 3=VECTRESET
    RESET_TYPE_MAP = {
        Target.ResetType.HARDWARE: 1,
        Target.ResetType.NSRST: 1,
        Target.ResetType.DEFAULT: 2,
        Target.ResetType.SYSTEM: 2,
        Target.ResetType.SYSRESETREQ: 2,
        Target.ResetType.CORE: 3,
        Target.ResetType.VECTRESET: 3,
        Target.ResetType.EMULATED: 3, # no direct match
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

    def default_reset_sequence(self, pname: str) -> str:
        proc_map = self.cmsis_pack_device.processors_map
        return proc_map[pname].default_reset_sequence

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
        if self._device.swj_enable:
            protocol |= 1 << 16
        if self._device.dormant:
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
