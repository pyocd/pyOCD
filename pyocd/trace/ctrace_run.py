# pyOCD debugger
# Copyright (c) 2026 Arm Limited
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

from dataclasses import dataclass
import hashlib
import logging
from pathlib import Path
import re
import threading
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, TYPE_CHECKING, Union)

import yaml

from ..core import exceptions

if TYPE_CHECKING:
    from ..core.core_target import CoreTarget
    from ..core.session import Session
    from ..core.soc_target import SoCTarget
    from ..utility.notification import Notification

LOG = logging.getLogger(__name__)

DEMCR = 0xE000EDFC
DEMCR_TRCENA = (1 << 24)

CORESIGHT_LAR_OFFSET = 0xFB0
CORESIGHT_LAR_KEY = 0xC5ACCE55


class CTraceRunError(exceptions.Error):
    """Custom exception for errors encountered during processing of .ctrace-run.yml."""


class CTraceRunTargetError(CTraceRunError):
    """Error encountered while applying ctrace-run configuration to the target."""


@dataclass(frozen=True)
class _CTraceRunRegister:
    """A resolved ctrace-run register access."""

    component: str
    register: str
    address: int
    value: int
    base_address: int
    mask: Optional[int] = None
    pname: Optional[str] = None


@dataclass(frozen=True)
class _CTraceRunData:
    """Immutable parsed ctrace-run configuration."""

    references: Tuple[Tuple[str, Optional[str]], ...]
    register_access: Tuple[_CTraceRunRegister, ...]


class _CTraceRunParser:
    """Cached parser for a .ctrace-run.yml file."""

    _DEFAULT_BASE_ADDRESSES: Dict[str, int] = {
        'ITM': 0xE0000000,
        'DWT': 0xE0001000,
        'PMU': 0xE0003000,
        'ETM': 0xE0041000,
    }

    _REGISTER_OFFSETS: Dict[str, Dict[str, int]] = {
        'ITM': {
            'ITM_TPR': 0xE40,
            'ITM_TCR': 0xE80,
        },
        'DWT': {
            'DWT_CTRL': 0x000,
            'DWT_CYCCNT': 0x004,
            'DWT_CPICNT': 0x008,
            'DWT_EXCCNT': 0x00C,
            'DWT_SLEEPCNT': 0x010,
            'DWT_LSUCNT': 0x014,
            'DWT_FOLDCNT': 0x018,
        },
        'PMU': {
            'PMU_CCNTR': 0x07C,
            'PMU_CCFILTR': 0x47C,
            'PMU_CNTENSET': 0xC00,
            'PMU_CNTENCLR': 0xC20,
            'PMU_INTENSET': 0xC40,
            'PMU_INTENCLR': 0xC60,
            'PMU_OVSCLR': 0xC80,
            'PMU_SWINC': 0xCA0,
            'PMU_OVSSET': 0xCC0,
            'PMU_CTRL': 0xE04,
        },
    }

    _INDEXED_REGISTER_PATTERNS: Dict[str, Tuple[Tuple[re.Pattern[str], int, int], ...]] = {
        'ITM': (
            (re.compile(r'^ITM_TER(\d+)$'), 0xE00, 4),
        ),
        'DWT': (
            (re.compile(r'^DWT_COMP(\d+)$'), 0x020, 0x10),
            (re.compile(r'^DWT_MASK(\d+)$'), 0x024, 0x10),
            (re.compile(r'^DWT_FUNCTION(\d+)$'), 0x028, 0x10),
        ),
        'PMU': (
            (re.compile(r'^PMU_EVCNTR(\d+)$'), 0x000, 4),
            (re.compile(r'^PMU_EVTYPER(\d+)$'), 0x400, 4),
        ),
    }

    def __init__(self, yml_path: Union[str, Path]) -> None:
        """Create a ctrace-run processor for a YAML file."""
        self._path = Path(yml_path).expanduser().resolve()
        self._digest: Optional[bytes] = None
        self._data: Optional[_CTraceRunData] = None

    def load(self, force: bool = False) -> Optional[Tuple[bytes, _CTraceRunData]]:
        """Read and parse the file if its content has changed."""
        try:
            yml_content = self._path.read_bytes()
        except FileNotFoundError:
            LOG.debug("No ctrace-run file found at '%s'", self._path)
            self._digest = None
            self._data = None
            return None
        except OSError as err:
            raise CTraceRunError(f"cannot access file: {err.strerror}") from err

        digest = hashlib.sha256(yml_content).digest()
        if not force and digest == self._digest and self._data is not None:
            return digest, self._data

        data = self._parse(yml_content)
        self._digest = digest
        self._data = data
        return digest, data

    def _parse(self, yml_content: bytes) -> _CTraceRunData:
        try:
            yml_data = yaml.safe_load(yml_content)
        except yaml.YAMLError as err:
            raise CTraceRunError(f"invalid YAML: {err}") from err

        if not isinstance(yml_data, dict) or 'ctrace-run' not in yml_data:
            raise CTraceRunError("invalid header")

        data = yml_data['ctrace-run']
        if not isinstance(data, dict):
            raise CTraceRunError("'ctrace-run' must be a dictionary")

        refs = data.get('ctrace-refs')
        if not isinstance(refs, list):
            raise CTraceRunError("'ctrace-refs' must be a list")

        references: List[Tuple[str, Optional[str]]] = []
        register_access: List[_CTraceRunRegister] = []
        for ref_index, ref in enumerate(refs, start=1):
            try:
                reference, ref_access = self._parse_reference(ref, ref_index)
            except CTraceRunError as err:
                LOG.warning("Ignoring invalid ctrace-run reference in '%s': %s", self._path, err)
                continue
            if ref_access:
                references.append(reference)
            register_access.extend(ref_access)

        LOG.debug("Parsed ctrace-run configuration from '%s'", self._path)
        return _CTraceRunData(tuple(references), tuple(register_access))

    def _parse_reference(self, ref: Any, ref_index: int) -> Tuple[Tuple[str, Optional[str]], List[_CTraceRunRegister]]:
        if not isinstance(ref, dict):
            raise CTraceRunError(f"ctrace-run reference entry {ref_index} must be a dictionary")

        ref_name = ref.get('ctrace-ref')
        if not isinstance(ref_name, str) or not ref_name:
            raise CTraceRunError(f"ctrace-run reference entry {ref_index} requires a non-empty 'ctrace-ref'")

        regs = ref.get('regs')
        if regs is None:
            regs = []
        if not isinstance(regs, list):
            raise CTraceRunError(f"'regs' in ctrace-run reference '{ref_name}' must be a list")

        pname = ref.get('pname')
        if regs and pname is not None and (not isinstance(pname, str) or not pname):
            raise CTraceRunError(f"'pname' in ctrace-run reference '{ref_name}' must be a non-empty string")

        return ((ref_name, pname), self._parse_regs(regs, pname, ref_name))

    def _parse_regs(self, regs: Iterable[Mapping[str, Any]], pname: Optional[str], ref_name: str) -> List[_CTraceRunRegister]:
        register_access: List[_CTraceRunRegister] = []

        for reg in regs:
            if not isinstance(reg, dict):
                raise CTraceRunError(f"register entry in ctrace-run reference '{ref_name}' must be a dictionary")

            reg_name = reg.get('name')
            value = reg.get('value')
            if not isinstance(reg_name, str) or not reg_name:
                raise CTraceRunError(f"register entry in ctrace-run reference '{ref_name}' requires a non-empty 'name'")
            if value is None:
                raise CTraceRunError(f"register '{reg_name}' in ctrace-run reference '{ref_name}' requires a 'value'")

            resolved = self._resolve_register(reg_name)
            if resolved is None:
                raise CTraceRunError(f"unknown register '{reg_name}' in ctrace-run reference '{ref_name}'")
            resolved_component, resolved_base, address = resolved

            try:
                register_access.append(_CTraceRunRegister(
                    component=resolved_component,
                    register=reg_name,
                    address=address,
                    value=self._parse_u32(value, 'value'),
                    mask=self._parse_u32(reg['mask'], 'mask') if 'mask' in reg else None,
                    base_address=resolved_base,
                    pname=pname,
                ))
            except (TypeError, ValueError) as err:
                raise CTraceRunError(f"invalid register '{reg_name}' in ctrace-run reference '{ref_name}': {err}") from err

        return register_access

    @classmethod
    def _resolve_register(cls, reg_name: str) -> Optional[Tuple[str, int, int]]:
        component = reg_name.partition('_')[0]
        base_address = cls._DEFAULT_BASE_ADDRESSES.get(component)
        if base_address is None:
            return None

        offsets = cls._REGISTER_OFFSETS.get(component)
        offset = offsets.get(reg_name) if offsets is not None else None

        if offset is None:
            for pattern, base, stride in cls._INDEXED_REGISTER_PATTERNS.get(component, ()):
                match = pattern.match(reg_name)
                if match:
                    offset = base + (int(match.group(1)) * stride)
                    break

        return None if offset is None else (component, base_address, base_address + offset)

    @staticmethod
    def _parse_u32(value: Any, name: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")
        if isinstance(value, int):
            result = value
        elif isinstance(value, str):
            result = int(value, 0)
        else:
            raise TypeError(f"{name} must be an integer")

        if not 0 <= result <= 0xFFFFFFFF:
            raise ValueError(f"{name} must be an unsigned 32-bit integer")
        return result


class CTraceRun:
    """Load and apply a CMSIS-Toolbox .ctrace-run.yml configuration."""

    def __init__(self, session: "Session") -> None:
        self._lock = threading.RLock()
        self._last_applied_digest: Optional[bytes] = None
        self._last_error: Optional[str] = None

        cbuild_run = session.cbuild_run
        if cbuild_run is None or not cbuild_run.trace.enabled:
            raise CTraceRunError("Cannot create CTraceRun when cbuild-run trace is not enabled")

        cbuild_run_path = session.options.get('cbuild_run')
        if cbuild_run_path is None:
            raise CTraceRunError("Cannot derive ctrace-run path without a cbuild-run path")

        suffix = '.cbuild-run.yml'
        source_path = Path(str(cbuild_run_path)).expanduser().resolve()
        source_name = source_path.name
        if not source_name.lower().endswith(suffix):
            raise CTraceRunError(f"Cannot derive ctrace-run name from cbuild-run file '{cbuild_run_path}'")

        project_path = cbuild_run.proj_path if cbuild_run.proj_path_name else None
        trace_root = (Path(project_path).expanduser().resolve() if project_path else source_path.parent)
        self._path = trace_root / '.trace' / f"{cbuild_run.solution_set}.ctrace-run.yml"
        self._parser = _CTraceRunParser(self._path)
        session.subscribe(self._trace_restart_handler, session.Event.TRACE_RESTART, session)

    def apply(self, target: "SoCTarget", force: bool = False) -> bool:
        """Apply new or explicitly reloaded configuration and return whether it was applied."""
        with self._lock:
            try:
                loaded = self._parser.load(force=force)
                if loaded is None:
                    self._last_applied_digest = None
                    self._last_error = None
                    return False

                digest, data = loaded
                if not force and digest == self._last_applied_digest:
                    return False

                self._apply_to_target(target, data)
                self._last_applied_digest = digest
                self._last_error = None
                return True
            except exceptions.Error as err:
                self._report_error(err)
                return False

    def reload(self, target: "SoCTarget") -> bool:
        """Reload and apply the file even if it has not changed."""
        return self.apply(target, force=True)

    def invalidate(self) -> None:
        """Invalidate the last applied configuration, so that it will be reapplied on the next call to apply()."""
        with self._lock:
            self._last_applied_digest = None

    def _trace_restart_handler(self, notification: "Notification") -> None:
        """Invalidate the applied configuration after target trace support restarts."""
        self.invalidate()

    def _report_error(self, error: exceptions.Error) -> None:
        error_message = str(error)
        if error_message == self._last_error:
            LOG.debug("ctrace-run configuration '%s' was not applied: %s", self._path, error)
        else:
            if isinstance(error, CTraceRunTargetError):
                LOG.error("Failed to apply ctrace-run configuration '%s': %s", self._path, error)
            else:
                LOG.warning("Ignoring invalid ctrace-run configuration '%s': %s", self._path, error)
            self._last_error = error_message

    def _apply_to_target(self, target: "SoCTarget", data: _CTraceRunData) -> None:
        if not data.register_access:
            LOG.debug("No ctrace-run register access to apply")
            return
        access_targets = self._resolve_access_targets(target, data.references)

        enabled_targets: Set[int] = set()
        unlocked_components: Set[Tuple[int, int]] = set()

        for reg in data.register_access:
            access_target = access_targets[reg.pname]
            target_key = id(access_target)

            if target_key not in enabled_targets:
                self._enable_trace_access(access_target)
                enabled_targets.add(target_key)

            if reg.component in ('DWT', 'ITM'):
                component_key = (target_key, reg.base_address)
                if component_key not in unlocked_components:
                    self._unlock_component(access_target, reg.component, reg.base_address)
                    unlocked_components.add(component_key)

            self._modify_register(access_target, reg)

    def _resolve_access_targets(self, target: "SoCTarget", references: Iterable[Tuple[str, Optional[str]]]) -> Dict[Optional[str], "CoreTarget"]:
        cores_by_pname = {core.node_name: core for core in target.cores.values()}
        access_targets: Dict[Optional[str], "CoreTarget"] = {}

        for ref_name, pname in references:
            if pname is None and len(target.cores) > 1:
                raise CTraceRunError(f"missing 'pname' in ctrace-run reference '{ref_name}' for a multicore target")
            if pname is not None and pname not in cores_by_pname:
                raise CTraceRunError(f"unknown pname '{pname}' in ctrace-run reference '{ref_name}'")
            access_targets[pname] = (target.selected_core_or_raise if pname is None else cores_by_pname[pname])

        return access_targets

    @staticmethod
    def _modify_register(target: "CoreTarget", reg: _CTraceRunRegister) -> None:
        try:
            value = reg.value
            if reg.mask is not None:
                current = target.read32(reg.address)
                value = (current & ~reg.mask) | (reg.value & reg.mask)
            target.write32(reg.address, value)
            LOG.debug("ctrace-run wrote %s = 0x%08x at 0x%08x%s",
                      reg.register, value, reg.address, f" for processor '{target.node_name}'" if target.node_name else "",)
        except exceptions.Error as err:
            pname = f" for processor '{target.node_name}'" if target.node_name else ""
            raise CTraceRunTargetError(f"register {reg.register} access at 0x{reg.address:08x}{pname} failed: {err}") from err

    @staticmethod
    def _enable_trace_access(target: "CoreTarget") -> None:
        try:
            demcr = target.read32(DEMCR)
            if (demcr & DEMCR_TRCENA) == 0:
                target.write32(DEMCR, demcr | DEMCR_TRCENA)
        except exceptions.Error as err:
            pname = f" for processor '{target.node_name}'" if target.node_name else ""
            raise CTraceRunTargetError(f"enabling trace access{pname} failed: {err}") from err

    @staticmethod
    def _unlock_component(target: "CoreTarget", component: str, base_address: int) -> None:
        try:
            target.write32(base_address + CORESIGHT_LAR_OFFSET, CORESIGHT_LAR_KEY)
        except exceptions.Error as err:
            pname = f" for processor '{target.node_name}'" if target.node_name else ""
            raise CTraceRunTargetError(f"unlocking {component} at 0x{base_address:08x}{pname} failed: {err}") from err
