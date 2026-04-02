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

import importlib_resources
import logging
import yaml

from typing import (List, Set, Dict, Optional, FrozenSet)

from .sequences import (DebugSequence, DebugSequenceNode, IfControl, WhileControl, Block)
from ...probe.debug_probe import DebugProbe

LOG = logging.getLogger(__name__)


class _YAMLSequenceParser:
    """@brief Base class for parsing debug sequences."""
    CONTROL_NODES = {'if', 'while'}

    @classmethod
    def _dbgconf_variables(cls, dbgconf_file: Optional[str]) -> Optional[Block]:
        if dbgconf_file is not None:
            try:
                with open(dbgconf_file) as f:
                    dbgconf = f.read()
                return Block(dbgconf, info='dbgconf')
            except FileNotFoundError:
                LOG.warning("dbgconf file '%s' was not found", dbgconf_file)

    @classmethod
    def _build_sequences(cls, sequence_list: List[dict]) -> Set[DebugSequence]:
        debug_sequences: Set[DebugSequence] = set()
        for elem in sequence_list:
            name = elem.get('name')
            if name is None:
                LOG.warning("invalid debug sequence; missing name")
                continue

            pname = elem.get('pname')
            info = elem.get('info', '')
            sequence = DebugSequence(name, True, pname, info)

            if 'blocks' in elem:
                for child in elem['blocks']:
                    cls._build_sequence_node(sequence, child)
            debug_sequences.add(sequence)
        return debug_sequences

    @classmethod
    def _build_sequence_node(cls, parent: DebugSequenceNode, elem: dict) -> None:
        info = elem.get('info', "")
        if any(node in elem for node in cls.CONTROL_NODES):
            if 'if' in elem:
                node = IfControl(str(elem['if']), info)
                if 'while' in elem:
                    # Add if node to the parent
                    parent.add_child(node)
                    # Update parent to the if node
                    parent = node
                    # Create while node as child of if node
                    node = WhileControl(str(elem['while']), info, int(elem.get('timeout', 0)))
            elif 'while' in elem:
                node = WhileControl(str(elem['while']), info, int(elem.get('timeout', 0)))

            parent.add_child(node)

            if 'blocks' in elem:
                for child in elem['blocks']:
                    cls._build_sequence_node(node, child)
            elif 'execute' in elem:
                child = {k: v for k, v in elem.items() if k not in cls.CONTROL_NODES}
                cls._build_sequence_node(node, child)
        else:
            if 'execute' in elem:
                is_atomic = 'atomic' in elem
                node = Block(elem['execute'], is_atomic, info)
                parent.add_child(node)


class DefaultDebugSequences(_YAMLSequenceParser):
    """@brief Provides default debug sequences for pack devices."""

    # Sequence-to-required-capabilities mapping
    _SEQUENCE_CAPABILITIES = {
        'DebugPortSetup': frozenset({DebugProbe.Capability.SWJ_SEQUENCE, DebugProbe.Capability.JTAG_SEQUENCE,}),
        'ResetHardware': frozenset({DebugProbe.Capability.PIN_ACCESS}),
        'ResetHardwareAssert': frozenset({DebugProbe.Capability.PIN_ACCESS}),
        'ResetHardwareDeassert': frozenset({DebugProbe.Capability.PIN_ACCESS}),
    }

    @classmethod
    def _load_default_sequences(cls) -> FrozenSet[DebugSequence]:
        """Load default sequences from YAML file."""
        try:
            resource_path = importlib_resources.files('pyocd.debug.sequences') / 'default_sequences.yaml'
            with resource_path.open('r') as f:
                yaml_data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            LOG.error("Default debug sequences file not found")
            return frozenset()

        sequence_list = yaml_data.get('debug-sequences', [])
        debug_sequences = cls._build_sequences(sequence_list)
        return frozenset(debug_sequences)

    @classmethod
    def _is_sequence_supported(cls, seq: DebugSequence, probe: Optional[DebugProbe]) -> bool:
        """Check if a sequence is supported by the given probe."""
        if probe is None:
            return True
        required_capabilities = cls._SEQUENCE_CAPABILITIES.get(seq.name, frozenset())
        return required_capabilities.issubset(probe.capabilities)

    @classmethod
    def get_sequences(cls, probe: Optional[DebugProbe] = None) -> Dict[str, DebugSequence]:
        """Return default sequences filtered by probe capabilities."""
        all_sequences = cls._load_default_sequences()
        return {seq.name: seq for seq in all_sequences if cls._is_sequence_supported(seq, probe)}
