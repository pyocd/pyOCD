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

"""YAML-driven CSR register loader for RISC-V targets.

Supports two-phase loading:
  Unconditional CSRs (machine, debug, trigger, vendor) loaded
  during _build_register_list().
  Conditional CSRs loaded based on hardware capability flags
  (e.g. has_fpu for FPU CSRs). Called after core init.
"""

import os
from typing import List, Sequence

import yaml

from ..core_registers import RiscvCoreRegisterInfo, RISCV_GDB_FEATURE_CSR

_CSR_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Sections deferred to conditional loading (loaded only when capability is set).
_DEFERRED_SECTIONS = frozenset({"fpu", "supervisor_custom"})


def _parse_yaml_file(relative_path: str) -> dict:
    """Parse a YAML CSR config file.

    Args:
        relative_path: Path relative to csr/data/ directory.

    Returns:
        Dictionary mapping section names to lists of
        [name, csr_address, bitsize, group].

    Raises:
        FileNotFoundError: If the YAML file does not exist.
        ValueError: If the YAML content is not a dict.
    """
    full_path = os.path.join(_CSR_DATA_DIR, relative_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"CSR config not found: {full_path}")
    with open(full_path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"CSR config must be a dict of sections: {relative_path}")
    return data


def _yaml_entry_to_register_info(entry: list) -> RiscvCoreRegisterInfo:
    """Convert a YAML CSR entry to RiscvCoreRegisterInfo.

    Args:
        entry: [name, csr_address, bitsize, group]

    Returns:
        RiscvCoreRegisterInfo with GDB regnum = 65 + csr_address.

    Raises:
        ValueError: If csr_address is out of valid range (0x000-0xFFF).
    """
    name, csr_addr, bitsize, group = entry
    if not (0x000 <= csr_addr <= 0xFFF):
        raise ValueError(
            f"CSR address out of range: {name} = 0x{csr_addr:03X} "
            f"(must be 0x000-0xFFF)"
        )
    gdb_regnum = 65 + csr_addr
    return RiscvCoreRegisterInfo(
        name=name,
        index=csr_addr,
        bitsize=bitsize,
        reg_type="uint32",
        reg_group=group,
        reg_num=gdb_regnum,
        feature=RISCV_GDB_FEATURE_CSR,
    )


def load_csr_configs(
    config_paths: Sequence[str],
    phase: int = 1,
    has_fpu: bool = False,
) -> List[RiscvCoreRegisterInfo]:
    """Load CSR register definitions from YAML config files.

    Two-phase loading:
        Unconditional load: machine, debug, trigger, vendor
                 machine/debug/user/config. Skip 'fpu' and
                 'supervisor_custom' sections.
        Conditional load: fpu if has_fpu,
                 supervisor_custom.

    Args:
        config_paths: YAML file paths relative to csr/data/.
        phase: 1 for unconditional, 2 for conditional.
        has_fpu: Whether target has FPU (only used for conditional load).

    Returns:
        List of RiscvCoreRegisterInfo instances.
    """
    regs = []
    seen_indices = set()

    for path in config_paths:
        sections = _parse_yaml_file(path)
        for section_name, entries in sections.items():
            if not entries:
                continue

            if phase == 1 and section_name in _DEFERRED_SECTIONS:
                continue
            if phase == 2:
                if section_name == "fpu" and not has_fpu:
                    continue
                if section_name not in _DEFERRED_SECTIONS:
                    continue

            for entry in entries:
                info = _yaml_entry_to_register_info(entry)
                if info.index in seen_indices:
                    continue
                seen_indices.add(info.index)
                regs.append(info)

    return regs
