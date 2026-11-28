# pyOCD debugger
# Copyright (c) 2026 Solarboaters
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

"""Equivalent position-independent FLMs may have different link origins (#1459)."""

import ast
from io import BytesIO
import os
from pathlib import Path
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
import pytest

from pyocd.core.memory_map import RamRegion
from pyocd.target.pack.flash_algo import PackFlashAlgo


DATA = Path(__file__).parents[1] / 'data' / 'packs'


def move_elf_origin(data: bytes, origin: int) -> BytesIO:
    """Move allocated ELF32 sections and their symbols, preserving instruction bytes."""
    elf = ELFFile(BytesIO(data))
    assert elf.elfclass == 32 and elf.little_endian
    moved = bytearray(data)
    allocated = {i for i, section in enumerate(elf.iter_sections()) if section['sh_flags'] & 2}
    for i, section in enumerate(elf.iter_sections()):
        if i in allocated:
            offset = elf['e_shoff'] + i * elf['e_shentsize'] + 12
            struct.pack_into('<I', moved, offset, section['sh_addr'] + origin)
        if section['sh_type'] == 'SHT_SYMTAB':
            for j, symbol in enumerate(section.iter_symbols()):
                if symbol['st_shndx'] in allocated:
                    offset = section['sh_offset'] + j * section['sh_entsize'] + 4
                    struct.pack_into('<I', moved, offset, symbol['st_value'] + origin)
    for i, segment in enumerate(elf.iter_segments()):
        if segment['p_type'] == 'PT_LOAD':
            offset = elf['e_phoff'] + i * elf['e_phentsize'] + 8
            struct.pack_into('<II', moved, offset, segment['p_vaddr'] + origin, segment['p_paddr'] + origin)
    if elf['e_entry']:
        struct.pack_into('<I', moved, 24, elf['e_entry'] + origin)
    return BytesIO(moved)


@pytest.mark.parametrize('filename', ['STM32F4xx_2048.FLM', 'nrf53xx_application.flm'])
@pytest.mark.parametrize('origin', [0, 0xc000, 0x20000000])
def test_link_origin_does_not_change_loaded_algorithm(filename, origin):
    data = (DATA / filename).read_bytes()
    original = PackFlashAlgo(BytesIO(data))
    shifted = PackFlashAlgo(move_elf_origin(data, origin))
    assert next(s.start for s in shifted.elf.sections if s.name == "PrgCode") == origin
    assert shifted.algo_data == original.algo_data
    assert shifted.symbols == original.symbols
    for field in ['ro_start', 'ro_size', 'rw_start', 'rw_size', 'zi_start', 'zi_size',
                  'flash_start', 'flash_size', 'page_size', 'sector_sizes']:
        assert getattr(shifted, field) == getattr(original, field)
    ram = RamRegion(0x20000000, length=0x40000)
    assert (shifted.get_pyocd_flash_algo(shifted.page_size, ram)
            == original.get_pyocd_flash_algo(original.page_size, ram))


@pytest.mark.parametrize('filename', ['STM32F4xx_2048.FLM', 'nrf53xx_application.flm'])
def test_generate_flash_algo_script(tmp_path, filename):
    pytest.importorskip('jinja2')
    root = Path(__file__).resolve().parents[2]
    data = (DATA / filename).read_bytes()
    dictionaries = []
    for origin in [0, 0xc000]:
        flm = tmp_path / f'algo-{origin}.FLM'
        flm.write_bytes(move_elf_origin(data, origin).getvalue())
        output = tmp_path / f'blob-{origin}.py'
        result = subprocess.run([sys.executable, str(root / 'scripts/generate_flash_algo.py'),
                                 str(flm), '-o', str(output)], cwd=tmp_path,
                                env=dict(os.environ, PYTHONPATH=str(root)),
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assignment = ast.parse(output.read_text()).body[0]
        dictionaries.append(ast.dump(assignment.value))
    assert dictionaries[0] == dictionaries[1]
