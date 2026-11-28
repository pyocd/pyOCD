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

"""Exercise malformed on-disk indexes with the real CMSIS pack cache."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import cmsis_pack_manager
import pytest

from pyocd.target.pack import pack_target
from pyocd.subcommands.pack_cmd import PackSubcommandBase
from pyocd.tools.lists import ListGenerator


@pytest.fixture
def cache(tmp_path):
    return cmsis_pack_manager.Cache(True, True, json_path=str(tmp_path), data_path=str(tmp_path))


def test_corrupt_index_does_not_hide_builtin_targets(cache, monkeypatch, caplog):
    Path(cache.index_path).write_text('{"incomplete":', encoding='utf-8')
    monkeypatch.setattr(cmsis_pack_manager, 'Cache', lambda *args, **kwargs: cache)
    result = ListGenerator.list_targets()
    assert any(target['name'] == 'cortex_m' for target in result['targets'])
    assert str(cache.index_path) in caplog.text
    assert 'pyocd pack update' in caplog.text
    # Reading targets must not remove cached packs or rewrite user files.
    assert Path(cache.index_path).read_text(encoding='utf-8') == '{"incomplete":'


def test_pack_search_rebuilds_corrupt_index(cache, monkeypatch):
    Path(cache.index_path).write_text('{"incomplete":', encoding='utf-8')
    updates = []

    def download_index():
        # Replace only the network download; retain the real on-disk Cache reader.
        updates.append(True)
        Path(cache.index_path).write_text(json.dumps({'ExampleMCU': {}}), encoding='utf-8')

    monkeypatch.setattr(cache, 'cache_descriptors', download_index)
    command = PackSubcommandBase(argparse.Namespace(patterns=['example']))
    assert command._get_matches(cache) == {'ExampleMCU'}
    assert updates == [True]


def test_valid_index_still_lists_installed_pack(cache, monkeypatch):
    source = Path(__file__).parents[1] / 'data' / 'packs' / 'NXP.MK64F12_DFP.11.0.0.pack'
    ref = cmsis_pack_manager.CmsisPackRef('NXP', 'MK64F12_DFP', '11.0.0')
    destination = Path(cache.data_path) / ref.get_pack_name()
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    Path(cache.index_path).write_text(json.dumps({'MK64FN1M0VLL12': {
        'from_pack': {'vendor': 'NXP', 'pack': 'MK64F12_DFP', 'version': '11.0.0'},
    }}), encoding='utf-8')
    monkeypatch.setattr(cache, 'cache_descriptors', lambda: pytest.fail('Valid cache must not download'))
    assert pack_target.ManagedPacks.get_installed_packs(cache) == [ref]
    assert any(device.part_number == 'MK64FN1M0VLL12'
               for device in pack_target.ManagedPacks.get_installed_targets(cache))


def test_missing_index_is_still_empty(cache):
    assert pack_target.ManagedPacks.get_installed_packs(cache) == []


@pytest.mark.skipif(sys.platform != 'linux', reason='Uses the Linux XDG cache location')
@pytest.mark.parametrize('arguments', [['pack', 'show'], ['list', '--targets']])
def test_cli_survives_corrupt_index(tmp_path, arguments):
    data = tmp_path / 'cmsis-pack-manager'
    data.mkdir()
    (data / 'index.json').write_text('{"incomplete":', encoding='utf-8')
    env = dict(os.environ, XDG_DATA_HOME=str(tmp_path),
               PYTHONPATH=str(Path(__file__).resolve().parents[2]))
    result = subprocess.run([sys.executable, '-m', 'pyocd', *arguments],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert 'pyocd pack update' in result.stderr
    assert 'Traceback' not in result.stderr
    if arguments[0] == 'list':
        assert 'cortex_m' in result.stdout
