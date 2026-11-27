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

import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

pytest.importorskip("setuptools")


@pytest.fixture
def project(tmp_path):
    # Run the complete production build script in a minimal package directory.
    source = Path(__file__).resolve().parents[2] / 'setup.py'
    shutil.copyfile(source, tmp_path / 'setup.py')
    (tmp_path / 'setup.cfg').write_text('[metadata]\nname = svd-fixture\nversion = 1.0\n')
    data = tmp_path / 'pyocd/debug/svd/data'
    data.mkdir(parents=True)
    (data / 'chip.svd').write_bytes(b'<device/>')
    return tmp_path


def build(project, epoch, mtime, timezone):
    os.utime(project / 'pyocd/debug/svd/data/chip.svd', (mtime, mtime))
    env = dict(os.environ, TZ=timezone)
    env.pop('SOURCE_DATE_EPOCH', None)
    if epoch is not None:
        env['SOURCE_DATE_EPOCH'] = str(epoch)
    subprocess.run([sys.executable, 'setup.py', '--name'], cwd=project, env=env,
                   check=True, capture_output=True)
    return (project / 'pyocd/debug/svd/svd_data.zip').read_bytes()


@pytest.mark.parametrize('epoch', [1700000000, 0])
def test_source_date_epoch_overrides_mtime_and_timezone(project, epoch):
    first = build(project, epoch, 1600000000, 'UTC0')
    second = build(project, epoch, 1650000000, 'EST5EDT')
    assert first == second
    with zipfile.ZipFile(project / 'pyocd/debug/svd/svd_data.zip') as archive:
        assert archive.read('chip.svd') == b'<device/>'
        if epoch == 0:
            assert archive.getinfo('chip.svd').date_time == (1980, 1, 1, 0, 0, 0)


def test_no_epoch_preserves_source_timestamp(project):
    first = build(project, None, 1600000000, 'UTC0')
    second = build(project, None, 1650000000, 'UTC0')
    assert first != second
