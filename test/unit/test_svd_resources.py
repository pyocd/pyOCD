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

import io
import zipfile
from unittest.mock import Mock

import pytest

from pyocd.debug.svd import loader


XML = (b'<device><name>Example</name><version>1</version><description>Test</description>'
       b'<addressUnitBits>8</addressUnitBits><width>32</width><peripherals/></device>')


@pytest.fixture
def resource(monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('device.svd', XML)
    stream = io.BytesIO(archive.getvalue())
    reference = Mock()
    reference.joinpath.return_value.open.return_value = stream
    monkeypatch.setattr(loader.importlib_resources, 'files', lambda package: reference)
    return stream


def test_builtin_closes_archive_before_deferred_load(resource):
    svd = loader.SVDFile.from_builtin('device.svd')
    assert resource.closed
    svd.load()
    assert svd.device.name == 'Example'


def test_missing_member_closes_archive(resource):
    assert loader.SVDFile.from_builtin('absent.svd') is None
    assert resource.closed


def test_invalid_archive_closes_stream(resource):
    resource.seek(0)
    resource.truncate()
    resource.write(b'not a zip archive')
    resource.seek(0)
    assert loader.SVDFile.from_builtin('device.svd') is None
    assert resource.closed


def test_caller_owned_stream_remains_open():
    stream = io.BytesIO(XML)
    svd = loader.SVDFile(stream)
    svd.load()
    assert svd.device.name == 'Example'
    assert not stream.closed
