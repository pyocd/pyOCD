# -*- coding: utf8 -*-
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
import sys
from types import SimpleNamespace

import pytest

from pyocd.core.helpers import ConnectHelper
from pyocd.target.pack import pack_target


@pytest.mark.parametrize('encoding', ['gbk', 'ascii', 'utf-8'])
@pytest.mark.parametrize('available', [True, False])
def test_probe_list_with_limited_output_encoding(monkeypatch, encoding, available):
    target = 'cortex_m' if available else 'unknown-chip'
    probe = SimpleNamespace(description='Test probe', unique_id='1234',
                            associated_board_info=SimpleNamespace(target=target, vendor='Test', name='Board'))
    monkeypatch.setattr(pack_target, 'is_pack_target_available', lambda *args: False)
    stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors='strict')
    with monkeypatch.context() as patch:
        patch.setattr(sys, 'stdout', stream)
        ConnectHelper._print_probe_list([probe])
        stream.flush()
        output = stream.buffer.getvalue().decode(encoding)
    assert target in output
    assert '1234' in output
    if encoding == 'utf-8':
        assert ('✔' if available else '✖') in output
    else:
        assert ('+' if available else 'x') in output
