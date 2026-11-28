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
import subprocess
import sys

import pytest


@pytest.mark.parametrize('quiet', [False, True])
@pytest.mark.parametrize('denied', [False, True])
def test_list_explains_usb_permission_failure(tmp_path, quiet, denied):
    # Exercise real CLI logging and ST-Link discovery with a denied USB device.
    script = r"""
import errno
import sys
from unittest.mock import Mock, patch
import usb.core
from pyocd.__main__ import PyOCDTool
from pyocd.probe.aggregator import DebugProbeAggregator
from pyocd.probe.stlink_probe import StlinkProbe

probe = Mock(idVendor=0x0483, idProduct=0x3748)
probe.get_active_configuration.side_effect = usb.core.USBError('Access denied', errno=errno.EACCES)
def find(*, find_all, custom_match):
    return [dev for dev in ([probe] if sys.argv[1] == 'denied' else []) if custom_match(dev)]
with patch('pyocd.probe.stlink.usb.usb_find', find), \
     patch('pyocd.probe.stlink.usb.platform.system', return_value='Linux'), \
     patch.object(DebugProbeAggregator, 'get_all_connected_probes', StlinkProbe.get_all_connected_probes):
    sys.exit(PyOCDTool().run(['list', '--no-config', '--color=never'] + sys.argv[2:]))
"""
    root = Path(__file__).resolve().parents[2]
    args = [sys.executable, '-c', script, 'denied' if denied else 'none']
    if quiet:
        args.append('-q')
    result = subprocess.run(args, cwd=tmp_path, env=dict(os.environ, PYTHONPATH=str(root)),
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert 'No available debug probes' in result.stdout
    assert ('udev rule' in result.stderr) == (denied and not quiet)
    assert 'udev' not in result.stdout
