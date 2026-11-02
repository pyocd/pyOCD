# pyOCD debugger
# Copyright (c) 2026 Firat Hajiyev
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

import argparse
from unittest.mock import Mock

import pytest

from pyocd.subcommands.info_cmd import InfoSubcommand


def test_probe_info_is_printed_before_target_discovery(monkeypatch, capsys):
    args = argparse.Namespace(
        project_dir=None,
        config=None,
        script=None,
        no_config=None,
        pack=None,
        cbuild_run=None,
        unique_id=None,
        target_override=None,
        frequency=None,
        connect_mode=None,
        cmd="info",
        options=None,
    )
    session = Mock()
    session.probe.description = "Test Probe"
    session.probe.unique_id = "1234"
    session.probe.supported_wire_protocols = []
    session.probe.capabilities = []
    session.open.side_effect = RuntimeError("target discovery failed")
    monkeypatch.setattr(
        "pyocd.subcommands.info_cmd.ConnectHelper.session_with_chosen_probe",
        Mock(return_value=session),
    )

    with pytest.raises(RuntimeError, match="target discovery failed"):
        InfoSubcommand(args).invoke()

    assert capsys.readouterr().out == "Debug Probe: Test Probe [1234]\n"
    session.close.assert_called_once_with()
