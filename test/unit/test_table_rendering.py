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

import argparse
from types import SimpleNamespace

import pytest

from pyocd.core.helpers import ConnectHelper
from pyocd.subcommands.base import SubcommandBase


@pytest.mark.parametrize("header", [True, False])
def test_subcommand_table_rendering(header):
    command = SubcommandBase(argparse.Namespace(no_header=not header))
    table = command._get_pretty_table(["Name", "Value"])
    table.add_row(["sample", "42"])
    rendered = table.get_string()
    assert "sample" in rendered
    assert "42" in rendered
    assert ("Name" in rendered) == header
    assert "|" not in rendered


def test_probe_selection_table_rendering(capsys):
    probe = SimpleNamespace(associated_board_info=None,
                            description="Example probe", unique_id="example-123")
    ConnectHelper._print_probe_list([probe])
    rendered = capsys.readouterr().out
    assert "Example probe" in rendered
    assert "example-123" in rendered
    assert "Probe/Board" in rendered
    assert "|" not in rendered
