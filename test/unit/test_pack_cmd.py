# pyOCD debugger
# Copyright (c) 2026 Giridhar
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

from argparse import Namespace
from types import SimpleNamespace

import pytest

from pyocd.subcommands.pack_cmd import (
    PackFindSubcommand,
    PackInstallSubcommand,
    PackSubcommand,
    )


@pytest.fixture
def cache():
    return SimpleNamespace(index={"KnownDevice": {}})


def test_pack_find_returns_error_when_no_device_matches(monkeypatch, cache):
    command = PackFindSubcommand(Namespace(
        patterns=["MissingDevice"],
        update=False,
        clean=False,
        no_header=False,
        verbose=0,
        quiet=0,
        ))
    monkeypatch.setattr(command, "_get_cache", lambda: cache)

    assert command.invoke() == 1


def test_pack_install_returns_error_when_no_device_matches(monkeypatch, cache):
    command = PackInstallSubcommand(Namespace(
        patterns=["MissingDevice"],
        update=False,
        clean=False,
        no_download=False,
        verbose=0,
        quiet=0,
        ))
    monkeypatch.setattr(command, "_get_cache", lambda: cache)

    assert command.invoke() == 1


@pytest.mark.parametrize(("find_devices", "install_devices"), [
    (["MissingDevice"], None),
    (None, ["MissingDevice"]),
    ])
def test_deprecated_pack_options_return_error_when_no_device_matches(
        monkeypatch, cache, find_devices, install_devices):
    command = PackSubcommand(Namespace(
        clean=False,
        update=False,
        show=False,
        find_devices=find_devices,
        install_devices=install_devices,
        no_download=False,
        no_header=False,
        verbose=0,
        quiet=0,
        ))
    monkeypatch.setattr(command, "_get_cache", lambda: cache)

    assert command.invoke() == 1
