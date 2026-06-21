# pyOCD debugger
# Copyright (c) 2026 pyOCD contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Regression tests for `pyocd.tools.lists.StubProbe`."""

from pyocd.tools.lists import StubProbe


def test_stub_probe_unique_id_is_string():
    """`StubProbe` is used as a placeholder when no real probe is needed
    (e.g. by `ListGenerator.list_targets()` when called with a CMSIS-Pack
    file). It must satisfy the abstract members of `DebugProbe` that
    consumers touch on the stub."""
    assert StubProbe().unique_id == "0"


def test_stub_probe_capabilities_returns_empty_set():
    """Regression for #1959.

    `DebugProbe.capabilities` is abstract — accessing it on a class that
    does not override it raises `NotImplementedError`. Before this fix,
    `StubProbe` did not override it, so `pyocd list --targets
    --pack=<file>` failed silently the moment any code path queried the
    stub's capabilities. An empty set is the correct stub value: it
    truthfully reports that this placeholder has no real probe features.
    """
    caps = StubProbe().capabilities
    assert caps == set()
    # The set must be iterable and membership-testable so downstream
    # `Capability.X in probe.capabilities` checks behave as if the probe
    # simply lacks every feature, rather than crashing.
    assert hasattr(caps, "__iter__")
    assert hasattr(caps, "__contains__")
