# pyOCD debugger
# Copyright (c) 2026 j4rvisstant
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

"""@brief Tests for the gdb breakpoint removal packets z0 and z1.

A z0/z1 that is acknowledged with OK while the core is halted must already be committed to the
target, so that a session ending without a further resume, step or disconnect leaves no
breakpoint armed. A failed commit must be reported as E01 rather than OK.
"""

import logging

import pytest

from pyocd.core.target import Target
from pyocd.debug.breakpoints.manager import UnrealizedBreakpoint

from .mock_breakpoints import (
    BKPT_INSTR,
    BreakpointHarness,
    COMP_FLASH_A,
    COMP_FLASH_B,
    COMP_RAM_R,
    E01_REPLY,
    FLASH_A,
    FLASH_B,
    FLASH_C,
    FP_COMP0_ADDR,
    FP_COMP1_ADDR,
    OK_REPLY,
    OP_AP_WRITE,
    OP_FLUSH,
    ORIGINAL_INSTR,
    RAM_R,
    bp_packet,
    make_harness,
    make_server,
)

GDBSERVER_LOGGER = 'pyocd.gdbserver.gdbserver'


@pytest.fixture
def harness() -> BreakpointHarness:
    return make_harness()


class TestGdbServerBreakpointRemoval:
    def test_z1_commits_removal_before_any_run(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap
        server = make_server(harness)

        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        core.resume()
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        core.halt()

        reply = server.breakpoint(None, bp_packet(b'z1', FLASH_A))

        assert reply == server.create_rsp_packet(b'OK')
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert fpb.available_breakpoints == 2
        assert FLASH_A not in manager.get_breakpoints()
        assert core.flush_calls == 1
        # Nothing resumed, stepped or disconnected after the z1.
        assert core.pre_run_events == [Target.RunType.RESUME]

    def test_z0_ram_commits_removal_before_any_run(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap
        sw_provider = harness.sw_provider
        server = make_server(harness, soft_bkpt_as_hard=False)

        core.write16(RAM_R, ORIGINAL_INSTR)
        assert server.breakpoint(None, bp_packet(b'Z0', RAM_R)) == OK_REPLY
        core.resume()
        assert core.read16(RAM_R) == BKPT_INSTR
        core.halt()

        reply = server.breakpoint(None, bp_packet(b'z0', RAM_R))

        assert reply == server.create_rsp_packet(b'OK')
        assert core.read16(RAM_R) == ORIGINAL_INSTR
        assert sw_provider.find_breakpoint(RAM_R) is None
        assert RAM_R not in manager.get_breakpoints()
        assert core.flush_calls == 1
        assert ap.comp_writes() == []

    def test_z0_soft_bkpt_as_hard_frees_comparator(self, harness: BreakpointHarness) -> None:
        core, fpb, ap = harness.core, harness.fpb, harness.ap
        server = make_server(harness, soft_bkpt_as_hard=True)

        core.write16(RAM_R, ORIGINAL_INSTR)
        assert server.breakpoint(None, bp_packet(b'Z0', RAM_R)) == OK_REPLY
        core.resume()
        assert ap.mem[FP_COMP0_ADDR] == COMP_RAM_R
        assert core.read16(RAM_R) == ORIGINAL_INSTR
        core.halt()

        reply = server.breakpoint(None, bp_packet(b'z0', RAM_R))

        assert reply == server.create_rsp_packet(b'OK')
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert fpb.available_breakpoints == 2
        assert core.read16(RAM_R) == ORIGINAL_INSTR
        assert core.flush_calls == 1

    def test_gdb_stop_resume_churn(self, harness: BreakpointHarness) -> None:
        core, fpb, ap = harness.core, harness.fpb, harness.ap
        server = make_server(harness)

        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        core.resume()
        core.halt()
        assert server.breakpoint(None, bp_packet(b'z1', FLASH_A)) == OK_REPLY
        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        # The reinsertion is still deferred until the resume.
        assert len(ap.comp_writes()) == 2
        core.resume()

        enabled = [bp for bp in fpb.hw_breakpoints if bp.enabled]
        assert len(enabled) == 1
        assert enabled[0].addr == FLASH_A
        assert fpb.num_hw_breakpoint_used == 1
        assert ap.mem[FP_COMP1_ADDR] == 0
        assert ap.comp_writes() == [
            (FP_COMP0_ADDR, COMP_FLASH_A),
            (FP_COMP0_ADDR, 0),
            (FP_COMP0_ADDR, COMP_FLASH_A),
            ]

    def test_z1_with_pending_addition_commits_only_removal(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap
        server = make_server(harness)

        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        core.resume()
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        core.halt()

        # gdb inserts a new breakpoint and deletes the old one while the core is stopped, so a
        # removal and an addition are pending when the z1 is handled.
        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_B)) == OK_REPLY
        harness.trace.clear()

        reply = server.breakpoint(None, bp_packet(b'z1', FLASH_A))

        assert reply == OK_REPLY
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert FLASH_A not in manager.get_breakpoints()
        # Only the removal reached the target; the addition is still deferred.
        assert harness.trace == [
            (OP_AP_WRITE, FP_COMP0_ADDR, 0),
            (OP_FLUSH,),
            ]
        assert ap.mem[FP_COMP1_ADDR] == 0
        assert FLASH_B not in manager.get_breakpoints()
        assert isinstance(manager.find_breakpoint(FLASH_B), UnrealizedBreakpoint)

        core.resume()

        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_B
        assert FLASH_B in manager.get_breakpoints()
        assert fpb.num_hw_breakpoint_used == 1

    def test_pending_Z1_stays_deferred_until_resume(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap
        server = make_server(harness)

        reply = server.breakpoint(None, bp_packet(b'Z1', FLASH_A))

        assert reply == OK_REPLY
        assert ap.writes == []
        assert core.flush_calls == 0
        assert FLASH_A not in manager.get_breakpoints()
        assert manager.find_breakpoint(FLASH_A) is not None

        core.resume()

        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A

    def test_z1_for_unknown_address_is_ok_without_provider_call(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap
        server = make_server(harness)

        reply = server.breakpoint(None, bp_packet(b'z1', FLASH_C))

        assert reply == OK_REPLY
        assert ap.writes == []
        assert core.flush_calls == 0
        assert bytes(core.ram) == bytes(1024)
        assert list(manager.get_breakpoints()) == []

    def test_commit_failure_replies_E01_and_logs_error(
            self,
            harness: BreakpointHarness,
            caplog: "pytest.LogCaptureFixture",
            ) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap
        server = make_server(harness)

        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        core.resume()
        core.halt()
        ap.fail_writes = True

        with caplog.at_level(logging.ERROR, logger=GDBSERVER_LOGGER):
            reply = server.breakpoint(None, bp_packet(b'z1', FLASH_A))

        assert reply == server.create_rsp_packet(b'E01')
        assert reply == E01_REPLY
        errors = [r for r in caplog.records if r.name == GDBSERVER_LOGGER and r.levelno == logging.ERROR]
        assert len(errors) >= 1
        assert any('0x%08x' % FLASH_A in r.getMessage() for r in errors)
        # The breakpoint stays live with its removal pending, so the next flush retries it.
        assert FLASH_A in manager.get_breakpoints()
        assert manager.find_breakpoint(FLASH_A) is None
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert core.flush_calls == 0

    def test_flush_failure_replies_E01_and_logs_error(
            self,
            harness: BreakpointHarness,
            caplog: "pytest.LogCaptureFixture",
            ) -> None:
        core, ap = harness.core, harness.ap
        server = make_server(harness)

        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        core.resume()
        core.halt()
        # The comparator write itself succeeds and only the drain of the probe's transfer queue
        # fails, which is how an error on a deferred transfer surfaces.
        core.fail_flush = True
        harness.trace.clear()

        with caplog.at_level(logging.ERROR, logger=GDBSERVER_LOGGER):
            reply = server.breakpoint(None, bp_packet(b'z1', FLASH_A))

        assert reply == server.create_rsp_packet(b'E01')
        assert reply == E01_REPLY
        errors = [r for r in caplog.records if r.name == GDBSERVER_LOGGER and r.levelno == logging.ERROR]
        assert len(errors) >= 1
        assert any('0x%08x' % FLASH_A in r.getMessage() for r in errors)
        # The drain was attempted, and its failure is reported instead of being hidden behind OK.
        assert core.flush_calls == 1
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert harness.trace == [
            (OP_AP_WRITE, FP_COMP0_ADDR, 0),
            (OP_FLUSH,),
            ]

    def test_removal_while_running_is_deferred(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap
        server = make_server(harness)

        assert server.breakpoint(None, bp_packet(b'Z1', FLASH_A)) == OK_REPLY
        # Non-stop mode: gdb may send z while the core runs.
        core.resume()
        assert core.get_state() == Target.State.RUNNING

        reply = server.breakpoint(None, bp_packet(b'z1', FLASH_A))

        assert reply == OK_REPLY
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert FLASH_A in manager.get_breakpoints()
        assert core.flush_calls == 0

        core.halt()
        core.resume()

        assert ap.mem[FP_COMP0_ADDR] == 0
        assert FLASH_A not in manager.get_breakpoints()
