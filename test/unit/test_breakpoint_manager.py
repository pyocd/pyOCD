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

"""@brief Tests for committing pending breakpoint removals to the target.

A removal that has been acknowledged must be physically committed before control returns, so
that a session which ends without a further resume or step leaves no breakpoint armed in the
target. Pending additions must stay deferred until the next flush().
"""

import pytest

from pyocd.core import exceptions
from pyocd.core.target import Target
from pyocd.debug.breakpoints.manager import UnrealizedBreakpoint

from .mock_breakpoints import (
    BKPT_INSTR,
    BreakpointHarness,
    COMP_FLASH_A,
    COMP_FLASH_B,
    COMP_RAM_R,
    FLASH_A,
    FLASH_B,
    FLASH_C,
    FP_COMP0_ADDR,
    FP_COMP1_ADDR,
    OP_AP_WRITE,
    OP_CORE_WRITE,
    OP_FLUSH,
    OP_INVALIDATE,
    ORIGINAL_INSTR,
    RAM_R,
    make_harness,
)

HW = Target.BreakpointType.HW
SW = Target.BreakpointType.SW


@pytest.fixture
def harness() -> BreakpointHarness:
    return make_harness()


class TestBreakpointManagerRemovals:
    def test_hw_removal_committed_before_next_run(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        core.resume()
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert fpb.num_hw_breakpoint_used == 1

        core.halt()
        manager.remove_breakpoint(FLASH_A)
        events_before = list(core.pre_run_events)
        harness.trace.clear()

        manager.flush_removals()

        assert ap.mem[FP_COMP0_ADDR] == 0
        assert fpb.available_breakpoints == 2
        assert fpb.find_breakpoint(FLASH_A) is None
        assert FLASH_A not in manager.get_breakpoints()
        assert manager.find_breakpoint(FLASH_A) is None
        assert core.flush_calls == 1
        # The comparator is cleared first and the probe queue is drained afterwards, so the
        # write cannot still be sitting in the host queue when the commit returns.
        assert harness.trace == [
            (OP_AP_WRITE, FP_COMP0_ADDR, 0),
            (OP_FLUSH,),
            ]
        # The commit must not resume or step the core.
        assert core.pre_run_events == events_before

    def test_sw_removal_committed_before_next_run(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap
        sw_provider = harness.sw_provider

        core.write16(RAM_R, ORIGINAL_INSTR)
        assert manager.set_breakpoint(RAM_R, SW) is True
        core.resume()
        assert core.read16(RAM_R) == BKPT_INSTR
        assert sw_provider.find_breakpoint(RAM_R) is not None

        core.halt()
        manager.remove_breakpoint(RAM_R)
        core.invalidated.clear()
        harness.trace.clear()

        manager.flush_removals()

        assert core.read16(RAM_R) == ORIGINAL_INSTR
        assert core.invalidated == [RAM_R]
        assert sw_provider.find_breakpoint(RAM_R) is None
        assert RAM_R not in manager.get_breakpoints()
        assert core.flush_calls == 1
        # The halfword is restored and the cache invalidated first, the probe queue drained last.
        assert harness.trace == [
            (OP_CORE_WRITE, RAM_R, ORIGINAL_INSTR),
            (OP_INVALIDATE, RAM_R),
            (OP_FLUSH,),
            ]
        # A software breakpoint must not touch a comparator.
        assert ap.comp_writes() == []

    def test_soft_bkpt_as_hard_removal_frees_comparator(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap

        core.write16(RAM_R, ORIGINAL_INSTR)
        # An FPBv2 accepts ram addresses, which is what soft_bkpt_as_hard relies on.
        assert manager.set_breakpoint(RAM_R, HW) is True
        core.resume()
        assert ap.mem[FP_COMP0_ADDR] == COMP_RAM_R
        assert core.read16(RAM_R) == ORIGINAL_INSTR
        assert harness.sw_provider.find_breakpoint(RAM_R) is None

        core.halt()
        manager.remove_breakpoint(RAM_R)

        manager.flush_removals()

        assert ap.mem[FP_COMP0_ADDR] == 0
        assert fpb.available_breakpoints == 2
        assert core.read16(RAM_R) == ORIGINAL_INSTR
        assert RAM_R not in manager.get_breakpoints()
        assert core.flush_calls == 1

    def test_stop_resume_churn_installs_once(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        core.resume()
        core.halt()
        manager.remove_breakpoint(FLASH_A)

        manager.flush_removals()

        assert ap.mem[FP_COMP0_ADDR] == 0
        assert fpb.num_hw_breakpoint_used == 0

        # gdb reinserts the breakpoint before the next resume; that addition stays deferred.
        assert manager.set_breakpoint(FLASH_A, HW) is True
        assert len(ap.comp_writes()) == 2
        core.resume()

        enabled = [bp for bp in fpb.hw_breakpoints if bp.enabled]
        assert len(enabled) == 1
        assert enabled[0].addr == FLASH_A
        assert fpb.num_hw_breakpoint_used == 1
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert ap.mem[FP_COMP1_ADDR] == 0
        assert ap.comp_writes() == [
            (FP_COMP0_ADDR, COMP_FLASH_A),
            (FP_COMP0_ADDR, 0),
            (FP_COMP0_ADDR, COMP_FLASH_A),
            ]

    def test_pending_addition_stays_deferred(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True

        manager.flush_removals()

        assert ap.writes == []
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert ap.mem[FP_COMP1_ADDR] == 0
        assert core.flush_calls == 0
        assert FLASH_A not in manager.get_breakpoints()
        assert manager.find_breakpoint(FLASH_A) is not None

        core.resume()

        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert FLASH_A in manager.get_breakpoints()

    def test_mixed_removal_and_addition_commits_only_removal(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        core.resume()
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        core.halt()

        # gdb deletes one breakpoint and creates another one while the core is stopped, so a
        # removal and an addition are pending at the same time.
        manager.remove_breakpoint(FLASH_A)
        assert manager.set_breakpoint(FLASH_B, HW) is True
        harness.trace.clear()

        manager.flush_removals()

        # The removal is committed, ...
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert fpb.find_breakpoint(FLASH_A) is None
        assert fpb.num_hw_breakpoint_used == 0
        assert FLASH_A not in manager.get_breakpoints()
        assert manager.find_breakpoint(FLASH_A) is None
        # ... and the addition is not: clearing the comparator and draining the queue are the
        # only things that touched the target.
        assert harness.trace == [
            (OP_AP_WRITE, FP_COMP0_ADDR, 0),
            (OP_FLUSH,),
            ]
        assert ap.mem[FP_COMP1_ADDR] == 0
        assert FLASH_B not in manager.get_breakpoints()
        assert fpb.find_breakpoint(FLASH_B) is None
        assert isinstance(manager.find_breakpoint(FLASH_B), UnrealizedBreakpoint)

        core.resume()

        assert FLASH_B in manager.get_breakpoints()
        assert manager.get_breakpoint_type(FLASH_B) == HW
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_B
        assert ap.mem[FP_COMP1_ADDR] == 0
        assert fpb.num_hw_breakpoint_used == 1

    def test_hw_allocation_unchanged_for_representative_sequence(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        assert manager.set_breakpoint(FLASH_B, HW) is True
        core.resume()
        assert fpb.num_hw_breakpoint_used == 2
        assert fpb.available_breakpoints == 0

        core.halt()
        manager.remove_breakpoint(FLASH_A)
        manager.remove_breakpoint(FLASH_B)

        manager.flush_removals()

        assert fpb.available_breakpoints == 2
        assert ap.mem[FP_COMP0_ADDR] == 0
        assert ap.mem[FP_COMP1_ADDR] == 0

        # Both comparators are free again, so both breakpoints can be re-added and the third
        # one is still refused: the same allocation result as before the early commit, where the
        # pending removals credited two comparators and the pending additions debited them.
        assert manager.set_breakpoint(FLASH_A, HW) is True
        assert manager.set_breakpoint(FLASH_B, HW) is True
        assert manager.set_breakpoint(FLASH_C, HW) is False
        assert manager.find_breakpoint(FLASH_C) is None

        core.resume()

        assert manager.get_breakpoint_type(FLASH_A) == HW
        assert manager.get_breakpoint_type(FLASH_B) == HW
        assert FLASH_C not in manager.get_breakpoints()
        assert fpb.num_hw_breakpoint_used == 2
        assert fpb.find_breakpoint(FLASH_A) is not None
        assert fpb.find_breakpoint(FLASH_B) is not None
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert ap.mem[FP_COMP1_ADDR] == COMP_FLASH_B

    def test_remove_never_set_is_noop(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap

        manager.remove_breakpoint(FLASH_B)

        manager.flush_removals()

        assert ap.writes == []
        assert core.flush_calls == 0
        assert bytes(core.ram) == bytes(1024)
        assert list(manager.get_breakpoints()) == []

    def test_remove_unflushed_addition_is_bookkeeping_only(self, harness: BreakpointHarness) -> None:
        core, manager, fpb, ap = harness.core, harness.manager, harness.fpb, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        manager.remove_breakpoint(FLASH_A)

        manager.flush_removals()

        assert ap.writes == []
        assert fpb.num_hw_breakpoint_used == 0
        assert core.flush_calls == 0
        assert manager.find_breakpoint(FLASH_A) is None
        assert FLASH_A not in manager.get_breakpoints()

        core.resume()

        assert ap.writes == []

    def test_removal_deferred_while_running(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        core.resume()
        assert core.get_state() == Target.State.RUNNING
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A

        manager.remove_breakpoint(FLASH_A)

        manager.flush_removals()

        # Restoring memory or clearing a comparator under a running core is not safe, so the
        # removal stays pending exactly as it does today.
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert FLASH_A in manager.get_breakpoints()
        assert core.flush_calls == 0

        core.halt()
        core.resume()

        assert ap.mem[FP_COMP0_ADDR] == 0
        assert FLASH_A not in manager.get_breakpoints()

    def test_failed_hw_removal_raises_and_keeps_breakpoint_pending(self, harness: BreakpointHarness) -> None:
        core, manager, ap = harness.core, harness.manager, harness.ap

        assert manager.set_breakpoint(FLASH_A, HW) is True
        core.resume()
        core.halt()

        ap.fail_writes = True
        manager.remove_breakpoint(FLASH_A)

        with pytest.raises(exceptions.Error):
            manager.flush_removals()

        # The breakpoint stays live and its removal stays pending, so the next flush retries it.
        assert FLASH_A in manager.get_breakpoints()
        assert manager.find_breakpoint(FLASH_A) is None
        assert ap.mem[FP_COMP0_ADDR] == COMP_FLASH_A
        assert core.flush_calls == 0

    def test_failed_sw_removal_is_detected(self, harness: BreakpointHarness) -> None:
        core, manager = harness.core, harness.manager
        sw_provider = harness.sw_provider

        core.write16(RAM_R, ORIGINAL_INSTR)
        assert manager.set_breakpoint(RAM_R, SW) is True
        core.resume()
        core.halt()

        core.fail_writes = True
        manager.remove_breakpoint(RAM_R)

        # The software provider swallows the transfer error and keeps its entry, so the failure
        # has to be detected through the provider instead of an exception from it.
        with pytest.raises(exceptions.DebugError):
            manager.flush_removals()

        assert RAM_R in manager.get_breakpoints()
        assert sw_provider.find_breakpoint(RAM_R) is not None
        assert core.read16(RAM_R) == BKPT_INSTR
        assert core.flush_calls == 0

        core.fail_writes = False
        core.resume()

        assert core.read16(RAM_R) == ORIGINAL_INSTR
        assert sw_provider.find_breakpoint(RAM_R) is None
