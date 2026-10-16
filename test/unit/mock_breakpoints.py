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

"""@brief Hardware-free doubles for the breakpoint removal tests.

The doubles are deliberately thin: the real BreakpointManager, the real SoftwareBreakpointProvider
and the real FPB are exercised over a fake core and a dict-backed fake access port, so the tests
can assert on actual comparator values and on the actual halfword in ram.

The fake access port and the fake core append to one shared trace, so a test can assert the order
in which the target was touched, not just the end state.

This module is intentionally not named test_* so pytest does not collect it.
"""

import threading
import types
from typing import (Any, Dict, List, Optional, Tuple)

from pyocd.core import exceptions
from pyocd.core.memory_interface import MemoryInterface
from pyocd.core.target import Target
from pyocd.coresight.fpb import FPB
from pyocd.debug.breakpoints.manager import BreakpointManager
from pyocd.debug.breakpoints.software import SoftwareBreakpointProvider
from pyocd.gdbserver.gdbserver import GDBServer
from pyocd.utility.notification import (Notification, Notifier)

from .mockcore import MockCore

## Base address used for the FPB in the fake access port.
FPB_BASE = 0xE0002000
FP_CTRL_ADDR = FPB_BASE + FPB.FP_CTRL
FP_COMP0_ADDR = FPB_BASE + FPB.FP_COMP0
FP_COMP1_ADDR = FP_COMP0_ADDR + 4

## FP_CTRL value presented by the fake access port.
#
# REV field 1 selects FPBv2, so ram addresses are hardware-breakpoint capable; NUM_CODE is 2 and
# NUM_LIT is 0.
FP_CTRL_REV2_TWO_COMPARATORS = 0x10000020

## Addresses in the MockCore flash region (0x0-0x3ff, not writable, so hardware breakpoints only).
FLASH_A = 0x100
FLASH_B = 0x200
FLASH_C = 0x300

## Address in the MockCore ram region (writable, so software breakpoints are possible).
RAM_R = 0x20000010

## Comparator values the FPBv2 encoding produces for the addresses above.
COMP_FLASH_A = (FLASH_A & 0xfffffffe) | 1
COMP_FLASH_B = (FLASH_B & 0xfffffffe) | 1
COMP_RAM_R = (RAM_R & 0xfffffffe) | 1

## Instruction placed in ram underneath a software breakpoint ('bx lr').
ORIGINAL_INSTR = 0x4770

## The instruction a software breakpoint writes over it.
BKPT_INSTR = SoftwareBreakpointProvider.BKPT_INSTR

## Expected gdb remote protocol replies.
OK_REPLY = b'$OK#9a'
E01_REPLY = b'$E01#a6'

## Operation names used in the shared trace. An entry is a tuple of the name and its arguments.
OP_AP_WRITE = 'ap_write'
OP_CORE_WRITE = 'core_write'
OP_INVALIDATE = 'invalidate'
OP_FLUSH = 'flush'

## One entry of the shared trace: the operation name followed by its arguments.
TraceEntry = Tuple[Any, ...]


class FakeAP(MemoryInterface):
    """@brief Dict-backed access port, so the real FPB can be driven without hardware.

    Only single-location accesses are implemented; that is all the FPB needs. The read32/write32
    shorthands of MemoryInterface work unchanged on top of them.
    """

    def __init__(self, trace: Optional[List[TraceEntry]] = None) -> None:
        self.mem: Dict[int, int] = {FP_CTRL_ADDR: FP_CTRL_REV2_TWO_COMPARATORS}
        self.writes: List[Tuple[int, int]] = []
        self.fail_writes: bool = False
        self.trace: List[TraceEntry] = trace if (trace is not None) else []

    def read_memory(self, addr: int, transfer_size: int = 32, now: bool = True) -> int:
        return self.mem.get(addr, 0)

    def write_memory(self, addr: int, value: int, transfer_size: int = 32) -> None:
        if self.fail_writes:
            raise exceptions.TransferError("fake AP write failure at 0x%08x" % addr)
        self.mem[addr] = value
        self.writes.append((addr, value))
        self.trace.append((OP_AP_WRITE, addr, value))

    def comp_writes(self) -> List[Tuple[int, int]]:
        """@brief Recorded writes that target an FPB comparator register."""
        return [w for w in self.writes if w[0] in (FP_COMP0_ADDR, FP_COMP1_ADDR)]


class BreakpointTestCore(MockCore):
    """@brief MockCore extended with what BreakpointManager and the sw provider require.

    MockCore has the memory map and byte-backed memory, but no session to subscribe to, no
    settable run state, no instruction cache maintenance and no flush().
    """

    def __init__(self, trace: Optional[List[TraceEntry]] = None) -> None:
        super().__init__()
        self.session = Notifier()
        self.state: Target.State = Target.State.HALTED
        self.has_cache: bool = False
        self.invalidated: List[Optional[int]] = []
        self.flush_calls: int = 0
        self.fail_writes: bool = False
        self.fail_flush: bool = False
        self.pre_run_events: List[Target.RunType] = []
        self.trace: List[TraceEntry] = trace if (trace is not None) else []
        self.session.subscribe(self._record_pre_run, Target.Event.PRE_RUN)

    def _record_pre_run(self, notification: Notification) -> None:
        self.pre_run_events.append(notification.data)

    def get_state(self) -> Target.State:
        return self.state

    def is_halted(self) -> bool:
        return self.state == Target.State.HALTED

    def is_running(self) -> bool:
        return self.state == Target.State.RUNNING

    def invalidate_instruction_cache(self, address: Optional[int] = None) -> None:
        self.invalidated.append(address)
        self.trace.append((OP_INVALIDATE, address))

    def flush(self) -> None:
        """@brief Drain the probe's queued transfers, as CortexM.flush() does.

        With fail_flush set the drain raises, which is how a transport error that only surfaces
        once deferred transfers are actually sent is simulated. The call is traced before it
        fails, so a test can tell an attempted drain from a missing one.
        """
        self.flush_calls += 1
        self.trace.append((OP_FLUSH,))
        if self.fail_flush:
            raise exceptions.TransferError("fake core flush failure")

    def write_memory(self, addr: int, value: int, transfer_size: int = 32) -> None:
        if self.fail_writes:
            raise exceptions.TransferError("fake core write failure at 0x%08x" % addr)
        self.trace.append((OP_CORE_WRITE, addr, value))
        super().write_memory(addr, value, transfer_size)

    def halt(self) -> None:
        self.state = Target.State.HALTED

    def resume(self) -> None:
        """@brief Send PRE_RUN and start running.

        Mirrors CortexM.resume(), which returns without sending PRE_RUN when the core is not
        halted. The fake deliberately does not call flush(), so flush_calls counts only the
        flushes requested by the code under test.
        """
        if self.state != Target.State.HALTED:
            return
        self.session.notify(Target.Event.PRE_RUN, self, Target.RunType.RESUME)
        self.state = Target.State.RUNNING

    def step(self) -> None:
        """@brief Send PRE_RUN for a single step; the core stays halted afterwards."""
        self.session.notify(Target.Event.PRE_RUN, self, Target.RunType.STEP)


class BreakpointHarness:
    """@brief The fake core plus the real manager and providers wired together."""

    def __init__(
            self,
            core: BreakpointTestCore,
            manager: BreakpointManager,
            sw_provider: SoftwareBreakpointProvider,
            fpb: FPB,
            ap: FakeAP,
            trace: List[TraceEntry],
            ) -> None:
        self.core = core
        self.manager = manager
        self.sw_provider = sw_provider
        self.fpb = fpb
        self.ap = ap
        ## Access port writes, core writes, cache invalidations and flushes in the order they
        ## happened. Shared by the fake access port and the fake core.
        self.trace = trace


def make_harness() -> BreakpointHarness:
    """@brief Build a harness wired like CortexM does it."""
    trace: List[TraceEntry] = []
    core = BreakpointTestCore(trace)
    manager = BreakpointManager(core)
    sw_provider = SoftwareBreakpointProvider(core)
    sw_provider.init()
    manager.add_provider(sw_provider)
    ap = FakeAP(trace)
    fpb = FPB(ap, addr=FPB_BASE)
    fpb.init()
    manager.add_provider(fpb)
    # Discard the writes made by FPB.init(): the FP_CTRL disable plus both comparators.
    ap.writes.clear()
    trace.clear()
    return BreakpointHarness(core, manager, sw_provider, fpb, ap, trace)


class FakeGdbTarget:
    """@brief Stand-in for the CortexM that the gdbserver handler talks to.

    The breakpoint methods are pure delegations to the breakpoint manager, exactly as in
    CortexM.
    """

    def __init__(self, harness: BreakpointHarness) -> None:
        self.core = harness.core
        self.bp_manager = harness.manager

    def set_breakpoint(self, addr: int, type: Target.BreakpointType = Target.BreakpointType.AUTO) -> bool:
        return self.bp_manager.set_breakpoint(addr, type)

    def remove_breakpoint(self, addr: int) -> None:
        self.bp_manager.remove_breakpoint(addr)

    def get_breakpoint_type(self, addr: int) -> Optional[Target.BreakpointType]:
        return self.bp_manager.get_breakpoint_type(addr)

    def get_state(self) -> Target.State:
        return self.core.get_state()

    def is_halted(self) -> bool:
        return self.core.is_halted()

    def resume(self) -> None:
        self.core.resume()

    def halt(self) -> None:
        self.core.halt()

    def flush(self) -> None:
        self.core.flush()


class ServerUnderTest(GDBServer):
    """@brief GDBServer carrying just enough state to run the breakpoint packet handler.

    GDBServer.__init__() needs a full session and binds a listening socket, so it is not called.
    Only the Thread base class is initialised, which keeps this object a usable Thread (pytest
    reads its repr when an assertion fails) without starting anything.
    """

    def __init__(self, target: FakeGdbTarget, soft_bkpt_as_hard: bool = False) -> None:
        threading.Thread.__init__(self, daemon=True)
        self.target = target
        self.soft_bkpt_as_hard = soft_bkpt_as_hard
        self.session = types.SimpleNamespace(log_tracebacks=False)
        self.lock = threading.RLock()


def make_server(harness: BreakpointHarness, soft_bkpt_as_hard: bool = False) -> ServerUnderTest:
    """@brief Build a socket-less gdbserver over the given harness."""
    return ServerUnderTest(FakeGdbTarget(harness), soft_bkpt_as_hard)


def bp_packet(command: bytes, addr: int, kind: int = 2) -> bytes:
    """@brief Build the payload that GDBServer.breakpoint() receives for a z/Z packet.

    The handler is passed msg[1:] and parses it with data.split(b'#')[0].split(b','), so the
    checksum is not validated and a placeholder is good enough.
    """
    return command + b',' + (b'%x' % addr) + b',' + (b'%d' % kind) + b'#00'
