# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import logging
from copy import copy

from .provider import Breakpoint
from ...core.target import Target

LOG = logging.getLogger(__name__)

class UnrealizedBreakpoint(Breakpoint):
    """! @brief Breakpoint class used until a breakpoint's type is decided."""
    pass

class BreakpointManager(object):
    """! @brief Manages all breakpoints for one core.

    The most important function of the breakpoint manager is to decide which breakpoint provider
    to use when a breakpoint is added. The caller can request a particular breakpoint type, but
    the manager may decide to use another depending on the situation. For instance, it tries to
    keep one hardware breakpoint available to use for stepping.

    The manager is also responsible for optimising breakpoint adding and removing. When the caller
    requests to add or remove breakpoints, the target is not immediately modified. Instead, the
    add/remove request is recorded for later. Then, before the target is stepped or resumed, the
    manager flushes breakpoint changes to the target. It is at this point when it decides which
    provider to use for each new breakpoint.
    """

    ## Number of hardware breakpoints to try to keep available.
    MIN_HW_BREAKPOINTS = 0

    def __init__(self, core):
        self._breakpoints = {}
        self._updated_breakpoints = {}
        self._session = core.session
        self._core = core
        self._fpb = None
        self._providers = {}
        self._ignore_notifications = False

        # Subscribe to some notifications.
        self._session.subscribe(self._pre_run_handler, Target.Event.PRE_RUN)
        self._session.subscribe(self._pre_disconnect_handler, Target.Event.PRE_DISCONNECT)

    def add_provider(self, provider):
        self._providers[provider.bp_type] = provider
        if provider.bp_type == Target.BreakpointType.HW:
            self._fpb = provider

    def get_breakpoints(self):
        """! @brief Return a list of all breakpoint addresses."""
        return self._breakpoints.keys()

    def find_breakpoint(self, addr):
        return self._updated_breakpoints.get(addr, None)

    def set_breakpoint(self, addr, type=Target.BreakpointType.AUTO):
        """! @brief Set a hardware or software breakpoint at a specific location in memory.
        
        @retval True Breakpoint was set.
        @retval False Breakpoint could not be set.
        """
        LOG.debug("set bkpt type %s at 0x%x", type.name, addr)

        # Clear Thumb bit in case it is set.
        addr = addr & ~1

        # Check for an existing breakpoint at this address.
        bp = self.find_breakpoint(addr)
        if bp is not None:
            return True

        # Reuse breakpoint objects from the live list.
        if addr in self._breakpoints:
            bp = self._breakpoints[addr]
        else:
            # Create temp bp object. This will be replaced with the real object once
            # breakpoints are flushed and the provider sets the bp.
            bp = UnrealizedBreakpoint(self)
            bp.type = type
            bp.addr = addr

            # Check whether this breakpoint can be added when we flush.
            if not self._check_added_breakpoint(bp):
                return False

        self._updated_breakpoints[addr] = bp
        return True

    def _check_added_breakpoint(self, bp):
        """! @brief Check whether a new breakpoint is likely to actually be added when we flush.
        
        First, software breakpoints are assumed to always be addable. For hardware breakpoints,
        the current free hardware breakpoint count is updated based on the current set of to-be
        added and removed breakpoints. If there are enough free hardware breakpoints to meet the
        minimum requirement and still add the new breakpoint, True is returned.
        """
        # If there is no FPB available, just go by whether we can install a sw bp.
        if self._fpb is None:
            region = self._core.memory_map.get_region_for_address(bp.addr)
            return region is not None and region.is_writable
        
        likely_bp_type = self._select_breakpoint_type(bp, False)
        if likely_bp_type == Target.BreakpointType.SW:
            return True
        
        # Count updated hw breakpoints.
        free_hw_bp_count = self._fpb.available_breakpoints
        added, removed = self._get_updated_breakpoints()
        for bp in removed:
            if bp.type == Target.BreakpointType.HW:
                free_hw_bp_count += 1
        for bp in added:
            likely_bp_type = self._select_breakpoint_type(bp, False)
            if likely_bp_type == Target.BreakpointType.HW:
                free_hw_bp_count -= 1
        
        return free_hw_bp_count > self.MIN_HW_BREAKPOINTS

    def remove_breakpoint(self, addr):
        """! @brief Remove a breakpoint at a specific location."""
        try:
            LOG.debug("remove bkpt at 0x%x", addr)

            # Clear Thumb bit in case it is set.
            addr = addr & ~1

            # Remove bp from dict.
            del self._updated_breakpoints[addr]
        except KeyError:
            LOG.debug("Tried to remove breakpoint 0x%08x that wasn't set" % addr)

    def _get_updated_breakpoints(self):
        """! @brief Compute added and removed breakpoints since last flush.
        @return Bi-tuple of (added breakpoint list, removed breakpoint list).
        """
        added = []
        removed = []

        # Get added breakpoints.
        for bp in self._updated_breakpoints.values():
            if not bp.addr in self._breakpoints:
                added.append(bp)

        # Get removed breakpoints.
        for bp in self._breakpoints.values():
            if not bp.addr in self._updated_breakpoints:
                removed.append(bp)

        # Return the list of pages to update.
        return added, removed

    def _select_breakpoint_type(self, bp, allow_all_hw_bps):
        type = bp.type

        # Look up the memory type for the requested address.
        region = self._core.memory_map.get_region_for_address(bp.addr)
        if region is not None:
            is_writable = region.is_writable
        else:
            # No memory region - fallback to hardware breakpoints.
            type = Target.BreakpointType.HW
            is_writable = False

        in_hw_bkpt_range = (self._fpb is not None) and (self._fpb.can_support_address(bp.addr))
        have_hw_bp = (self._fpb is not None) \
                    and ((self._fpb.available_breakpoints > self.MIN_HW_BREAKPOINTS) \
                    or (allow_all_hw_bps and self._fpb.available_breakpoints > 0))

        # Determine best type to use if auto.
        if type == Target.BreakpointType.AUTO:
            # Use sw breaks for:
            #  1. Addresses outside the supported FPBv1 range of 0-0x1fffffff
            #  2. RAM regions by default.
            #  3. Number of remaining hw breaks are at or less than the minimum we want to keep.
            #
            # Otherwise use hw.
            if not in_hw_bkpt_range or (not have_hw_bp):
                if is_writable:
                    type = Target.BreakpointType.SW
                else:
                    LOG.debug("unable to set bp because no hw bp available")
                    return None
            else:
                type = Target.BreakpointType.HW

            LOG.debug("using type %s for auto bp", type.name)

        # Revert to sw bp if out of hardware breakpoint range.
        if (type == Target.BreakpointType.HW) and not in_hw_bkpt_range:
            if is_writable:
                LOG.debug("using sw bp instead because of unsupported addr")
                type = Target.BreakpointType.SW
            else:
                LOG.debug("could not fallback to software breakpoint")
                return None

        # Revert to hw bp if region is flash.
        if not is_writable:
            if in_hw_bkpt_range and have_hw_bp:
                LOG.debug("using hw bp instead because addr is flash")
                type = Target.BreakpointType.HW
            else:
                LOG.debug("could not fallback to hardware breakpoint")
                return None

        LOG.debug("selected bkpt type %s for addr 0x%x", type.name, bp.addr)
        return type

    def flush(self, is_step=False):
        try:
            # Ignore any notifications while we modify breakpoints.
            self._ignore_notifications = True

            added, removed = self._get_updated_breakpoints()
            LOG.debug("added=%s removed=%s", added, removed)

            # Handle removed breakpoints first by asking the providers to remove them.
            for bp in removed:
                assert bp.provider is not None
                bp.provider.remove_breakpoint(bp)
                del self._breakpoints[bp.addr]

            # Only allow use of all hardware breakpoints if we're not stepping and there is
            # only a single added breakpoint.
            allow_all_hw_bps = not is_step and len(added) == 1

            # Now handle added breakpoints.
            for bp in added:
                type = self._select_breakpoint_type(bp, allow_all_hw_bps)
                if type is None:
                    continue

                # Set the bp.
                try:
                    provider = self._providers[type]
                    bp = provider.set_breakpoint(bp.addr)
                except KeyError:
                    raise ValueError("Unknown breakpoint type %s" % type.name)

                # Save the bp.
                if bp is not None:
                    self._breakpoints[bp.addr] = bp

            # Update breakpoint lists.
            LOG.debug("bps after flush=%s", self._breakpoints)
            self._updated_breakpoints = copy(self._breakpoints)

            # Flush all providers.
            self._flush_all()
        finally:
            self._ignore_notifications = False

    def get_breakpoint_type(self, addr):
        bp = self.find_breakpoint(addr)
        return bp.type if (bp is not None) else None

    def filter_memory(self, addr, size, data):
        for provider in [p for p in self._providers.values() if p.do_filter_memory]:
            data = provider.filter_memory(addr, size, data)
        return data

    def filter_memory_unaligned_8(self, addr, size, data):
        for provider in [p for p in self._providers.values() if p.do_filter_memory]:
            for i, d in enumerate(data):
                data[i] = provider.filter_memory(addr + i, 8, d)
        return data

    def filter_memory_aligned_32(self, addr, size, data):
        for provider in [p for p in self._providers.values() if p.do_filter_memory]:
            for i, d in enumerate(data):
                data[i] = provider.filter_memory(addr + i, 32, d)
        return data

    def remove_all_breakpoints(self):
        """! @brief Remove all breakpoints immediately."""
        for bp in self._breakpoints.values():
            bp.provider.remove_breakpoint(bp)
        self._breakpoints = {}
        self._flush_all()

    def _flush_all(self):
        # Flush all providers.
        for provider in self._providers.values():
            provider.flush()

    def _pre_run_handler(self, notification):
        if not self._ignore_notifications:
            is_step = notification.data == Target.RunType.STEP
            self.flush(is_step)

    def _pre_disconnect_handler(self, notification):
        pass


