# pyOCD debugger
# Copyright (c) 2016-2020,2025 Arm Limited
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

from ..core import exceptions
from ..coresight.cortex_m_core_registers import (CortexMCoreRegisterInfo, index_for_reg)
from .metrics import CacheMetrics

LOG = logging.getLogger(__name__)

class RegisterCache(object):
    """@brief Cache of a core's register values.

    The only interesting part of this cache is how it handles the special registers: CONTROL,
    FAULTMASK, BASEPRI, PRIMASK, and CFBP. The values of the first four registers are read and written
    all at once as the CFBP register through the hardware DCRSR register. On reads of any of these
    registers, or the combined CFBP, the cache will ask the underlying context to read CFBP. It will
    then update the cache entries for all five registers. Writes to any of these registers just
    invalidate all five.

    Same logic applies for XPSR submasks.
    """

    CFBP_INDEX_LIST = [
        index_for_reg('cfbp'),
        index_for_reg('cfbp_s'),
        index_for_reg('cfbp_ns')
    ]

    CFBP_REGS_LIST = [
        [index_for_reg(name) for name in ['control',    'faultmask',    'basepri',    'primask'   ]],
        [index_for_reg(name) for name in ['control_s',  'faultmask_s',  'basepri_s',  'primask_s' ]],
        [index_for_reg(name) for name in ['control_ns', 'faultmask_ns', 'basepri_ns', 'primask_ns']]
    ]

    XPSR_INDEX = index_for_reg('xpsr')

    XPSR_REGS = [
        index_for_reg(name) for name in ['apsr', 'iapsr', 'eapsr', 'ipsr', 'epsr', 'iepsr']
    ]

    SP_REGS = [
        index_for_reg(name) for name in ['sp', 'msp', 'psp', 'msp_s', 'psp_s', 'msp_ns', 'psp_ns']
    ]

    def __init__(self, context, core):
        self._context = context
        self._core = core
        self._run_token = -1
        self._reset_cache()

    def _reset_cache(self):
        self._cache = {}
        self._metrics = CacheMetrics()

    def _dump_metrics(self):
        if self._metrics.total > 0:
            LOG.debug("%d reads [%d%% hits, %d regs]", self._metrics.total, self._metrics.percent_hit, self._metrics.hits)
        else:
            LOG.debug("no accesses")

    def _check_cache(self):
        """@brief Invalidates the cache if needed and returns whether the core is running."""
        if self._core.is_running():
            LOG.debug("core is running; invalidating cache")
            self._reset_cache()
            return True
        elif self._run_token != self._core.run_token:
            self._dump_metrics()
            LOG.debug("out of date run token; invalidating cache")
            self._reset_cache()
            self._run_token = self._core.run_token
        return False

    def _convert_and_check_registers(self, reg_list):
        # convert to index only
        reg_list = [index_for_reg(reg) for reg in reg_list]
        self._core.check_reg_list(reg_list)
        return reg_list

    def read_core_registers_raw(self, reg_list):
        # Invalidate the cache. If the core is still running, just read directly from it.
        if self._check_cache():
            return self._context.read_core_registers_raw(reg_list)

        reg_list = self._convert_and_check_registers(reg_list)
        reg_set = set(reg_list)

        # Get list of values we have cached.
        cached_set = set(r for r in reg_list if r in self._cache)
        self._metrics.hits += len(cached_set)

        # Create list of uncached registers.
        read_list = list(reg_set.difference(cached_set))

        read_cfbp_flags = []
        for index, regs in zip(self.CFBP_INDEX_LIST, self.CFBP_REGS_LIST):
            read_cfpb = any(r for r in read_list if r in regs or r == index)
            read_cfbp_flags.append(read_cfpb)
            if read_cfpb and index not in read_list:
                read_list.append(index)

        read_xpsr = any(r for r in read_list if r in self.XPSR_REGS or r == self.XPSR_INDEX)
        if read_xpsr and self.XPSR_INDEX not in read_list:
            read_list.append(self.XPSR_INDEX)

        self._metrics.misses += len(read_list)

        # Read registers not in the cache from the target.
        if read_list:
            try:
                values = self._context.read_core_registers_raw(read_list)
            except exceptions.CoreRegisterAccessError:
                # Invalidate cache on register read error just to be safe.
                self._reset_cache()
                raise
        else:
            values = []

        # Update all CFBP based registers.
        for read_cfbp, index, regs in zip(read_cfbp_flags, self.CFBP_INDEX_LIST, self.CFBP_REGS_LIST):
            if read_cfbp:
                i = read_list.index(index)
                v = values[i]
                self._cache[index] = v
                for r in regs:
                    self._cache[r] = (v >> ((r & 3) * 8)) & 0xff

        # Update all XPSR based registers.
        if read_xpsr:
            i = read_list.index(self.XPSR_INDEX)
            v = values[i]
            self._cache[self.XPSR_INDEX] = v
            for r in self.XPSR_REGS:
                self._cache[r] = v & CortexMCoreRegisterInfo.get(r).psr_mask

        # Build the results list in the same order as requested registers.
        results = []
        for r in reg_list:
            if r in cached_set:
                results.append(self._cache[r])
            else:
                i = read_list.index(r)
                v = values[i]
                results.append(v)
                self._cache[r] = v

        return results

    # TODO only write dirty registers to target right before running.
    def write_core_registers_raw(self, reg_list, data_list):
        # Check and invalidate the cache. If the core is still running, just pass the writes
        # to our context.
        if self._check_cache():
            self._context.write_core_registers_raw(reg_list, data_list)
            return

        reg_list = self._convert_and_check_registers(reg_list)
        self._metrics.writes += len(reg_list)

        # Update cached register values.
        for i, r in enumerate(reg_list):
            v = data_list[i]
            self._cache[r] = v

        # Remove cached CFBP based register values when writing to them.
        if any(r for r in reg_list if r in self.CFBP_INDEX_LIST):
            # If writing to any variant of CFBP register, remove all CFBP based registers from the cache.
            for index, regs in zip(self.CFBP_INDEX_LIST, self.CFBP_REGS_LIST):
                for r in regs + [index]:
                    self._cache.pop(r, None)
        else:
            # If writing to any variant of CFBP sub-register (CONTROL, FAULTMASK, BASEPRI, PRIMASK),
            # remove only variants of that sub-register from the cache.
            for pos in range(len(self.CFBP_REGS_LIST[0])):
                sub_regs = [regs[pos] for regs in self.CFBP_REGS_LIST]
                if any(r in sub_regs for r in reg_list):
                    for r in sub_regs:
                        self._cache.pop(r, None)

        # Remove all cached XPSR based register values when writing any of them.
        if any(r for r in reg_list if r in self.XPSR_REGS or r == self.XPSR_INDEX):
            for r in self.XPSR_REGS + [self.XPSR_INDEX]:
                self._cache.pop(r, None)

        # Remove all cached SP register values when writing any of them.
        if any(r for r in reg_list if r in self.SP_REGS):
            for r in self.SP_REGS:
                self._cache.pop(r, None)

        # Write new register values to target.
        try:
            self._context.write_core_registers_raw(reg_list, data_list)
        except exceptions.CoreRegisterAccessError:
            # Invalidate cache on register write error just to be safe.
            self._reset_cache()
            raise

    def invalidate(self):
        self._reset_cache()
