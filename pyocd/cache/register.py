# pyOCD debugger
# Copyright (c) 2016-2020 Arm Limited
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
    """! @brief Cache of a core's register values.
    
    The only interesting part of this cache is how it handles the special registers: CONTROL,
    FAULTMASK, BASEPRI, PRIMASK, and CFBP. The values of the first four registers are read and written
    all at once as the CFBP register through the hardware DCRSR register. On reads of any of these
    registers, or the combined CFBP, the cache will ask the underlying context to read CFBP. It will
    then update the cache entries for all five registers. Writes to any of these registers just
    invalidate all five.
    
    Same logic applies for XPSR submasks.
    """

    CFBP_INDEX = index_for_reg('cfbp')
    XPSR_INDEX = index_for_reg('xpsr')
    
    CFBP_REGS = [index_for_reg(name) for name in [
                'cfbp',
                'control',
                'faultmask',
                'basepri',
                'primask',
                ]]

    XPSR_REGS = [index_for_reg(name) for name in [
                    'xpsr',
                    'apsr',
                    'iapsr',
                    'eapsr',
                    'ipsr',
                    'epsr',
                    'iepsr',
                    ]]

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
        """! @brief Invalidates the cache if needed and returns whether the core is running."""
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

        # Read uncached registers from the target.
        read_list = list(reg_set.difference(cached_set))
        reading_cfbp = any(r for r in read_list if r in self.CFBP_REGS)
        reading_xpsr = any(r for r in read_list if r in self.XPSR_REGS)
        if reading_cfbp:
            if not self.CFBP_INDEX in read_list:
                read_list.append(self.CFBP_INDEX)
            cfbp_index = read_list.index(self.CFBP_INDEX)
        if reading_xpsr:
            if not self.XPSR_INDEX in read_list:
                read_list.append(self.XPSR_INDEX)
            xpsr_index = read_list.index(self.XPSR_INDEX)
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
        if reading_cfbp:
            v = values[cfbp_index]
            self._cache[self.CFBP_INDEX] = v
            for r in self.CFBP_REGS:
                if r == self.CFBP_INDEX:
                    continue
                self._cache[r] = (v >> ((-r - 1) * 8)) & 0xff

        # Update all XPSR based registers.
        if reading_xpsr:
            v = values[xpsr_index]
            self._cache[self.XPSR_INDEX] = v
            for r in self.XPSR_REGS:
                if r == self.XPSR_INDEX:
                    continue
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

        writing_cfbp = any(r for r in reg_list if r in self.CFBP_REGS)
        writing_xpsr = any(r for r in reg_list if r in self.XPSR_REGS)

        # Update cached register values.
        for i, r in enumerate(reg_list):
            v = data_list[i]
            self._cache[r] = v

        # Just remove all cached CFBP and XPSR based register values.
        if writing_cfbp:
            for r in self.CFBP_REGS:
                self._cache.pop(r, None)

        if writing_xpsr:
            for r in self.XPSR_REGS:
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

