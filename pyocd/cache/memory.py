# pyOCD debugger
# Copyright (c) 2016-2020 Arm Limited
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

from intervaltree import (Interval, IntervalTree)
import logging

from ..utility import conversion
from .metrics import CacheMetrics
from ..core.exceptions import TransferFaultError

LOG = logging.getLogger(__name__)

class MemoryCache(object):
    """! @brief Memory cache.
    
    Maintains a cache of target memory. The constructor is passed a backing DebugContext object that
    will be used to fill the cache.
    
    The cache is invalidated whenever the target has run since the last cache operation (based on run
    tokens). If the target is currently running, all accesses cause the cache to be invalidated.
    
    The target's memory map is referenced. All memory accesses must be fully contained within a single
    memory region, or a TransferFaultError will be raised. However, if an access is outside of all regions,
    the access is passed to the underlying context unmodified. When an access is within a region, that
    region's cacheability flag is honoured.
    """
    
    def __init__(self, context, core):
        self._context = context
        self._core = core
        self._run_token = -1
        self._reset_cache()

    def _reset_cache(self):
        self._cache = IntervalTree()
        self._metrics = CacheMetrics()

    def _check_cache(self):
        """! @brief Invalidates the cache if appropriate."""
        if self._core.is_running():
            LOG.debug("core is running; invalidating cache")
            self._reset_cache()
        elif self._run_token != self._core.run_token:
            self._dump_metrics()
            LOG.debug("out of date run token; invalidating cache")
            self._reset_cache()
            self._run_token = self._core.run_token

    def _get_ranges(self, addr, count):
        """! @brief Splits a memory address range into cached and uncached subranges.
        @return Returns a 2-tuple with the first element being a set of Interval objects for each
          of the cached subranges. The second element is a set of Interval objects for each of the
          non-cached subranges.
        """
        cached = self._cache.overlap(addr, addr + count)
        uncached = {Interval(addr, addr + count)}
        for cachedIv in cached:
            newUncachedSet = set()
            for uncachedIv in uncached:

                # No overlap.
                if cachedIv.end < uncachedIv.begin or cachedIv.begin > uncachedIv.end:
                    newUncachedSet.add(uncachedIv)
                    continue

                # Begin segment.
                if cachedIv.begin - uncachedIv.begin > 0:
                    newUncachedSet.add(Interval(uncachedIv.begin, cachedIv.begin))

                # End segment.
                if uncachedIv.end - cachedIv.end > 0:
                    newUncachedSet.add(Interval(cachedIv.end, uncachedIv.end))
            uncached = newUncachedSet
        return cached, uncached

    def _read_uncached(self, uncached):
        """! "@brief Reads uncached memory ranges and updates the cache.
        @return A list of Interval objects is returned. Each Interval has its @a data attribute set
          to a bytearray of the data read from target memory.
        """
        uncachedData = []
        for uncachedIv in uncached:
            data = self._context.read_memory_block8(uncachedIv.begin, uncachedIv.end - uncachedIv.begin)
            iv = Interval(uncachedIv.begin, uncachedIv.end, bytearray(data))
            self._cache.add(iv) # TODO merge contiguous cached intervals
            uncachedData.append(iv)
        return uncachedData

    def _update_metrics(self, cached, uncached, addr, size):
        cachedSize = 0
        for iv in cached:
            begin = iv.begin
            end = iv.end
            if iv.begin < addr:
                begin = addr
            if iv.end > addr + size:
                end = addr + size
            cachedSize += end - begin

        uncachedSize = sum((iv.end - iv.begin) for iv in uncached)

        self._metrics.reads += 1
        self._metrics.hits += cachedSize
        self._metrics.misses += uncachedSize

    def _dump_metrics(self):
        if self._metrics.total > 0:
            LOG.debug("%d reads, %d bytes [%d%% hits, %d bytes]; %d bytes written",
                self._metrics.reads, self._metrics.total, self._metrics.percent_hit,
                self._metrics.hits, self._metrics.writes)
        else:
            LOG.debug("no reads")

    def _read(self, addr, size):
        """! @brief Performs a cached read operation of an address range.
        @return A list of Interval objects sorted by address.
        """
        # Get the cached and uncached subranges of the requested read.
        cached, uncached = self._get_ranges(addr, size)
        self._update_metrics(cached, uncached, addr, size)

        # Read any uncached ranges.
        uncachedData = self._read_uncached(uncached)

        # Merged cached with data we just read
        combined = list(cached) + uncachedData
        combined.sort(key=lambda x: x.begin)
        return combined

    def _merge_data(self, combined, addr, size):
        """! @brief Extracts data from the intersection of an address range across a list of interval objects.
        
        The range represented by @a addr and @a size are assumed to overlap the intervals. The first
        and last interval in the list may have ragged edges not fully contained in the address range, in
        which case the correct slice of those intervals is extracted.
        
        @param self
        @param combined List of Interval objects forming a contiguous range. The @a data attribute of
          each interval must be a bytearray.
        @param addr Start address. Must be within the range of the first interval.
        @param size Number of bytes. (@a addr + @a size) must be within the range of the last interval.
        @return A single bytearray object with all data from the intervals that intersects the address
          range.
        """
        result = bytearray()
        resultAppend = bytearray()

        # Check for fully contained subrange.
        if len(combined) and combined[0].begin < addr and combined[0].end > addr + size:
            offset = addr - combined[0].begin
            endOffset = offset + size
            result = combined[0].data[offset:endOffset]
            return result
        
        # Take slice of leading ragged edge.
        if len(combined) and combined[0].begin < addr:
            offset = addr - combined[0].begin
            result += combined[0].data[offset:]
            combined = combined[1:]
        # Take slice of trailing ragged edge.
        if len(combined) and combined[-1].end > addr + size:
            offset = addr + size - combined[-1].begin
            resultAppend = combined[-1].data[:offset]
            combined = combined[:-1]

        # Merge.
        for iv in combined:
            result += iv.data
        result += resultAppend

        return result

    def _update_contiguous(self, cached, addr, value):
        size = len(value)
        end = addr + size
        leadBegin = addr
        leadData = bytearray()
        trailData = bytearray()
        trailEnd = end

        if cached[0].begin < addr and cached[0].end > addr:
            offset = addr - cached[0].begin
            leadData = cached[0].data[:offset]
            leadBegin = cached[0].begin
        if cached[-1].begin < end and cached[-1].end > end:
            offset = end - cached[-1].begin
            trailData = cached[-1].data[offset:]
            trailEnd = cached[-1].end

        self._cache.remove_overlap(addr, end)

        data = leadData + value + trailData
        self._cache.addi(leadBegin, trailEnd, data)

    def _check_regions(self, addr, count):
        """! @return A bool indicating whether the given address range is fully contained within
              one known memory region, and that region is cacheable.
        @exception TransferFaultError Raised if the access is not entirely contained within a single region.
        """
        regions = self._core.memory_map.get_intersecting_regions(addr, length=count)

        # If no regions matched, then allow an uncached operation.
        if len(regions) == 0:
            return False

        # Raise if not fully contained within one region.
        if len(regions) > 1 or not regions[0].contains_range(addr, length=count):
            raise TransferFaultError("individual memory accesses must not cross memory region boundaries")

        # Otherwise return whether the region is cacheable.
        return regions[0].is_cacheable

    def read_memory(self, addr, transfer_size=32, now=True):
        # TODO use more optimal underlying read_memory calls
        if transfer_size == 8:
            data = self.read_memory_block8(addr, 1)[0]
        else:
            data = conversion.byte_list_to_nbit_le_list(self.read_memory_block8(addr, transfer_size // 8),
                    transfer_size)[0]

        if now:
            return data
        else:
            def read_cb():
                return data
            return read_cb

    def read_memory_block8(self, addr, size):
        if size <= 0:
            return []

        self._check_cache()

        # Validate memory regions.
        if not self._check_regions(addr, size):
            LOG.debug("range [%x:%x] is not cacheable", addr, addr+size)
            return self._context.read_memory_block8(addr, size)

        # Get the cached and uncached subranges of the requested read.
        combined = self._read(addr, size)

        # Extract data out of combined intervals.
        result = list(self._merge_data(combined, addr, size))
        assert len(result) == size, "result size ({}) != requested size ({})".format(len(result), size)
        return result

    def read_memory_block32(self, addr, size):
        return conversion.byte_list_to_u32le_list(self.read_memory_block8(addr, size*4))

    def write_memory(self, addr, value, transfer_size=32):
        if transfer_size == 8:
            return self.write_memory_block8(addr, [value])
        else:
            return self.write_memory_block8(addr, conversion.nbit_le_list_to_byte_list([value], transfer_size))

    def write_memory_block8(self, addr, value):
        if len(value) <= 0:
            return

        self._check_cache()

        # Validate memory regions.
        cacheable = self._check_regions(addr, len(value))

        # Write to the target first, so if it fails we don't update the cache.
        result = self._context.write_memory_block8(addr, value)

        if cacheable:
            size = len(value)
            end = addr + size
            cached = sorted(self._cache.overlap(addr, end), key=lambda x:x.begin)
            self._metrics.writes += size

            if len(cached):
                # Write data is entirely within a single cached interval.
                if addr >= cached[0].begin and end <= cached[0].end:
                    beginOffset = addr - cached[0].begin
                    endOffset = beginOffset + size
                    cached[0].data[beginOffset:endOffset] = value

                else:
                    self._update_contiguous(cached, addr, bytearray(value))
            else:
                # No cached data in this range, so just add the entire interval.
                self._cache.addi(addr, end, bytearray(value))

        return result

    def write_memory_block32(self, addr, data):
        return self.write_memory_block8(addr, conversion.u32le_list_to_byte_list(data))

    def invalidate(self):
        self._reset_cache()

