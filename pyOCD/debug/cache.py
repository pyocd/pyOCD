"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from .context import DebugContext
from ..coresight.cortex_m import (CORE_REGISTER, register_name_to_index)
from ..utility import conversion
from intervaltree import (Interval, IntervalTree)
import logging

## @brief Generic failure to access memory.
class MemoryAccessError(RuntimeError):
    pass

## @brief Holds hit ratio metrics for the caches.
class CacheMetrics(object):
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.reads = 0
        self.writes = 0

    @property
    def total(self):
        return self.hits + self.misses

    @property
    def percent_hit(self):
        if self.total > 0:
            return self.hits * 100.0 / self.total
        else:
            return 0

    @property
    def percent_miss(self):
        if self.total > 0:
            return self.misses * 100.0 / self.total
        else:
            return 0

## @brief Cache of a core's register values.
#
# The only interesting part of this cache is how it handles the special registers: CONTROL,
# FAULTMASK, BASEPRI, PRIMASK, and CFBP. The values of the first four registers are read and written
# all at once as the CFBP register through the hardware DCRSR register. On reads of any of these
# registers, or the combined CFBP, the cache will ask the underlying context to read CFBP. It will
# then update the cache entries for all five registers. Writes to any of these registers just
# invalidate all five.
class RegisterCache(object):

    CFBP_REGS = [   CORE_REGISTER['cfbp'],
                    CORE_REGISTER['control'],
                    CORE_REGISTER['faultmask'],
                    CORE_REGISTER['basepri'],
                    CORE_REGISTER['primask'],
                    ]

    def __init__(self, parentContext):
        self._context = parentContext
        self._run_token = -1
        self._log = logging.getLogger('regcache')
        self._reset_cache()

    def _reset_cache(self):
        self._cache = {}
        self._metrics = CacheMetrics()

    def _dump_metrics(self):
        if self._metrics.total > 0:
            self._log.debug("%d reads [%d%% hits, %d regs]", self._metrics.total, self._metrics.percent_hit, self._metrics.hits)
        else:
            self._log.debug("no accesses")

    def _check_cache(self):
        if self._context.core.isRunning():
            self._log.debug("core is running; invalidating cache")
            self._reset_cache()
        elif self._run_token != self._context.core.run_token:
            self._dump_metrics()
            self._log.debug("out of date run token; invalidating cache")
            self._reset_cache()
            self._run_token = self._context.core.run_token

    def _convert_and_check_registers(self, reg_list):
        # convert to index only
        reg_list = [register_name_to_index(reg) for reg in reg_list]

        # Sanity check register values
        for reg in reg_list:
            if reg not in CORE_REGISTER.values():
                raise ValueError("unknown reg: %d" % reg)
            elif ((reg >= 0x40) or (reg == 33)) and (not self._context.core.has_fpu):
                raise ValueError("attempt to read FPU register without FPU")

        return reg_list

    def readCoreRegistersRaw(self, reg_list):
        self._check_cache()

        reg_list = self._convert_and_check_registers(reg_list)
        reg_set = set(reg_list)

        # Get list of values we have cached.
        cached_set = set(r for r in reg_list if r in self._cache)
        self._metrics.hits += len(cached_set)

        # Read uncached registers from the target.
        read_list = list(reg_set.difference(cached_set))
        reading_cfbp = any(r for r in read_list if r in self.CFBP_REGS)
        if reading_cfbp:
            if not CORE_REGISTER['cfbp'] in read_list:
                read_list.append(CORE_REGISTER['cfbp'])
            cfbp_index = read_list.index(CORE_REGISTER['cfbp'])
        self._metrics.misses += len(read_list)
        values = self._context.readCoreRegistersRaw(read_list)

        # Update all CFBP based registers.
        if reading_cfbp:
            v = values[cfbp_index]
            self._cache[CORE_REGISTER['cfbp']] = v
            for r in self.CFBP_REGS:
                if r == CORE_REGISTER['cfbp']:
                    continue
                self._cache[r] = (v >> ((-r - 1) * 8)) & 0xff

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
    def writeCoreRegistersRaw(self, reg_list, data_list):
        self._check_cache()

        reg_list = self._convert_and_check_registers(reg_list)
        self._metrics.writes += len(reg_list)

        writing_cfbp = any(r for r in reg_list if r in self.CFBP_REGS)

        # Update cached register values.
        for i, r in enumerate(reg_list):
            v = data_list[i]
            self._cache[r] = v

        # Just remove all cached CFBP based register values.
        if writing_cfbp:
            for r in self.CFBP_REGS:
                try:
                    del self._cache[r]
                except KeyError:
                    pass

        # Write new register values to target.
        self._context.writeCoreRegistersRaw(reg_list, data_list)

    def invalidate(self):
        self._reset_cache()

## @brief Memory cache.
#
# Maintains a cache of target memory. The constructor is passed a backing DebugContext object that
# will be used to fill the cache.
#
# The cache is invalidated whenever the target has run since the last cache operation (based on run
# tokens). If the target is currently running, all accesses cause the cache to be invalidated.
#
# The target's memory map is referenced. All memory accesses must be fully contained within a single
# memory region, or a MemoryAccessError will be raised. However, if an access is outside of all regions,
# the access is passed to the underlying context unmodified. When an access is within a region, that
# region's cacheability flag is honoured.
class MemoryCache(object):
    def __init__(self, context):
        self._context = context
        self._run_token = -1
        self._log = logging.getLogger('memcache')
        self._reset_cache()

    def _reset_cache(self):
        self._cache = IntervalTree()
        self._metrics = CacheMetrics()

    ##
    # @brief Invalidates the cache if appropriate.
    def _check_cache(self):
        if self._context.core.isRunning():
            self._log.debug("core is running; invalidating cache")
            self._reset_cache()
        elif self._run_token != self._context.core.run_token:
            self._dump_metrics()
            self._log.debug("out of date run token; invalidating cache")
            self._reset_cache()
            self._run_token = self._context.core.run_token

    ##
    # @brief Splits a memory address range into cached and uncached subranges.
    # @return Returns a 2-tuple with the first element being a set of Interval objects for each
    #   of the cached subranges. The second element is a set of Interval objects for each of the
    #   non-cached subranges.
    def _get_ranges(self, addr, count):
        cached = self._cache.search(addr, addr + count)
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

    ##
    # @brief Reads uncached memory ranges and updates the cache.
    # @return A list of Interval objects is returned. Each Interval has its @a data attribute set
    #   to a bytearray of the data read from target memory.
    def _read_uncached(self, uncached):
        uncachedData = []
        for uncachedIv in uncached:
            data = self._context.readBlockMemoryUnaligned8(uncachedIv.begin, uncachedIv.end - uncachedIv.begin)
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
            self._log.debug("%d reads, %d bytes [%d%% hits, %d bytes]; %d bytes written",
                self._metrics.reads, self._metrics.total, self._metrics.percent_hit,
                self._metrics.hits, self._metrics.writes)
        else:
            self._log.debug("no reads")

    ##
    # @brief Performs a cached read operation of an address range.
    # @return A list of Interval objects sorted by address.
    def _read(self, addr, size):
        # Get the cached and uncached subranges of the requested read.
        cached, uncached = self._get_ranges(addr, size)
        self._update_metrics(cached, uncached, addr, size)

        # Read any uncached ranges.
        uncachedData = self._read_uncached(uncached)

        # Merged cached with data we just read
        combined = list(cached) + uncachedData
        combined.sort(key=lambda x: x.begin)
        return combined

    ##
    # @brief Extracts data from the intersection of an address range across a list of interval objects.
    #
    # The range represented by @a addr and @a size are assumed to overlap the intervals. The first
    # and last interval in the list may have ragged edges not fully contained in the address range, in
    # which case the correct slice of those intervals is extracted.
    #
    # @param self
    # @param combined List of Interval objects forming a contiguous range. The @a data attribute of
    #   each interval must be a bytearray.
    # @param addr Start address. Must be within the range of the first interval.
    # @param size Number of bytes. (@a addr + @a size) must be within the range of the last interval.
    # @return A single bytearray object with all data from the intervals that intersects the address
    #   range.
    def _merge_data(self, combined, addr, size):
        result = bytearray()
        resultAppend = bytearray()

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

    ##
    # @brief
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

    ##
    # @return A bool indicating whether the given address range is fully contained within
    #       one known memory region, and that region is cacheable.
    # @exception MemoryAccessError Raised if the access is not entirely contained within a single region.
    def _check_regions(self, addr, count):
        regions = self._context.core.memory_map.getIntersectingRegions(addr, length=count)

        # If no regions matched, then allow an uncached operation.
        if len(regions) == 0:
            return False

        # Raise if not fully contained within one region.
        if len(regions) > 1 or not regions[0].containsRange(addr, length=count):
            raise MemoryAccessError("individual memory accesses must not cross memory region boundaries")

        # Otherwise return whether the region is cacheable.
        return regions[0].isCacheable

    def readMemory(self, addr, transfer_size=32, now=True):
        # TODO use more optimal underlying readMemory call
        if transfer_size == 8:
            data = self.readBlockMemoryUnaligned8(addr, 1)[0]
        elif transfer_size == 16:
            data = conversion.byteListToU16leList(self.readBlockMemoryUnaligned8(addr, 2))[0]
        elif transfer_size == 32:
            data = conversion.byteListToU32leList(self.readBlockMemoryUnaligned8(addr, 4))[0]

        if now:
            return data
        else:
            def read_cb():
                return data
            return read_cb

    def readBlockMemoryUnaligned8(self, addr, size):
        if size <= 0:
            return []

        self._check_cache()

        # Validate memory regions.
        if not self._check_regions(addr, size):
            self._log.debug("range [%x:%x] is not cacheable", addr, addr+size)
            return self._context.readBlockMemoryUnaligned8(addr, size)

        # Get the cached and uncached subranges of the requested read.
        combined = self._read(addr, size)

        # Extract data out of combined intervals.
        result = list(self._merge_data(combined, addr, size))
        return result

    def readBlockMemoryAligned32(self, addr, size):
        return conversion.byteListToU32leList(self.readBlockMemoryUnaligned8(addr, size*4))

    def writeMemory(self, addr, value, transfer_size=32):
        if transfer_size == 8:
            return self.writeBlockMemoryUnaligned8(addr, [value])
        elif transfer_size == 16:
            return self.writeBlockMemoryUnaligned8(addr, conversion.u16leListToByteList([value]))
        elif transfer_size == 32:
            return self.writeBlockMemoryUnaligned8(addr, conversion.u32leListToByteList([value]))

    def writeBlockMemoryUnaligned8(self, addr, value):
        if len(value) <= 0:
            return

        self._check_cache()

        # Validate memory regions.
        cacheable = self._check_regions(addr, len(value))

        # Write to the target first, so if it fails we don't update the cache.
        result = self._context.writeBlockMemoryUnaligned8(addr, value)

        if cacheable:
            size = len(value)
            end = addr + size
            cached = sorted(self._cache.search(addr, end), key=lambda x:x.begin)
            self._metrics.writes += size

            if len(cached):
                # Write data is entirely within cached data.
                if addr >= cached[0].begin and end <= cached[0].end:
                    beginOffset = addr - cached[0].begin
                    endOffset = end - cached[0].end
                    cached[0].data[beginOffset:endOffset] = value

                else:
                    self._update_contiguous(cached, addr, bytearray(value))
            else:
                # No cached data in this range, so just add the entire interval.
                self._cache.addi(addr, end, bytearray(value))

        return result

    def writeBlockMemoryAligned32(self, addr, data):
        return self.writeBlockMemoryUnaligned8(addr, conversion.u32leListToByteList(data))

    def invalidate(self):
        self._reset_cache()

## @brief Debug context combining register and memory caches.
class CachingDebugContext(DebugContext):
    def __init__(self, parentContext):
        super(CachingDebugContext, self).__init__(parentContext.core)
        self._regcache = RegisterCache(parentContext)
        self._memcache = MemoryCache(parentContext)

    def writeMemory(self, addr, value, transfer_size=32):
        return self._memcache.writeMemory(addr, value, transfer_size)

    def readMemory(self, addr, transfer_size=32, now=True):
        return self._memcache.readMemory(addr, transfer_size, now)

    def writeBlockMemoryUnaligned8(self, addr, value):
        return self._memcache.writeBlockMemoryUnaligned8(addr, value)

    def writeBlockMemoryAligned32(self, addr, data):
        return self._memcache.writeBlockMemoryAligned32(addr, data)

    def readBlockMemoryUnaligned8(self, addr, size):
        return self._memcache.readBlockMemoryUnaligned8(addr, size)

    def readBlockMemoryAligned32(self, addr, size):
        return self._memcache.readBlockMemoryAligned32(addr, size)

    def readCoreRegistersRaw(self, reg_list):
        return self._regcache.readCoreRegistersRaw(reg_list)

    def writeCoreRegistersRaw(self, reg_list, data_list):
        return self._regcache.writeCoreRegistersRaw(reg_list, data_list)

    def invalidate(self):
        self._regcache.invalidate()
        self._memcache.invalidate()



