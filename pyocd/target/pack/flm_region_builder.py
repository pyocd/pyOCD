# pyOCD debugger
# Copyright (c) 2022-2023 Chris Reed
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
from pathlib import PurePath
from typing import (Any, Dict, cast, TYPE_CHECKING)

from ...core.memory_map import (
    FlashRegion,
    MemoryMap,
    MemoryRange,
    MemoryType,
    RamRegion,
)
from .flash_algo import (PackFlashAlgo, FlashAlgoException)

if TYPE_CHECKING:
    from ...coresight.coresight_target import CoreSightTarget
    from ...core.memory_map import (MemoryMap)

LOG = logging.getLogger(__name__)

class FlmFlashRegionBuilder:
    """
    @brief Finishes the process of constructing flash regions with algos based on FLM files.

    If a flash region passed to finalise_region() is missing an algo dict but has an associated FLM
    algo file, the FLM will be loaded.
    """

    def __init__(self, target: "CoreSightTarget", memory_map: "MemoryMap") -> None:
        self._target = target
        self._session = target.session
        self._memory_map = memory_map

    def finalise_region(self, region: FlashRegion) -> bool:
        """@brief Load FLM file for the given flash region.

        The region is ignored if it has an algo dict already, or if it doesn't have an FLM file. Otherwise
        the algo dict is constructed from the FLM and subregions are added for each of the algo's sector
        size ranges.

        @return Boolean indicating whether the region was finalised successfully.
        """
        try:
            # If the region doesn't have an algo dict but does have an FLM file, try to load
            # the FLM and create the algo dict.
            if (region.algo is None) and (region.flm is not None):
                if isinstance(region.flm, (str, PurePath)):
                    flm_path = self._session.find_user_file(None, [str(region.flm)])
                    if flm_path is not None:
                        LOG.info("Creating flash algo for region %s from: %s", region.name, flm_path)
                        pack_algo = PackFlashAlgo(flm_path)
                    else:
                        LOG.warning("Failed to find FLM file: %s", region.flm)
                        return False
                elif isinstance(region.flm, PackFlashAlgo):
                    pack_algo = region.flm
                else:
                    LOG.warning("Flash region %s flm attribute is unexpected type", region)
                    return False

                # Log details of this flash algo if the debug option is enabled.
                if self._session.options.get("debug.log_flm_info"):
                    LOG.debug("Flash algo info: %s", pack_algo.flash_info)

                # Get the page size. If it's unreasonably small, then use the smallest sector size.
                page_size = pack_algo.page_size
                if page_size <= 32:
                    page_size = min(s[1] for s in pack_algo.sector_sizes)

                # Select the RAM to use for the algo.
                try:
                    ram_for_algo = self._select_flash_ram(region)
                except RuntimeError:
                    return False

                # Create the algo dict from the FLM.
                algo = pack_algo.get_pyocd_flash_algo(page_size, ram_for_algo)

                # If we got a valid algo from the FLM, set it on the region.
                if algo is not None:
                    region.algo = algo

                # Set region page/sector sizes and algorithm range; add sector subregions.
                self._update_flash_attributes(region, pack_algo, page_size, algo)

            return True
        except FlashAlgoException as algo_err:
            LOG.warning("Failed to load flash algorithm for region '%s' (%x-%x): %s",
                    region.name, region.start, region.end, algo_err)
            return False

    def _select_flash_ram(self, region: FlashRegion) -> RamRegion:
        """@brief Choose the RAM region to use for the given flash region's algo.

        @exception RuntimeError No RAM region is available.
        """
        # See if an explicit RAM range was specified for the algo.
        if hasattr(region, '_RAMstart'):
            ram_start = region._RAMstart

            # The region size comes either from the RAMsize attribute, the containing region's
            # bounds, or a large, arbitrary value.
            if hasattr(region, '_RAMsize'):
                ram_size = region._RAMsize
            else:
                containing_region = self._memory_map.get_region_for_address(ram_start)
                if containing_region is not None:
                    ram_size = containing_region.length - (ram_start - containing_region.start)
                else:
                    # No size specified, and the RAMstart attribute is outside of a known region,
                    # so just use a mid-range arbitrary size.
                    ram_size = 16 * 1024

            ram_for_algo = RamRegion(start=ram_start, length=ram_size)
        else:
            # No RAM addresses were given, so go with the RAM marked default.
            ram_for_algo = cast(RamRegion, self._memory_map.get_default_region_of_type(MemoryType.RAM))
            # Must have a default ram.
            if ram_for_algo is None:
                LOG.warning(f"CMSIS-Pack device {self._target.part_number} has no default RAM defined; cannot program flash")
                raise RuntimeError("no default RAM")

        return ram_for_algo

    def _update_flash_attributes(
            self,
            region: FlashRegion,
            pack_algo: PackFlashAlgo,
            page_size: int,
            algo: Dict[str, Any],
            ) -> None:
        """Depending on the sector size(s) defined by the flash algorithm, either simply set
        the parent flash region's attributes or create sector size subregions."""
        # First set the region's start and end if they weren't set.
        if region.start == region.end:
            # Directly access the attributes. Normally region start/end are not settable to
            # prevent modification of regions in a memory map such that they overlap.
            region._start = pack_algo.flash_start
            region._end = pack_algo.flash_start + pack_algo.flash_size - 1

        # Don't need to create subregions if there is a single sector size and its range
        # starts at the same address and is equal or larger than the parent flash region.
        sector_sizes = list(pack_algo.iter_sector_size_ranges())
        create_subregions = not (len(sector_sizes) == 1
                                and sector_sizes[0][0].start == region.start
                                and sector_sizes[0][0].end >= region.end)

        if create_subregions:
            self._add_flash_subregions(region, pack_algo, page_size, algo)
        else:
            # Set attributes on parent flash region. The parent region still has to have these attributes
            # even though there are subregions.
            region.attributes['page_size'] = page_size
            region.attributes['sector_size'] = sector_sizes[0][1]

    def _add_flash_subregions(
            self,
            region: FlashRegion,
            pack_algo: PackFlashAlgo,
            page_size: int,
            algo: Dict[str, Any],
            ) -> None:
        """@brief Create subregions of the parent flash region for each sector size.

        The overall range of combined sector sizes doesn't necessarily fill the parent region's
        entire size. Conversely, the algorithm may define more sectors than fit in the parent
        region.
        """
        max_sector_size = 0

        # Create subregions.
        for range, sector_size in pack_algo.iter_sector_size_ranges():
            # Limit subregion range to parent region size. There are cases (eg nRF5340, nRF9160) where
            # the flash algo defines a larger flash memory, then the DFP's <memory> attribute sets a
            # smaller value.
            if not region.contains_range(range):
                range = MemoryRange(max(region.start, range.start), end=min(region.end, range.end))
                if range.is_empty:
                    continue

            # Track maximum sector size.
            max_sector_size = max(max_sector_size, sector_size)

            # Limit page size.
            if page_size > sector_size:
                region_page_size = sector_size
                LOG.warning(f"Page size ({page_size}) is larger than sector size ({sector_size}) for flash "
                            f"region {region.name}; using sector size")
            else:
                region_page_size = page_size

            # Construct unique region name.
            region_name = region.name + f"_{sector_size:#x}"

            subregion = FlashRegion(
                name=region_name,
                access=region.access,
                start=range.start,
                end=range.end,
                sector_size=sector_size,
                page_size=region_page_size,
                erased_byte_value=pack_algo.flash_info.value_empty,
                algo=algo,
            )

            region.submap.add_region(subregion)

        # Set attributes on parent flash region. The parent region still has to have these attributes
        # even though there are subregions.
        region.attributes['page_size'] = page_size
        region.attributes['sector_size'] = max_sector_size
