# pyOCD debugger
# Copyright (c) 2026 Arm Limited
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

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, TYPE_CHECKING, cast

from .builder import FlashBuilder
from .flash import Flash
from ..core.exceptions import FlashFailure, FlashEraseFailure, FlashProgramFailure
from ..debug.sequences.sequences import FlashSequenceParams
from ..debug.sequences.functions import DebugSequenceCommonFunctions
from ..utility.timeout import Timeout

if TYPE_CHECKING:
    from ..debug.sequences.delegates import DebugSequenceDelegate
    from ..core.memory_map import FlashRegion

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)


class FlashDebugSequence(Flash):
    """@brief Flash programming implementation based on Open-CMSIS-Pack debug sequences.

    Implements Open-CMSIS-Pack standard flash programming sequences as defined in the Open-CMSIS-Pack specification:
    FlashInit, FlashUninit, FlashEraseSector, FlashEraseChip, FlashProgramPage.
    """

    # Open-CMSIS-Pack standard sequence names
    _SEQ_INIT = "FlashInit"
    _SEQ_UNINIT = "FlashUninit"
    _SEQ_ERASE_CHIP = "FlashEraseChip"
    _SEQ_ERASE_SECTOR = "FlashEraseSector"
    _SEQ_PROGRAM_PAGE = "FlashProgramPage"
    _SEQ_ERASE_SETUP = "FlashEraseSetup"
    _SEQ_PROGRAM_SETUP = "FlashProgramSetup"
    _SEQ_CODE_MEM_REMAP = "DebugCodeMemRemap"

    ## Sequences required for basic flash programming operations.
    _REQUIRED_SEQUENCES = (_SEQ_ERASE_SECTOR, _SEQ_PROGRAM_PAGE)

    def __init__(self, target) -> None:
        super().__init__(target, flash_algo=None)
        self._delegate: Optional[DebugSequenceDelegate] = target.debug_sequence_delegate
        self.is_valid = True
        self.use_analyzer = False
        self.double_buffer_supported = False
        self.page_buffers = []
        self.min_program_length = 0
        self._pname: Optional[str] = None

    @Flash.region.setter
    def region(self, flash_region: "FlashRegion") -> None:
        Flash.region.fset(self, flash_region)
        self._pname = flash_region.attributes.get('pname')

    @property
    def is_erase_all_supported(self) -> bool:
        return self._has_sequence(self._SEQ_ERASE_CHIP)

    @property
    def has_required_sequences(self) -> bool:
        return all(self._has_sequence(name) for name in self._REQUIRED_SEQUENCES)


    def init(self, operation, address: Optional[int] = None, clock: int = 0, reset: bool = False) -> None:
        # clock and reset arguments are ignored in this implementation

        if self.region is None:
            raise FlashFailure("flash init failed: flash region is not set", address=address)

        if address is None:
            address = self.region.start

        assert isinstance(operation, self.Operation)

        current_flash_algo = getattr(self.target.session.context_state, 'current_flash_algo', None)
        if current_flash_algo is not None and current_flash_algo is not self:
            current_flash_algo.cleanup()

        if self._active_operation is not None:
            if self._active_operation == operation:
                return
            self.uninit()

        if operation == self.Operation.VERIFY:
            if self._has_sequence(self._SEQ_CODE_MEM_REMAP):
                TRACE.debug("call code remap(addr=%#010x)", address)
                params = FlashSequenceParams(0, address, 0, 0)
                self._run_sequence(self._SEQ_CODE_MEM_REMAP, params)
        elif self._has_sequence(self._SEQ_INIT):
            TRACE.debug("call init(addr=%#010x, op=%d)", address, operation)
            params = FlashSequenceParams(operation, address, 0, 0)
            self._run_sequence(self._SEQ_INIT, params)
        else:
            LOG.warning("flash init sequence not available")

        self._active_operation = operation

    def uninit(self, address: Optional[int] = None) -> None:
        if self._active_operation is None:
            return

        if self.region is None:
            raise FlashFailure("flash uninit failed: flash region is not set", address=address)

        if address is None:
            address = self.region.start

        if self._has_sequence(self._SEQ_UNINIT):
            TRACE.debug("call uninit(addr=%#010x, op=%d)", address, self._active_operation)
            params = FlashSequenceParams(self._active_operation, address, 0, 0)
            self._run_sequence(self._SEQ_UNINIT, params)
        else:
            LOG.warning("flash uninit sequence not available")

        self._active_operation = None

    def erase_all(self, address: Optional[int] = None) -> None:
        assert self._active_operation == self.Operation.ERASE

        if self.region is None:
            raise FlashEraseFailure("flash erase chip failed: flash region is not set", address=address)

        if address is None:
            address = self.region.start

        if not self._has_sequence(self._SEQ_ERASE_CHIP):
            raise FlashEraseFailure("flash erase chip sequence not available", address=address)

        TRACE.debug("call erase_all")
        params = FlashSequenceParams(self.Operation.ERASE, address, 0, 0)
        self._run_sequence(self._SEQ_ERASE_CHIP, params)

    def erase_sector(self, address: int) -> None:
        assert self._active_operation == self.Operation.ERASE

        if self.region is None:
            raise FlashEraseFailure("flash erase sector failed: flash region is not set", address=address)

        sector = self.get_sector_info(address)
        if sector is None:
            raise FlashEraseFailure("address is not within any sector", address=address)

        if not self._has_sequence(self._SEQ_ERASE_SECTOR):
            raise FlashEraseFailure("flash erase sector sequence not available", address=address)

        TRACE.debug("call erase_sector(%#010x)", address)
        params = FlashSequenceParams(self.Operation.ERASE, address, 0,
                                     int(self._get_region_attr(address, '_flashinfo_block_arg', 0)))
        timeout = self._get_region_attr(address, '_flashinfo_etime')
        self._run_sequence(self._SEQ_ERASE_SECTOR, params, timeout=timeout)

    def program_page(self, address: int, bytes) -> None:
        assert self._active_operation == self.Operation.PROGRAM

        if self.region is None:
            raise FlashProgramFailure("flash program page failed: flash region is not set", address=address)

        fns = self._get_sequence_functions()
        filler = self._get_region_attr(self.region.start, '_flashinfo_fill_val')

        fns.set_flash_buffer(bytes, filler=filler)

        if not self._has_sequence(self._SEQ_PROGRAM_PAGE):
            raise FlashProgramFailure("flash program page sequence not available", address=address)

        TRACE.debug("call program_page(addr=%#010x, len=%#010x)", address, len(bytes))
        params = FlashSequenceParams(self.Operation.PROGRAM, address, len(bytes), 0)
        timeout = self._get_region_attr(address, '_flashinfo_ptime')
        self._run_sequence(self._SEQ_PROGRAM_PAGE, params, timeout=timeout)

    def program_phrase(self, address: int, bytes) -> None:
        self.program_page(address, bytes)

    def get_flash_builder(self):
        return FlashDebugSequenceBuilder(self)

    def _run_sequence(self, name: str, params: FlashSequenceParams, timeout: Optional[float] = None) -> None:
        if self._delegate is None:
            raise FlashFailure("flash debug sequence delegate is not available")
        with Timeout(timeout) as t_o:
            #TODO: Timeout should really stop the sequence execution.
            self._delegate.run_sequence(name, pname=self._pname, flash_params=params)
        if t_o.did_time_out:
            raise FlashFailure(f"flash sequence '{name}' timed out")

    def _get_region_attr(self, address: int, name: str, default=None):
        region = self._get_region_or_subregion(address)
        if region is None:
            return default
        return region.attributes.get(name, default)

    def _has_sequence(self, name: str) -> bool:
        return (self._delegate is not None) and self._delegate.has_sequence_with_name(name, self._pname)

    def _get_sequence_functions(self) -> DebugSequenceCommonFunctions:
        if self._delegate is None:
            raise FlashFailure("flash debug sequence delegate is not available")
        return cast(DebugSequenceCommonFunctions, self._delegate.get_sequence_functions())


class FlashDebugSequenceBuilder(FlashBuilder):
    """@brief Flash builder that lets DSQ setup sequences select erase/program implementations."""

    def __init__(self, flash: FlashDebugSequence) -> None:
        super().__init__(flash)
        self._dsq_flash = flash
        self._cached_flm_flash: Optional[Flash] = None
        self._cached_algorithm_selection: Optional[tuple] = None
        self._prepared_flash: Optional[Flash] = None

    def erase(self, *args, **kwargs):
        flm_flash = self._select_flm_flash(FlashDebugSequence._SEQ_ERASE_SETUP,
                                           self._dsq_flash.Operation.ERASE)

        with self._use_flash(flm_flash):
            return super().erase(*args, **kwargs)

    def program(self, *args, **kwargs):
        flm_flash = self._select_flm_flash(FlashDebugSequence._SEQ_PROGRAM_SETUP,
                                           self._dsq_flash.Operation.PROGRAM)

        with self._use_flash(flm_flash):
            return super().program(*args, **kwargs)

    @contextmanager
    def _use_flash(self, flash: Optional[Flash]) -> Iterator[None]:
        """@brief Temporarily switch self.flash to a setup-selected FLM."""
        if flash is None:
            yield
            return

        original, self.flash = self.flash, flash
        try:
            yield
        finally:
            self.flash = original

    def _select_flm_flash(self, seq_name: str, operation) -> Optional[Flash]:
        """@brief Run a setup sequence and return a Flash using the selected FLM, or None."""
        if not self._dsq_flash._has_sequence(seq_name):
            TRACE.debug("%s not available; using flash debug sequences", seq_name)
            return None

        if not self.flash_operation_list:
            return None

        address = min(operation.addr for operation in self.flash_operation_list)
        end = max(operation.addr + len(operation.data) for operation in self.flash_operation_list)
        length = end - address

        TRACE.debug("call %s(addr=%#010x, len=%#010x)", seq_name, address, length)
        fns = self._dsq_flash._get_sequence_functions()

        selected_flm_flash = None
        selected_flm_failed = False

        def load_flash_algorithm(algo_path, ram_start: int, ram_size: int) -> int:
            nonlocal selected_flm_flash, selected_flm_failed
            selected_flm_flash = self._get_or_create_flm_flash(seq_name, algo_path, ram_start, ram_size, address, length)
            selected_flm_failed = selected_flm_flash is None
            return 1 if selected_flm_failed else 0

        with fns.flash_algorithm_loader(load_flash_algorithm):
            self._dsq_flash._run_sequence(seq_name, FlashSequenceParams(operation, address, length, 0))

        if selected_flm_failed:
            raise FlashFailure(f"{seq_name} failed to load selected flash algorithm")
        if selected_flm_flash is None:
            TRACE.debug("%s did not select an FLM; using flash debug sequences", seq_name)
        return selected_flm_flash

    def _get_or_create_flm_flash(
            self,
            seq_name: str,
            algo_path: Path,
            ram_start: int,
            ram_size: int,
            address: int,
            length: int,
            ) -> Optional[Flash]:
        selection = (algo_path, ram_start, ram_size)
        if self._cached_flm_flash is not None and self._cached_algorithm_selection == selection:
            region = self._cached_flm_flash.region
            if region is not None and region.contains_range(start=address, length=length):
                return self._cached_flm_flash
            return None
        self._release_cached_flm_flash()
        flm_flash = self._load_flm_as_flash(seq_name, algo_path, ram_start, ram_size, address, length)
        if flm_flash is not None:
            self._cached_flm_flash = flm_flash
            self._cached_algorithm_selection = selection
        return flm_flash

    def _release_cached_flm_flash(self) -> None:
        """@brief Clean up and discard the cached FLM-backed Flash."""
        flm_flash = self._cached_flm_flash
        self._cached_flm_flash = None
        self._cached_algorithm_selection = None
        if (flm_flash is not None
                and getattr(flm_flash.target.session.context_state, 'current_flash_algo', None) is flm_flash):
            flm_flash.cleanup()

    def _load_flm_as_flash(
            self,
            seq_name: str,
            algo_path: Path,
            ram_start: int,
            ram_size: int,
            address: int,
            length: int,
            ) -> Optional[Flash]:
        """@brief Build a configured Flash instance from an FLM, or None on failure."""
        from ..target.pack.flash_algo import PackFlashAlgo, FlashAlgoException
        from ..target.pack.flm_region_builder import FlmFlashRegionBuilder
        dsq_region = self._dsq_flash.region
        assert dsq_region is not None

        if not algo_path.is_file():
            LOG.error("FlashLoadAlgorithm: '%s' not found", algo_path)
            return None

        try:
            pack_algo = PackFlashAlgo(str(algo_path))
        except (OSError, FlashAlgoException, ValueError) as err:
            LOG.error("FlashLoadAlgorithm: '%s': %s", algo_path, err)
            return None

        region_start = max(dsq_region.start, pack_algo.flash_start)
        region_end = min(dsq_region.end, pack_algo.flash_start + pack_algo.flash_size - 1)
        if region_start > region_end:
            LOG.error("FlashLoadAlgorithm: '%s' outside region '%s' (%#010x-%#010x)",
                        algo_path, dsq_region.name, dsq_region.start, dsq_region.end)
            return None
        request_end = address + length - 1
        if length > 0 and not (region_start <= address and request_end <= region_end):
            LOG.error("FlashLoadAlgorithm: '%s' does not cover requested range (%#010x-%#010x)",
                        algo_path, address, request_end)
            return None

        region = dsq_region.clone_with_changes(
            start=region_start,
            length=region_end - region_start + 1,
            algo=None,
            flm=pack_algo,
            flash_class=Flash,
            erased_byte_value=pack_algo.flash_info.value_empty,
            are_erased_sectors_readable='Verify' not in pack_algo.symbols,
            _RAMstart=ram_start,
            _RAMsize=ram_size,
        )

        if not FlmFlashRegionBuilder(self._dsq_flash.target, self._dsq_flash.target.memory_map).finalise_region(region):
            return None

        flm_flash = Flash(self._dsq_flash.target, region.algo)
        flm_flash.region = region
        TRACE.info("Using flash algorithm selected by %s for region '%s': %s", seq_name, dsq_region.name, algo_path)
        return flm_flash

    def _prepare_sectors_and_pages(self, keep_unwritten: bool, smart_flash: bool) -> None:
        if self._prepared_flash is not self.flash:
            self.sector_list = []
            self.page_list = []
            self.prepared_sectors_and_pages = False
            self.algo_inited_for_read = False
            self._prepared_flash = self.flash
        super()._prepare_sectors_and_pages(keep_unwritten, smart_flash)
