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
from typing import Optional, TYPE_CHECKING, cast

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
    _SEQ_CODE_MEM_REMAP = "DebugCodeMemRemap"

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

    def init(self, operation, address: Optional[int] = None, clock: int = 0, reset: bool = False) -> None:
        # clock and reset arguments are ignored in this implementation

        if self.region is None:
            raise FlashFailure("flash init failed: flash region is not set", address=address)

        if address is None:
            address = self.region.start

        assert isinstance(operation, self.Operation)

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
