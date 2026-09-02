# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
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

"""HPMicro RISC-V target base class with XPI flash support.

Provides the shared XPI flash loader blob and add_xpi_flash() helper.
Chip-level subclasses define RAM layout and XPI_MAP (flash_base -> xpi controller base).
Board-level subclasses call add_xpi_flash() with board-specific flash parameters.
"""

import logging

from ....core.memory_map import FlashRegion
from ....core.target import Target
from ....riscv.target.riscv_target import RISCVTarget
from .hpm_xpi_algo import HPM_XPI_FLASH_ALGO
from .hpm_xpi_flm_algo import HPM_XPI_FLM_FLASH_ALGO, OFFSET_FLM_PARAMS
from .flash_algo_builder import build_flash_algo

LOG = logging.getLogger(__name__)


def _override_from_options(options, key: str, default, converter=None):
    """Override a config value from a session option.

    Lets board revision variants / runtime algo selection be configured at
    runtime via ``-O hpmicro.<key>=<value>`` without a separate target class.
    Returns ``default`` when the option is not set.

    Args:
        options: An OptionsManager-like object with ``is_set``/``get``.
        key: Option name, e.g. ``'hpmicro.nor_config_opt1'`` or ``'hpmicro.algo_type'``.
        default: Value used when the option is unset.
        converter: Optional callable applied to the stored value (e.g. ``_to_int``
            for nor_config opts that accept decimal/0x-hex). ``None`` returns the
            raw value (string passthrough, used for algo_type).
    """
    if not options.is_set(key):
        return default
    val = options.get(key)
    return converter(val) if converter else val


def _to_int(val):
    """Coerce an option value to int (decimal or 0x-hex)."""
    return int(val, 0) if isinstance(val, str) else int(val)


class HPMicroTarget(RISCVTarget):
    """Base class for HPMicro RISC-V targets.

    Subclasses must set:
        XPI_MAP: dict mapping flash_base -> XPI controller peripheral base address
        _FLASH_RAM_START: Working RAM for flash algo (typically ILM base)
        _FLASH_RAM_SIZE: Working RAM size for flash algo

    MEMORY_MAP should contain only RAM regions. Board subclasses add
    flash regions via add_xpi_flash().
    """

    VENDOR = "HPMicro"

    # Default: standard CSRs only, no vendor custom.
    # Part targets override this to include vendor-specific configs.
    CSR_CONFIGS = []

    XPI_MAP = {}
    _FLASH_RAM_START = None
    _FLASH_RAM_SIZE = None

    @property
    def _XPI_BASE(self):
        return self.XPI_MAP.get(0x80000000)

    # Registry of available flash algo blobs. Part targets can override
    # to add new blob types or change defaults.
    FLASH_ALGOS = {
        'custom': {
            'algo': HPM_XPI_FLASH_ALGO,
            'page_size': 256,
            'flash_base_required': True,
            'init_style': 'init_params',
        },
        'flm': {
            'algo': HPM_XPI_FLM_FLASH_ALGO,
            'page_size': 256,
            'flash_base_required': False,
            'init_style': 'flm_init_params',
        },
    }
    DEFAULT_FLASH_ALGO = 'custom'

    def __init__(self, session, memory_map=None):
        super().__init__(session, memory_map)

    def _register_reset_hooks(self) -> None:
        """Default every core's reset type to HARDWARE so `mon reset halt`
        asserts SRST and re-samples the boot strap (no power-cycle needed to
        switch boot mode). Set here (not in __init__) because cores are
        created later in the init sequence (_create_cores); __init__ runs
        before self.cores is populated, so an assignment there is a no-op.
        Probes that lack Capability.RESET_ASSERT (FTDI, cJTAG) silently
        degrade to ndmreset via _get_actual_reset_type.
        """
        for core in self.cores.values():
            core.default_reset_type = Target.ResetType.HARDWARE

    def add_xpi_flash(self, *, flash_size, nor_config_header,
                       nor_config_opt0, nor_config_opt1,
                       flash_base=0x80000000, sector_size=0x1000,
                       is_boot_memory=False, algo_type=None):
        """Add an XPI flash region with board-specific parameters.

        algo_type selects from FLASH_ALGOS registry. Defaults to
        DEFAULT_FLASH_ALGO if not specified. Part targets can override
        FLASH_ALGOS and DEFAULT_FLASH_ALGO to add or change blobs.
        """
        # Allow runtime override of NOR config for board revision variants
        # (e.g. different flash pin groups). Usage: -O hpmicro.nor_config_opt1=0
        nor_config_opt0 = _override_from_options(
            self.session.options, 'hpmicro.nor_config_opt0', nor_config_opt0, _to_int)
        nor_config_opt1 = _override_from_options(
            self.session.options, 'hpmicro.nor_config_opt1', nor_config_opt1, _to_int)
        algo_type = _override_from_options(
            self.session.options, 'hpmicro.algo_type', algo_type)
        if algo_type is None:
            algo_type = self.DEFAULT_FLASH_ALGO
        if algo_type not in self.FLASH_ALGOS:
            raise ValueError(
                f"Unknown hpmicro.algo_type={algo_type!r}; "
                f"valid: {sorted(self.FLASH_ALGOS.keys())}")
        spec = self.FLASH_ALGOS[algo_type]
        page_size = spec['page_size']
        flash_base_for_algo = flash_base if spec['flash_base_required'] else None

        if spec['init_style'] == 'init_params':
            init_params = [
                nor_config_header,
                nor_config_opt0,
                nor_config_opt1,
                self.XPI_MAP.get(flash_base, self._XPI_BASE),
            ]
            flm_init_params = None
        elif spec['init_style'] == 'flm_init_params':
            init_params = None
            flm_init_params = None
            if nor_config_header is not None:
                flm_init_params = {
                    '_offset': OFFSET_FLM_PARAMS,
                    'nor_config_header': nor_config_header,
                    'nor_config_opt0': nor_config_opt0 if nor_config_opt0 is not None else 0,
                    'nor_config_opt1': nor_config_opt1 if nor_config_opt1 is not None else 0,
                    'xpi_base': self.XPI_MAP.get(flash_base, self._XPI_BASE),
                }
        else:
            raise ValueError(f"Unknown init_style: {spec['init_style']}")

        assert self._FLASH_RAM_START is not None, f"{type(self).__name__} must set _FLASH_RAM_START"
        assert self._FLASH_RAM_SIZE is not None, f"{type(self).__name__} must set _FLASH_RAM_SIZE"
        algo = build_flash_algo(
            spec['algo'],
            ram_start=self._FLASH_RAM_START,
            ram_size=self._FLASH_RAM_SIZE,
            flash_base=flash_base_for_algo,
            page_size=page_size,
            sector_size=sector_size,
            init_params=init_params,
            flm_init_params=flm_init_params,
            init_timeout=30.0,
            page_buffer_ram_start=getattr(self, '_PAGE_BUF_RAM_START', None),
        )
        # XPI flash-controller DMA cache-line: the DMA fetches wrong data
        # (silently corrupting the programmed image) if the batch buffer
        # base is not aligned to its cache-line granularity. Subclasses
        # override _DMA_CACHELINE_BYTES if a future XPI revision changes it.
        algo['dma_cacheline_bytes'] = getattr(self, '_DMA_CACHELINE_BYTES', 64)
        from .hpm_flash_adapter import HPMicroFlashAdapter
        xpi_region = FlashRegion(
            name="XPI_FLASH",
            start=flash_base,
            length=flash_size,
            access='rx',
            blocksize=sector_size,
            page_size=page_size,
            is_boot_memory=is_boot_memory,
            algo=algo,
        )
        xpi_region.flash_class = HPMicroFlashAdapter
        self.memory_map.add_region(xpi_region)
