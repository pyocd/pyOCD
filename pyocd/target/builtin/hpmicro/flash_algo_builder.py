# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
# SPDX-License-Identifier: Apache-2.0

"""Flash algo builder for HPMicro XPI flash.

Merges ELF-derived flash algorithm data (blob + offsets) with
SoC-specific parameters (RAM, flash geometry, XPI config).
All HPMicro targets sharing the same XPI loader blob use this builder.
"""


def build_flash_algo(base_algo, *, ram_start, ram_size, flash_base,
                     page_size, sector_size,
                     init_args=None, init_params=None,
                     flm_init_params=None,
                     init_timeout=30.0,
                     page_buffer_ram_start=None):
    """Build flash algo dict by merging ELF data with SoC parameters.

    Args:
        base_algo: ELF-derived algo dict (from generated module).
        ram_start: Working RAM base address.
        ram_size: Working RAM size in bytes.
        flash_base: XPI flash base address.
        page_size: Flash page size in bytes.
        sector_size: Flash sector size in bytes.
        init_args: Register-passed init arguments (a0-aN), alternative to RAM-pointer init_params.
        init_params: List of init parameters (RAM-pointer-passed to a1).
        flm_init_params: Dict of FLM pre-init params (written to blob data
            section before Init): {_offset, nor_config_header, nor_config_opt0,
            nor_config_opt1, xpi_base}.
        init_timeout: Override timeout for flash_init in seconds.

    Only one of init_args/init_params/flm_init_params should be provided.

    Returns:
        Complete flash algo dict for RiscvFlashAdapter consumption.
    """
    provided = sum(x is not None for x in [init_args, init_params, flm_init_params])
    if provided > 1:
        raise ValueError("Cannot specify more than one of init_args, init_params, flm_init_params")

    algo = dict(base_algo)
    algo.update({
        'working_ram_start': ram_start,
        'working_ram_size': ram_size,
        'page_size': page_size,
        'sector_size': sector_size,
        'init_timeout': init_timeout,
    })
    if flash_base is not None:
        algo['flash_base'] = flash_base
    if init_args is not None:
        algo['init_args'] = init_args
    if init_params is not None:
        algo['init_params'] = init_params
    if flm_init_params is not None:
        algo['flm_init_params'] = flm_init_params
    if page_buffer_ram_start is not None:
        algo['page_buffer_ram_start'] = page_buffer_ram_start

    # Pass through BSS layout from manifest for adapter consumption.
    # Deep-copy to avoid shared dict references between targets.
    import copy
    for key in ('bss_layout', 'bss_sizes', 'p_filesz', 'p_memsz'):
        if key in base_algo:
            algo[key] = copy.deepcopy(base_algo[key])

    return algo
