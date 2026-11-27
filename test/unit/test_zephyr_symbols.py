# pyOCD debugger
# Copyright (c) 2026 Solarboaters
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.debug.context import DebugContext
from pyocd.rtos.zephyr import ZephyrThreadProvider


@pytest.fixture
def zephyr_image(mockcore):
    # Offset-table field order is shared by Zephyr v2.5.0 openocd.c and
    # v2.6.0 thread_info.c. Concrete struct offsets vary with the target build.
    kernel, offsets, size, thread = 0x20000000, 0x20000040, 0x20000080, 0x20000100
    mockcore.write_memory_block32(offsets, [1, 0, 4, 8, 12, 16, 17, 18, 20, 24])
    mockcore.write8(size, 4)
    mockcore.write32(kernel, thread)
    mockcore.write32(kernel + 4, thread)
    mockcore.write32(thread + 12, 0)
    mockcore.write8(thread + 16, 0)
    mockcore.write8(thread + 18, 3)
    mockcore.write_memory_block8(thread + 24, b'worker\x00')
    context = DebugContext(mockcore)
    target = SimpleNamespace(get_target_context=lambda: context, session=Mock(), run_token=1)
    return ZephyrThreadProvider(target), kernel, offsets, size, thread


@pytest.mark.parametrize('names', ['legacy', 'current', 'both'])
def test_thread_enumeration_for_old_and_new_symbol_names(zephyr_image, names):
    provider, kernel, offsets, size, thread = zephyr_image
    symbols = {'_kernel': kernel}
    if names in ('legacy', 'both'):
        symbols.update(_kernel_openocd_offsets=offsets, _kernel_openocd_size_t_size=size)
    if names in ('current', 'both'):
        symbols.update(_kernel_thread_info_offsets=offsets, _kernel_thread_info_size_t_size=size)
    if names == 'both':
        # Modern names must win over stale aliases.
        symbols['_kernel_openocd_size_t_size'] = 0x20000300
    assert provider.init(SimpleNamespace(get_symbol_value=symbols.get))
    provider.read_from_target = True
    threads = provider.get_threads()
    assert len(threads) == 1
    assert threads[0].unique_id == thread
    assert threads[0].name == 'worker'
    assert threads[0].priority == 3
    assert threads[0].is_current


@pytest.mark.parametrize('missing', ['_kernel', '_kernel_openocd_offsets', '_kernel_openocd_size_t_size'])
def test_incomplete_legacy_symbols_do_not_enable_provider(zephyr_image, missing):
    provider, kernel, offsets, size, _ = zephyr_image
    symbols = {'_kernel': kernel, '_kernel_openocd_offsets': offsets, '_kernel_openocd_size_t_size': size}
    del symbols[missing]
    assert not provider.init(SimpleNamespace(get_symbol_value=symbols.get))
    assert not provider.is_enabled
