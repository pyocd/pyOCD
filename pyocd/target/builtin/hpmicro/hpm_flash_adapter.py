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

"""HPMicro-specific RISC-V flash adapter.

Overrides generic flash-lifecycle hooks on RiscvFlashAdapter to manage
HPMicro flash hardware: FLM blob parameter loading before init, and
D-cache maintenance after ops so host SBA reads see actual flash
contents.
"""

import logging

from ....riscv.dm.registers import Command, RiscvRegno
from ....riscv.instructions import RiscvInstr
from ....riscv.flash.riscv_adapter import RiscvFlashAdapter

LOG = logging.getLogger(__name__)


class HPMicroFlashAdapter(RiscvFlashAdapter):
    """RiscvFlashAdapter tuned for HPMicro flash hardware."""

    def _pre_call_hook(self, init: bool) -> None:
        """Load FLM blob parameters (flash-controller config) to the blob's
        data section before the algo's init routine runs."""
        if not init:
            return
        algo = self.flash_algo
        if 'flm_init_params' not in algo:
            return
        params = algo['flm_init_params']
        params_addr = algo['load_address'] + params['_offset']
        values = [params['nor_config_header'], params['nor_config_opt0'],
                  params['nor_config_opt1'], params['xpi_base']]
        self.target.write_memory_block32(params_addr, values)
        LOG.info("flm_init_params: wrote flash-controller config at 0x%08x "
                 "(header=0x%08x, opt0=0x%08x, opt1=0x%08x, xpi_base=0x%08x)",
                 params_addr, values[0], values[1], values[2], values[3])
        # Clear the initialized flags so pc_init does full setup every time.
        # FLM blob keeps state in PROGBITS (bss_size=0), so the generic BSS
        # clear in _call_function does not cover these flags.
        bss_layout = algo.get('bss_layout', {})
        for flag_name in ('initialized', 'flm_initialized'):
            flag_off = bss_layout.get(flag_name)
            if flag_off is not None:
                flag_addr = algo['load_address'] + flag_off
                self.target.write_memory_block32(flag_addr, [0])
                LOG.debug("FLM pre-init: cleared %s flag at 0x%08x",
                          flag_name, flag_addr)

    def _post_op_cache_sync(self) -> None:
        """Force D-cache write-back + disable so host SBA reads see actual
        memory after the algo's init routine re-enables the cache. The
        blob's own flush may not fully drain under debug halt."""
        if self._active_operation is not None:
            return
        core = self.target.selected_core
        dm = core.riscv_dm
        progbuf = dm._progbuf
        if not progbuf.available:
            return
        try:
            # Read the D-cache enable bit (vendor memory-cache-control CSR 0x7CA).
            progbuf.write_program([RiscvInstr.csrr(10, 0x7CA)])
            dm._abstract.execute(Command.build_postexec_only())
            mcache = dm._abstract.read_register(RiscvRegno.X10)
            dc_enabled = bool(mcache & 0x2)
            LOG.info("dcache: MCACHE_CTL=0x%08x, DC_ENABLED=%s", mcache, dc_enabled)
            if dc_enabled:
                # Write-back + invalidate all D-cache lines via the vendor
                # cache-control command CSR (0x7CC, cmd 6); then clear the
                # D-cache enable bit.
                progbuf.write_program([
                    0x06000513,  # li a0, (6<<8)
                    0x7CC7A073,  # csrs 0x7CC, a0
                ])
                dm._abstract.execute(Command.build_postexec_only())
                progbuf.write_program([
                    0x00100513,  # li a0, 1
                    0x7CA7B073,  # csrc 0x7CA, a0
                ])
                dm._abstract.execute(Command.build_postexec_only())
                progbuf.write_program([RiscvInstr.csrr(10, 0x7CA)])
                dm._abstract.execute(Command.build_postexec_only())
                mcache2 = dm._abstract.read_register(RiscvRegno.X10)
                LOG.info("dcache: after flush+disable MCACHE_CTL=0x%08x", mcache2)
        except Exception as e:
            LOG.warning("dcache flush failed: %s", e)
        # SBA read-back sanity log for the config the algo left in memory.
        load_addr = self.flash_algo.get('load_address', 0)
        bss_layout = self.flash_algo.get('bss_layout', {})
        try:
            nor_off = bss_layout.get('nor_config')
            if nor_off is not None:
                sba_nor = self.target.read_memory_block32(load_addr + nor_off, 4)
                LOG.info("dcache: post-flush SBA nor_config@0x%x = %s",
                         nor_off, " ".join(f"0x{v:08x}" for v in sba_nor))
        except Exception:
            pass

    def _post_init_diagnostics(self) -> None:
        """First-init state inspection: log BSS/layout/nor_config values so a
        misconfigured algo is visible. Skipped on subsequent inits."""
        if self._active_operation is not None:
            return
        load_addr = self.flash_algo.get('load_address', 0)
        bss_layout = self.flash_algo.get('bss_layout', {})
        bss_sizes = self.flash_algo.get('bss_sizes', {})
        try:
            if not self._init_diag_done:
                for name, offset in bss_layout.items():
                    size = bss_sizes.get(name, 4)
                    count = max(1, size // 4)
                    vals = self.target.read_memory_block32(load_addr + offset, count)
                    if count == 1:
                        LOG.info("bss: %s@0x%x = 0x%x", name, offset, vals[0])
                    else:
                        LOG.info("bss: %s@0x%x (%dB) = %s ...", name, offset, size,
                                 " ".join(f"0x{v:08x}" for v in vals[:8]))
                nor_offset = bss_layout.get('nor_config')
                if nor_offset is not None and 'nor_config' in bss_sizes:
                    nor_size = bss_sizes['nor_config']
                    nor_words = (nor_size + 3) // 4
                    full_nc = self.target.read_memory_block32(
                        load_addr + nor_offset, nor_words)
                    nonzero = [(i, v) for i, v in enumerate(full_nc) if v != 0]
                    if nonzero:
                        LOG.info("nor_config has %d nonzero words: %s",
                                 len(nonzero),
                                 ", ".join(f"[{i}]=0x{v:08x}" for i, v in nonzero[:16]))
                    else:
                        LOG.warning("nor_config is ENTIRELY ZERO after init")
                sb = self.flash_algo.get('static_base', 0)
                if sb != 0 and load_addr != sb:
                    gp_delta = sb - load_addr
                    LOG.info("gp_alias: GP=0x%x, load=0x%x, delta=0x%x",
                             sb, load_addr, gp_delta)
                    p_filesz = self.flash_algo.get('p_filesz', 0)
                    if p_filesz > 0:
                        link_base = sb - 0x800
                        linked_bss = self.target.read_memory_block32(
                            link_base + p_filesz, 16)
                        LOG.info("gp_alias: linked BSS@0x%x = %s",
                                 link_base + p_filesz,
                                 " ".join(f"0x{v:08x}" for v in linked_bss[:8]))
                        LOG.info("gp_alias: linked nor@0x%x = %s",
                                 link_base + p_filesz + 4,
                                 " ".join(f"0x{v:08x}" for v in linked_bss[4:12]))
                self._init_diag_done = True
            else:
                init_off = bss_layout.get('initialized')
                if init_off is not None:
                    val = self.target.read_memory_block32(
                        load_addr + init_off, 1)[0]
                    LOG.debug("bss: initialized@0x%x = 0x%x (subsequent init)",
                              init_off, val)
        except Exception:
            pass
