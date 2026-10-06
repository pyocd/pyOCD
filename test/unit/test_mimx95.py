# pyOCD debugger
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

import zlib
from unittest import mock

import pytest

from pyocd.core.exceptions import TransferError
from pyocd.core.target import Target
from pyocd.core.memory_map import FlashRegion
from pyocd.coresight.cortex_m import CortexM
from pyocd.flash.flash import Flash
from pyocd.target.builtin import target_MIMX95 as imx95

@pytest.fixture
def flash():
    f = imx95.FlexSpiFlash(mock.Mock(), imx95.FLASH_ALGO)
    f.init = mock.Mock()
    with mock.patch.object(Flash, 'cleanup') as super_cleanup:
        f.super_cleanup = super_cleanup
        yield f


class TestFlexSpiCleanup:
    @pytest.mark.parametrize("operation, restored", [
        (Flash.Operation.ERASE, True),
        (Flash.Operation.PROGRAM, True),
        (Flash.Operation.VERIFY, False),
        (None, False),
    ])
    def test_read_setup_restored(self, flash, operation, restored):
        flash._active_operation = operation
        flash.cleanup()
        assert flash.init.call_args_list == ([mock.call(Flash.Operation.VERIFY)] if restored else [])
        flash.super_cleanup.assert_called_once()

    def test_cleanup_runs_when_restore_fails(self, flash):
        flash._active_operation = Flash.Operation.PROGRAM
        flash.init.side_effect = TransferError()
        with pytest.raises(TransferError):
            flash.cleanup()
        flash.super_cleanup.assert_called_once()


@pytest.fixture
def core():
    regs = {CortexM.DEMCR: 0, 0x28020800: 0x20040000, 0x28020804: 0x28021235}
    c = imx95.CM7Core.__new__(imx95.CM7Core)
    c._app_vtor = mock.Mock(return_value=0x28020800)
    c.read32 = mock.Mock(side_effect=lambda a: regs.get(a, 0))
    c.write32 = mock.Mock(side_effect=regs.__setitem__)
    c.write_memory_block32 = mock.Mock(side_effect=lambda a, ws: regs.update(
            {a + 4 * i: w for i, w in enumerate(ws)}))
    c.write_core_registers_raw = mock.Mock()
    c.resume = mock.Mock()
    c._session = mock.Mock()
    c._session.options.get.return_value = False
    c.regs = regs
    return c


class TestCm7Restart:
    def test_emulated_reset_starts_app(self, core):
        seen = {}
        with mock.patch.object(CortexM, '_perform_emulated_reset',
                lambda self: seen.update(demcr=self.regs[CortexM.DEMCR])):
            core._perform_emulated_reset()
        assert seen['demcr'] & CortexM.DEMCR_VC_CORERESET  # generic reset left the core halted
        assert core.regs[CortexM.DEMCR] == 0
        assert core.regs[imx95.MPU_CTRL] == 0
        assert core.regs[CortexM.VTOR] == 0x28020800
        assert core.regs[imx95.CM7_CFSR] == core.regs[imx95.CM7_HFSR] == 0xFFFFFFFF  # write-one-to-clear
        assert core.regs[CortexM.FPCCR] == imx95.CM7_FPCCR_RESET
        core.write_core_registers_raw.assert_called_once_with(['msp', 'pc'], [0x20040000, 0x28021234])
        core.resume.assert_called_once()

    def test_emulated_reset_and_halt_stays_halted(self, core):
        core.regs[CortexM.DEMCR] = CortexM.DEMCR_VC_CORERESET
        with mock.patch.object(CortexM, '_perform_emulated_reset'):
            core._perform_emulated_reset()
        assert core.regs[CortexM.DEMCR] == CortexM.DEMCR_VC_CORERESET
        core.resume.assert_not_called()

    @pytest.mark.parametrize("reset_type, actual", [
        (Target.ResetType.DEFAULT, Target.ResetType.EMULATED),
        (Target.ResetType.EMULATED, Target.ResetType.EMULATED),
        (Target.ResetType.SYSTEM, Target.ResetType.EMULATED),
        (Target.ResetType.CORE, Target.ResetType.EMULATED),
        (Target.ResetType.HARDWARE, Target.ResetType.EMULATED),
        (Target.ResetType.SYSRESETREQ, Target.ResetType.SYSRESETREQ),
    ])
    def test_reset_type_mapping(self, core, reset_type, actual):
        core._supported_reset_types = set(Target.ResetType)
        assert core._get_actual_reset_type(reset_type) is actual


class TestCm7AppVtor:
    @pytest.mark.parametrize("option, regs, vtor", [
        ("0x28020800", {}, 0x28020800),
        (None, {CortexM.VTOR: 0x28020800, 0x28020804: 0x28021235}, 0x28020800),
        (None, {CortexM.VTOR: 0x28020800, CortexM.DHCSR: CortexM.S_LOCKUP}, imx95.FLEXSPI_BASE),
        (None, {CortexM.VTOR: 0x28020840 + 4}, imx95.FLEXSPI_BASE),  # misaligned
        (None, {CortexM.VTOR: 0x0, 0x4: 0x9}, imx95.FLEXSPI_BASE),  # parking loop at the boot vector
        (None, {CortexM.VTOR: 0x20480000, 0x20480004: 0x20480009}, imx95.FLEXSPI_BASE),  # OCRAM parking loop
    ])
    def test_app_vtor(self, option, regs, vtor):
        c = imx95.CM7Core.__new__(imx95.CM7Core)
        c._session = mock.Mock()
        c._session.options.get.return_value = option
        c.memory_map = imx95.MIMX95_CM7_MX25UM.memoryMap
        c.read32 = lambda a: regs.get(a, 0)
        assert c._app_vtor() == vtor


@pytest.mark.parametrize("flash_class, cm33_caches_off", [
    (imx95.FlexSpiFlash, False),
    (imx95.FlexSpiFlashCm33, True),
])
def test_prepare_target_writes(flash_class, cm33_caches_off):
    f = flash_class.__new__(flash_class)
    f.target = mock.Mock()
    with mock.patch.object(imx95.AccessPort, 'create') as create:
        f.prepare_target()
    assert f.target.mock_calls[0] == mock.call.reset_and_halt()
    writes = [c.args for c in f.target.ap3.write32.call_args_list]
    caches = [(0x44400000, 0), (0x44400800, 0), (imx95.MPU_CTRL, 0)] if cm33_caches_off else []
    assert writes == list(imx95.XSPI1_PAD_WRITES) + [(0x44452A80, 0x203)] + caches
    # The CM33 flash halts the CM7 through its MEM-AP (AP2); the CM7 flash leaves it to the core.
    cm7_halts = [c.args for c in create.return_value.write32.call_args_list]
    assert cm7_halts == ([(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)]
                         if cm33_caches_off else [])


def test_cm33_algo_call_refreshes_wdog2():
    f = imx95.FlexSpiFlashCm33.__new__(imx95.FlexSpiFlashCm33)
    f.target = mock.Mock()
    with mock.patch.object(Flash, '_call_function') as call:
        f._call_function(0x20000045, 1, 2)
    f.target.ap3.write32.assert_called_once_with(imx95.WDOG2_CNT, imx95.WDOG_REFRESH_KEY)
    call.assert_called_once_with(0x20000045, 1, 2)


def cm7_target(ap2_read32):
    t = imx95.MIMX95_CM7_MX25UM.__new__(imx95.MIMX95_CM7_MX25UM)
    t.ap2 = mock.Mock()
    t.ap2.read32.side_effect = ap2_read32
    t.dp = mock.Mock()
    return t


class TestCm7Connect:
    def test_connect_dhcsr_keeps_reset_flag(self):
        t = cm7_target(lambda a: CortexM.S_RESET_ST | CortexM.C_DEBUGEN)
        assert t._read_connect_dhcsr() & CortexM.S_RESET_ST

    def test_connect_dhcsr_fault(self):
        t = cm7_target(mock.Mock(side_effect=TransferError("fault")))
        assert t._read_connect_dhcsr() is None
        t.dp.clear_sticky_err.assert_called_once()

    def test_wait_out_of_reset(self):
        reads = iter([TransferError("fault"), CortexM.S_RESET_ST, CortexM.S_RESET_ST, 0])
        def read32(addr):
            r = next(reads)
            if isinstance(r, Exception):
                raise r
            return r
        t = cm7_target(read32)
        with mock.patch.object(imx95.time, 'sleep'):
            assert t._wait_m7_out_of_reset() is False
        assert next(reads, None) is None  # stopped at the first read without S_RESET_ST
        t.dp.clear_sticky_err.assert_called_once()

    def test_wait_stops_on_lockup(self):
        t = cm7_target(lambda a: CortexM.S_RESET_ST | CortexM.S_LOCKUP)
        assert t._wait_m7_out_of_reset() is True
        assert t.ap2.read32.call_count == 1


class TestCm7DmaStop:
    def test_stop_clears_erq_waits_and_clears_status(self, core):
        run, idle, done = 0x42010000, 0x42018000, 0x44010000
        core.regs.update({run: imx95.EDMA_CH_CSR_ERQ | imx95.EDMA_CH_CSR_ACTIVE | 0x4, idle: 0,
                done: imx95.EDMA_CH_CSR_DONE})
        writes = []
        def write32(addr, value):
            writes.append((addr, value))
            if addr == run:  # hardware: clearing ERQ lets the channel finish
                value &= ~imx95.EDMA_CH_CSR_ACTIVE
            value &= ~imx95.EDMA_CH_CSR_DONE  # write-one-to-clear
            core.regs[addr] = value
        core.write32 = mock.Mock(side_effect=write32)
        core._stop_dma([run, idle, done])
        addr, value = writes[0]  # ERQ cleared, other bits kept, DONE not written
        assert addr == run and value & 0x4 and not value & (imx95.EDMA_CH_CSR_ERQ | imx95.EDMA_CH_CSR_DONE)
        assert core.regs[run] == 0x4 and core.regs[done] == 0
        assert (done, imx95.EDMA_CH_CSR_DONE) in writes
        assert all((ch + imx95.EDMA_CH_INT, imx95.EDMA_CH_INT_INT) in writes for ch in (run, idle, done))

    def test_restart_stops_dma_when_enabled(self, core):
        core._session.options.get.side_effect = lambda name: name == "imx95.stop_dma"
        core._session.target.m7_dma_channels.return_value = [0x42010000]
        core._stop_dma = mock.Mock()
        with mock.patch.object(CortexM, '_perform_emulated_reset'):
            core._perform_emulated_reset()
        core._stop_dma.assert_called_once_with([0x42010000])

    def test_owned_channels_are_the_readable_pages(self):
        owned = {imx95.EDMA2_CH0 + n * imx95.EDMA2_CH_STEP for n in range(30, 60)}
        owned |= {imx95.EDMA3_CH0 + n * imx95.EDMA3_CH_STEP for n in range(32)}
        def read32(addr):
            if addr not in owned:
                raise TransferError("TRDC denied")
            return 0
        t = cm7_target(read32)
        t._dma_channels = None
        assert set(t.m7_dma_channels()) == owned
        assert t.ap2.read32.call_count == 32 + 32  # one read per eDMA2 pair, one per eDMA3 channel
        t.m7_dma_channels()
        assert t.ap2.read32.call_count == 64  # found once per session


@pytest.mark.parametrize("algo", [imx95.FLASH_ALGO])
def test_algo_has_no_chip_erase(algo):
    assert 'pc_eraseAll' not in algo
    assert not Flash(mock.Mock(), algo).is_erase_all_supported
class TestCm7FlashAlgoLayout:
    algo = imx95.FLASH_ALGO

    def test_buffers_analyzer_and_algo_do_not_overlap(self):
        size = self.algo['page_size']
        spans = [(self.algo['load_address'], self.algo['begin_data']),  # code and stack
                 (self.algo['analyzer_address'], self.algo['analyzer_address'] + 0x600)]
        spans += [(b, b + size) for b in self.algo['page_buffers']]
        spans.sort()
        assert all(a_end <= b_start for (_, a_end), (b_start, _) in zip(spans, spans[1:]))
        assert spans[-1][1] <= imx95.M7_PARK_SP  # DTCM the CM7 target already uses

    @pytest.mark.parametrize("target", [imx95.MIMX95_CM7_MX25UM, imx95.MIMX95_CM33_MX25UM])
    def test_region_page_size_matches_algo(self, target):
        region = target.memoryMap.get_first_matching_region(name="flexspi")
        assert region.algo is self.algo
        assert region.page_size == self.algo['page_size']
        assert region.page_size % region.sector_size == 0 and region.page_size % 0x100 == 0

    def test_analyzer_entries_fit_for_whole_window(self):
        f = Flash(mock.Mock(), self.algo)
        size = self.algo['page_size']
        pages = [(0x28000000, size), (0x28020000, size), (0x2C000000 - size, size)]
        f.target.read_memory_block32.side_effect = lambda addr, n: [0] * n
        f._call_function_and_wait = mock.Mock(return_value=0)
        f.compute_crcs(pages)
        entries = f.target.write_memory_block32.call_args_list[-1].args[1]
        assert [((e >> 16) << (e & 0xFFFF), 1 << (e & 0xFFFF)) for e in entries] == pages
        assert all(e < (1 << 32) for e in entries)


class FakeAlgoFlash:
    """FlexSpiFlash on a fake core: records algo calls by name and page buffer loads."""

    def __init__(self, algo=imx95.FLASH_ALGO, target=imx95.MIMX95_CM7_MX25UM, page_size=None):
        self.events = []
        t = mock.Mock()
        t.session.options.get.return_value = None
        t.write_memory_block8.side_effect = lambda addr, data: self.events.append(('load', addr, len(data)))
        t.read_memory_block8.side_effect = lambda addr, n: [0xFF] * n
        # CRC analyzer results: every page reads as erased.
        t.read_memory_block32.side_effect = lambda addr, n: [zlib.crc32(b'\xff' * self.flash.region.page_size)] * n
        self.flash = f = imx95.FlexSpiFlash(t, algo)
        f.region = target.memoryMap.get_first_matching_region(name="flexspi")
        if page_size:
            f.region = FlashRegion(start=f.region.start, length=f.region.length, blocksize=f.region.blocksize,
                                   page_size=page_size, algo=algo, flash_class=imx95.FlexSpiFlash)
        f.prepare_target = mock.Mock()
        names = {algo[k]: k[3:] for k in algo if k.startswith('pc_')}
        names[algo['analyzer_address']] = 'analyzer'

        def call(pc, r0=None, r1=None, r2=None, r3=None, init=False):
            name = names[pc]
            self.events.append(('init', r2) if name == 'init' else (name, r0) if r0 is not None else (name,))
        f._call_function = call
        f._call_function_and_wait = lambda *a, **k: call(*a, **{x: y for x, y in k.items() if x != 'timeout'}) or 0
        f.wait_for_completion = lambda timeout=None: self.events.append(('wait',)) or 0

    def write(self, addr, data, smart_flash=False):
        fb = self.flash.get_flash_builder()
        fb.add_data(addr, data)
        fb.erase(smart_flash=smart_flash)
        fb.program(smart_flash=smart_flash)
        return self.events


def test_read_setup_restored_after_each_pass():
    events = FakeAlgoFlash().write(0x28020000, bytes(0x4000))
    inits = [e for e in events if e[0] == 'init']
    programs = [i for i, e in enumerate(events) if e[0] == 'program_page']
    assert inits[-1] == ('init', Flash.Operation.VERIFY)
    assert events.index(('init', Flash.Operation.VERIFY), programs[-1]) > programs[-1]


@pytest.mark.parametrize("page_size", [None, 0x100])
def test_erase_overlaps_download_and_precedes_program(page_size):
    fake = FakeAlgoFlash(page_size=page_size)
    base, size = 0x28020000, 0x9000  # ends inside a page and a sector
    events = fake.write(base, bytes(range(256)) * (size // 256))
    page, bufs = fake.flash.region.page_size, fake.flash.page_buffers
    unit = max(page, 0x1000)
    end = base + -(-size // unit) * unit
    first_erase = next(i for i, e in enumerate(events) if e[0] == 'erase_sector')
    assert events[first_erase - 1] == ('init', Flash.Operation.PROGRAM)
    assert ('init', Flash.Operation.ERASE) not in events
    assert [e[1] for e in events if e[0] == 'erase_sector'] == list(range(base, end, 0x1000))
    erased, programmed, loaded = set(), [], dict.fromkeys(bufs, 0)
    for i, e in enumerate(events):
        if e[0] == 'erase_sector':
            assert events[i + 1][0] == 'load' and events[i + 2] == ('wait',)  # download while erasing
            erased.add(e[1])
        elif e[0] == 'load':
            loaded[max(b for b in bufs if b <= e[1])] += e[2]
        elif e[0] == 'program_page':
            assert e[1] & ~0xFFF in erased
            full = [b for b in bufs if loaded[b] >= page]
            assert full  # the whole page is in a buffer before the program starts
            loaded[full[0]] = 0
            programmed.append(e[1])
    assert programmed == list(range(base, end, page))
    # The read setup is restored after the last program.
    assert events[-4:] == [('wait',), ('unInit', Flash.Operation.PROGRAM),
                           ('init', Flash.Operation.VERIFY), ('unInit', Flash.Operation.VERIFY)]


def test_smart_flash_skips_unchanged_pages():
    # The fake flash reads 0xFF: the first page matches and is neither erased nor programmed.
    events = FakeAlgoFlash().write(0x28020000, b'\xff' * 0x4000 + b'\x00' * 0x4000, smart_flash=True)
    assert [e[1] for e in events if e[0] == 'erase_sector'] == list(range(0x28024000, 0x28028000, 0x1000))
    assert [e[1] for e in events if e[0] == 'program_page'] == [0x28024000]
