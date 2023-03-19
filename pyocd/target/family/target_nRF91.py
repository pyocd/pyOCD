# pyOCD debugger
# Copyright (c) 2006-2013 Arm Limited
# Copyright (c) 2019 Monadnock Systems Ltd.
# Copyright (c) 2023 Nordic Semiconductor ASA
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
from time import sleep
import os
import re
from zipfile import ZipFile
from tempfile import TemporaryDirectory
from intelhex import IntelHex

from ...core import exceptions
from ...core.target import Target
from ...coresight.coresight_target import CoreSightTarget
from ...flash.eraser import FlashEraser
from ...flash.file_programmer import FileProgrammer
from ...utility.timeout import Timeout
from ...utility.progress import print_progress

from typing import (Callable, Optional, TYPE_CHECKING, Union)
ProgressCallback = Callable[[Union[int, float]], None]

if TYPE_CHECKING:
    from ...core.session import Session

AHB_AP_NUM = 0x0
APB_AP_NUM = 0x3
CTRL_AP_NUM = 0x4

CTRL_AP_RESET = 0x000
CTRL_AP_ERASEALL = 0x004
CTRL_AP_ERASEALLSTATUS = 0x008
CTRL_AP_APPROTECTSTATUS = 0x00C
CTRL_AP_ERASEPROTECTSTATUS = 0x018
CTRL_AP_ERASEPROTECTDISABLE = 0x01C
CTRL_AP_MAILBOX_TXDATA = 0x020
CTRL_AP_MAILBOX_TXSTATUS = 0x024
CTRL_AP_MAILBOX_RXDATA = 0x028
CTRL_AP_MAILBOX_RXSTATUS = 0x02C
CTRL_AP_IDR = 0x0FC

CTRL_AP_ERASEALLSTATUS_READY = 0x0
CTRL_AP_ERASEALLSTATUS_BUSY = 0x1

CTRL_AP_APPROTECTSTATUS_APPROTECT_MSK = 0x1
CTRL_AP_APPROTECTSTATUS_SECUREAPPROTECT_MSK = 0x2
CTRL_AP_ERASEPROTECTSTATUS_MSK = 0x1

CTRL_AP_MAILBOX_STATUS_NODATAPENDING = 0x0
CTRL_AP_MAILBOX_STATUS_DATAPENDING = 0x1

CTRL_AP_RESET_NORESET = 0x0
CTRL_AP_RESET_RESET = 0x1

CTRL_AP_ERASEALL_NOOPERATION = 0x0
CTRL_AP_ERASEALL_ERASE = 0x1

CTRL_IDR_EXPECTED = 0x12880000

MASS_ERASE_TIMEOUT = 30.0

FAULT_EVENT = 0x4002A100
COMMAND_EVENT = 0x4002A108
DATA_EVENT = 0x4002A110
IPC_PIPELINED_MAX_BUFFER_SIZE = 0xE000
IPC_MAX_BUFFER_SIZE = 0x10000

LOG = logging.getLogger(__name__)


def change_endianness(x: int, n=4) -> int:
    return sum(((x >> 8*i) & 0xFF) << 8*(n-i-1) for i in range(n))

def bytes_to_word(bts):
    result = 0
    for i, b in enumerate(bts):
        result |= b << (8*i)
    return result

def word_to_bytes(wrd):
    result = []
    for i in range(4):
        result.append((wrd >> (8*i)) & 0xFF)
    return bytes(result)

def split_addr_range_into_chunks(range, chunk_size):
    chunks = []
    addr = range[0]
    while True:
        c = (addr, min(range[1], addr + chunk_size))
        chunks.append(c)
        addr = c[1]
        if addr == range[1]:
            break
    return chunks


class NRF91(CoreSightTarget):

    VENDOR = "Nordic Semiconductor"

    def __init__(self, session, memory_map=None):
        super(NRF91, self).__init__(session, memory_map)
        self.ctrl_ap = None

    def create_init_sequence(self):
        seq = super(NRF91, self).create_init_sequence()

        # Must check whether security is enabled, and potentially auto-unlock, before
        # any init tasks that require system bus access.
        seq.wrap_task('discovery',
            lambda seq: seq.insert_before('find_components',
                              ('check_ctrl_ap_idr', self.check_ctrl_ap_idr),
                              ('check_flash_security', self.check_flash_security),
                          )
            )

        seq.insert_before('post_connect_hook',
                          ('check_part_info', self.check_part_info))

        return seq

    def check_ctrl_ap_idr(self):
        self.ctrl_ap = self.dp.aps[CTRL_AP_NUM]

        # Check CTRL-AP ID.
        if self.ctrl_ap.idr != CTRL_IDR_EXPECTED:
            LOG.error("%s: bad CTRL-AP IDR (is 0x%08x)", self.part_number, self.ctrl_ap.idr)

    def check_flash_security(self):
        """@brief Check security and unlock device.

        This init task determines whether the device is locked (APPROTECT enabled). If it is,
        and if auto unlock is enabled, then perform a mass erase to unlock the device.

        This init task runs *before* cores are created.
        """

        if self.is_locked():
            if self.session.options.get('auto_unlock'):
                LOG.warning("%s APPROTECT enabled: will try to unlock via mass erase", self.part_number)

                # Do the mass erase.
                if not self.mass_erase():
                    LOG.error("%s: mass erase failed", self.part_number)
                    raise exceptions.TargetErrors.TargetError("unable to unlock device")
                # Target needs to be reset to clear protection status
                self.session.probe.reset()
                self.pre_connect()
                self.dp.connect()
                self._discoverer._create_1_ap(AHB_AP_NUM)
                self._discoverer._create_1_ap(APB_AP_NUM)
            else:
                LOG.warning("%s APPROTECT enabled: not automatically unlocking", self.part_number)
        else:
            LOG.info("%s not in secure state", self.part_number)

    def is_locked(self):
        status = self.ctrl_ap.read_reg(CTRL_AP_APPROTECTSTATUS)
        return (status & CTRL_AP_APPROTECTSTATUS_APPROTECT_MSK == 0) \
            or (status & CTRL_AP_APPROTECTSTATUS_SECUREAPPROTECT_MSK == 0)

    def is_eraseprotected(self):
        status = self.ctrl_ap.read_reg(CTRL_AP_ERASEPROTECTSTATUS)
        return status & CTRL_AP_ERASEPROTECTSTATUS_MSK == 0

    def mass_erase(self):
        if self.is_eraseprotected():
            LOG.warning("ERASEPROTECT is enabled.")
            if self.is_locked():
                LOG.error("If the firmware supports unlocking with a known 32-bit key,")
                LOG.error("then this is the only way to recover the device.")
                return False
            else:
                LOG.warning("Performing a chip erase instead.")
                eraser = FlashEraser(self.session, FlashEraser.Mode.CHIP)
                eraser._log_chip_erase = False
                eraser.erase()
                return True

        # See Nordic Whitepaper nWP-027 for magic numbers and order of operations from the vendor
        self.ctrl_ap.write_reg(CTRL_AP_ERASEALL, CTRL_AP_ERASEALL_ERASE)
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.ctrl_ap.read_reg(CTRL_AP_ERASEALLSTATUS)
                if status == CTRL_AP_ERASEALLSTATUS_READY:
                    break
                sleep(0.1)
            else:
                # Timed out
                LOG.error("Mass erase timeout waiting for ERASEALLSTATUS")
                return False
        self.ctrl_ap.write_reg(CTRL_AP_RESET, CTRL_AP_RESET_RESET)
        self.ctrl_ap.write_reg(CTRL_AP_RESET, CTRL_AP_RESET_NORESET)
        self.ctrl_ap.write_reg(CTRL_AP_ERASEALL, CTRL_AP_ERASEALL_NOOPERATION)
        return True

    def check_part_info(self):
        partno = self.read32(0x00FF0140)
        hwrevision = self.read32(0x00FF0144)
        variant = self.read32(0x00FF0148)

        LOG.info(f"This appears to be an nRF{partno:X} " +
                 f"{word_to_bytes(variant).decode('ASCII', errors='ignore')} " +
         	 f"{word_to_bytes(hwrevision).decode('ASCII', errors='ignore')}")

    def write_uicr(self, addr: int, value: int):
        current_value = self.read32(addr)
        if ((current_value & value) != value) and (current_value != 0xFFFFFFFF):
            raise exceptions.TargetError("cannot write UICR value, mass_erase needed")

        self.write32(0x50039504, 1)  # NVMC.CONFIG = WriteEnable
        self._wait_nvmc_ready()
        self.write32(addr, value)
        self._wait_nvmc_ready()
        self.write32(0x50039504, 0)  # NVMC.CONFIG = ReadOnly
        self._wait_nvmc_ready()

    def _wait_nvmc_ready(self):
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                if self.read32(0x50039400) != 0x00000000:  # NVMC.READY != BUSY
                    break
            else:
                raise exceptions.TargetError("wait for NVMC timed out")

class ModemUpdater(object):
    """@brief Implements the nRF91 Modem Update procedure like described in nAN-41"""
    _target: "Target"
    _session: "Session"
    _progress: Optional[ProgressCallback]
    _total_data_size: int
    _progress_offset: float
    _current_progress_fraction: float
    _chunk_size: int
    _pipelined: bool
    _segments: list
    _firmware_update_digest: str

    def __init__(self,
                 session: "Session",
                 progress: Optional[ProgressCallback] = None,
                 ):
        self._session = session
        self._target = session.board.target
        self._total_data_size = 0
        self._pipelined = False
        self._segments = []
        self._firmware_update_digest = None

        if progress is not None:
            self._progress = progress
        elif session.options.get('hide_programming_progress'):
            self._progress = None
        else:
            self._progress = print_progress()

        self._reset_state()

    def program_and_verify(self, mfw_zip: str):
        """@brief Program and verify modem firmware from ZIP file."""
        self._setup_device()
        self._process_zip_file(mfw_zip)

        LOG.info("programming modem firmware..")
        self._total_data_size = sum(r[1]-r[0] for s in self._segments for r in s.segments())
        for s in self._segments:
            self._program_segment(s)
        self._progress(1.0)
        LOG.info("modem firmware programmed.")

        LOG.info("verifying modem firmware..")
        self._verify()
        LOG.info("modem firmware verified.")

    def verify(self, mfw_zip: str):
        """@brief Just verify modem firmware from ZIP file."""
        self._setup_device()
        self._process_zip_file(mfw_zip)

        LOG.info("verifying modem firmware..")
        self._verify()
        LOG.info("modem firmware verified.")

    def _setup_device(self):
        """@brief initialize device to use modem DFU"""
        # init UICR.HFXOSR if necessary
        if self._target.read32(0x00FF801C) == 0xFFFFFFFF:
            LOG.warning("UICR.HFXOSR is not set, setting it to 0x0E")
            self._target.write_uicr(addr=0x00FF801C, value=0x0000000E)

        # init UICR.HFXOCNT if necessary
        if self._target.read32(0x00FF8020) == 0xFFFFFFFF:
            LOG.warning("UICR.HFXOCNT is not set, setting it to 0x20")
            self._target.write_uicr(addr=0x00FF8020, value=0x00000020)

        self._target.reset_and_halt(reset_type=Target.ResetType.SW)

        # 1. configure IPC to be in non-secure mode
        self._target.write32(addr=0x500038A8, value=0x00000002)

        # 2. configure IPC HW for DFU
        self._target.write32(addr=0x4002A514, value=0x00000002)
        self._target.write32(addr=0x4002A51C, value=0x00000008)
        self._target.write32(addr=0x4002A610, value=0x21000000)
        self._target.write32(addr=0x4002A614, value=0x00000000)
        self._target.write32(addr=0x4002A590, value=0x00000001)
        self._target.write32(addr=0x4002A598, value=0x00000004)
        self._target.write32(addr=0x4002A5A0, value=0x00000010)

        # 3. configure RAM as non-secure
        for n in range(32):
            self._target.write32(addr=0x50003700+(n*4), value=0x00000007)

        # 4. allocate memory in RAM
        self._target.write32(addr=0x20000000, value=0x80010000)
        self._target.write32(addr=0x20000004, value=0x2100000C)
        self._target.write32(addr=0x20000008, value=0x0003FC00)

        # 5. reset the modem
        self._target.write32(addr=0x50005610, value=0)
        self._target.write32(addr=0x50005614, value=1)
        self._target.write32(addr=0x50005610, value=1)
        self._target.write32(addr=0x50005614, value=0)
        self._target.write32(addr=0x50005610, value=0)

    def _process_zip_file(self, mfw_zip: str):
        """@brief extract the mfw ZIP file and load DFU loader"""
        digest_id = self._read_key_digest()
        modem_firmware_loader = None

        with TemporaryDirectory() as tmpdir:
            with ZipFile(mfw_zip, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)
            files = os.listdir(tmpdir)

            # find modem firmware loader
            for f in files:
                if f.startswith(f"{digest_id}.ipc_dfu.signed_") and f.endswith(".ihex"):
                    modem_firmware_loader = os.path.join(tmpdir, f)
                    m = re.match(r"\.ipc_dfu\.signed_(\d+)\.(\d+)\.(\d+)\.ihex", f[7:])
                    if m:
                        loader_version = tuple(int(x) for x in m.groups())
                        LOG.info("modem_firmware_loader version: {}.{}.{}".format(
                            *loader_version))
                        if loader_version > (1, 1, 2):
                            LOG.info("using pipelined method")
                            self._pipelined = True
                    break
            if not modem_firmware_loader:
                raise exceptions.TargetError(
                    f"No compatible loader {digest_id}.ipc_dfu.signed_x.x.x.ihex found.")

            # find modem firmware segments
            for f in files:
                m = re.match(r"firmware\.update\.image\.segments\.(\d+).hex", f)
                if m:
                    self._segments.append(
                        (m.group(1), os.path.join(tmpdir, f)))
            self._segments.sort()
            self._segments = [IntelHex(s[1]) for s in self._segments]

            if len(self._segments) == 0:
                raise exceptions.TargetError("No modem firmware segments found")

            # parse segment digests
            with open(os.path.join(tmpdir, "firmware.update.image.digest.txt"), "r") as f:
                for line in f:
                    m = re.match(r"SHA256 of all ranges in ascending address order:\s*(\w{64})",
                                 line)
                    if m:
                        self._firmware_update_digest = m.group(1)
            if not self._firmware_update_digest:
                raise exceptions.TargetError("no firmware digest found")

            LOG.info("loading modem firmware loader..")
            FileProgrammer(self._session).program(
                modem_firmware_loader, file_format='hex')
            self._target.write32(0x4002A004, 0x00000001)  # start IPC task
            self._wait_and_ack_events()
            LOG.info("modem_firmware_loader started.")

    def _read_key_digest(self) -> str:
        """@brief read first word of modem key digest for choosing a loader"""
        self._wait_and_ack_events()
        digest_data = change_endianness(self._target.read32(0x20000010))
        return (f"{digest_data:08X}")[:7]

    def _program_segment(self, segment: IntelHex):
        """@brief program contents of segment HEX file using DFU loader"""
        if self._pipelined:
            bufsz = IPC_PIPELINED_MAX_BUFFER_SIZE
        else:
            bufsz = IPC_MAX_BUFFER_SIZE

        chunks = []
        for s in segment.segments():
            chunks += split_addr_range_into_chunks(s, bufsz)

        if self._pipelined:
            self._write_chunk(segment, chunks[0], 0)

            for i, c in enumerate(chunks):
                self._commit_chunk(c, i % 2)

                # write next chunk while current one is processed
                if (i + 1) < len(chunks):
                    self._write_chunk(segment, chunks[i + 1], (i + 1) % 2)

                self._wait_and_ack_events()
        else:
            for i, c in enumerate(chunks):
                self._write_chunk(segment, c, 0)
                self._commit_chunk(c, 0)
                self._wait_and_ack_events()

    def _write_chunk(self, segment: IntelHex, chunk, bank):
        """@brief write a chunk of the current segment to RAM"""
        start = chunk[0]
        size = chunk[1]-chunk[0]
        if self._pipelined:
            ram_address = 0x2000001C + IPC_PIPELINED_MAX_BUFFER_SIZE * bank
        else:
            ram_address = 0x20000018

        data = list(segment.tobinarray(start=start, size=size))
        data_words = [bytes_to_word(data[i:i+4])
                      for i in range(0, len(data), 4)]
        self._target.write_memory_block32(ram_address, data_words)
        self._current_progress_fraction = size / float(self._total_data_size)
        self._progress_cb(1.0)
        self._progress_offset += self._current_progress_fraction

    def _commit_chunk(self, chunk, bank):
        """@brief signal DFU loader that chunk is ready to be programmed"""
        buffer_offset = bank * IPC_PIPELINED_MAX_BUFFER_SIZE
        self._target.write32(0x20000010, chunk[0])
        self._target.write32(0x20000014, chunk[1]-chunk[0])
        if self._pipelined:
            self._target.write32(0x20000018, buffer_offset)
        if self._pipelined:
            # command = PIPELINE_WRITE
            self._target.write32(0x2000000C, 0x9)
        else:
            # command = WRITE
            self._target.write32(0x2000000C, 0x3)
        # start IPC task
        self._target.write32(0x4002A004, 1)

    def _verify(self):
        """@brief verify programmed modem firmware"""
        ranges_to_verify = []
        for s in self._segments:
            for r in s.segments():
                if r[0] < 0x1000000:
                    ranges_to_verify.append(r)

        # write given start, size pairs and number of entries
        self._target.write32(0x20000010, len(ranges_to_verify))
        for i, (start, end) in enumerate(ranges_to_verify):
            self._target.write32(0x20000014 + (8 * i), start)
            self._target.write32(0x20000018 + (8 * i), end-start)

        # command = VERIFY
        self._target.write32(0x2000000C, 0x7)
        # start IPC task
        self._target.write32(0x4002A004, 1)

        self._wait_and_ack_events()

        response = self._target.read32(0x2000000C)
        if (response & 0xFF000000) == 0x5A000000:
            raise exceptions.TargetError(f"Error while verifying: {response & 0xFFFFFF:X}")

        digest_data = [self._target.read32(x) for x in range(0x20000010, 0x2000002D, 0x4)]
        digest_str = "".join(f"{x:08X}" for x in digest_data)

        if digest_str != self._firmware_update_digest:
            raise exceptions.TargetError(
                f"checksum mismatch: {digest_str} != {self._firmware_update_digest}"
            )

    def _wait_and_ack_events(self):
        """@brief wait for and acknowledge DFU events"""
        fault = False

        # poll for events
        with Timeout(MASS_ERASE_TIMEOUT) as to:
            while to.check():
                if self._target.read32(FAULT_EVENT) != 0:
                    fault = True
                    break
                if self._target.read32(COMMAND_EVENT) != 0:
                    break
                if self._target.read32(DATA_EVENT) != 0:
                    break
            else:
                raise exceptions.TargetError("wait for events timed out")

        # reset events
        for reg in [FAULT_EVENT, COMMAND_EVENT, DATA_EVENT]:
            self._target.write32(reg, 0)

        response = self._target.read32(0x2000000C)
        if (response & 0xFF000000) == 0xA5000000:
            LOG.debug(f"ACK response, code {response:08X}")
        elif (response & 0xFF000000) == 0x5A000000:
            raise exceptions.TargetError(f"NACK response, code {response:08X}")

        if fault:
            raise exceptions.TargetError("modem triggered FAULT_EVENT")

    def _reset_state(self):
        """@brief Clear all state variables. """
        self._total_data_size = 0
        self._progress_offset = 0.0
        self._current_progress_fraction = 0.0

    def _progress_cb(self, amount):
        """@brief callback for updating the progress bar"""
        if self._progress is not None:
            self._progress((amount * self._current_progress_fraction) + self._progress_offset)
