"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2018 ARM Limited

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

from ..core import exceptions
from ..probe.debug_probe import DebugProbe
from .ap import (MEM_AP_CSW, LOG_DAP, APSEL, APBANKSEL, APREG_MASK, AccessPort)
from ..utility.sequencer import CallSequence
import logging
import logging.handlers
import os
import os.path
import six

# DP register addresses.
DP_IDCODE = 0x0 # read-only
DP_ABORT = 0x0 # write-only
DP_CTRL_STAT = 0x4 # read-write
DP_SELECT = 0x8 # write-only
DP_RDBUFF = 0xC # read-only

ABORT_STKERRCLR = 0x00000004

# DP Control / Status Register bit definitions
CTRLSTAT_STICKYORUN = 0x00000002
CTRLSTAT_STICKYCMP = 0x00000010
CTRLSTAT_STICKYERR = 0x00000020

DPIDR_MIN_MASK = 0x10000
DPIDR_VERSION_MASK = 0xf000
DPIDR_VERSION_SHIFT = 12

CSYSPWRUPACK = 0x80000000
CDBGPWRUPACK = 0x20000000
CSYSPWRUPREQ = 0x40000000
CDBGPWRUPREQ = 0x10000000

TRNNORMAL = 0x00000000
MASKLANE = 0x00000f00

class DebugPort(object):
    # DAP log file name.
    DAP_LOG_FILE = "pyocd_dap.log"

    def __init__(self, link, target):
        self.link = link
        self.target = target
        self.valid_aps = None
        self.aps = {}
        self._access_number = 0
        if LOG_DAP:
            self._setup_logging()

    @property
    def next_access_number(self):
        self._access_number += 1
        return self._access_number

    ## @brief Set up DAP logging.
    #
    # A memory handler is created that buffers log records before flushing them to a file
    # handler that writes to DAP_LOG_FILE. This improves logging performance by writing to the
    # log file less often.
    def _setup_logging(self):
        cwd = os.getcwd()
        logfile = os.path.join(cwd, self.DAP_LOG_FILE)
        logging.info("dap logfile: %s", logfile)
        self.logger = logging.getLogger('dap')
        self.logger.propagate = False
        formatter = logging.Formatter('%(relativeCreated)010dms:%(levelname)s:%(name)s:%(message)s')
        fileHandler = logging.FileHandler(logfile, mode='w+', delay=True)
        fileHandler.setFormatter(formatter)
        memHandler = logging.handlers.MemoryHandler(capacity=128, target=fileHandler)
        self.logger.addHandler(memHandler)
        self.logger.setLevel(logging.DEBUG)

    def init(self):
        # Connect to the target.
        self.link.connect()
        self.link.swj_sequence()
        try:
            self.read_id_code()
        except exceptions.TransferError:
            # If the read of the DP IDCODE fails, retry SWJ sequence. The DP may have been
            # in a state where it thought the SWJ sequence was an invalid transfer.
            self.link.swj_sequence()
            self.read_id_code()
        self.clear_sticky_err()

    def read_id_code(self):
        # Read ID register and get DP version
        self.dpidr = self.read_reg(DP_IDCODE)
        self.dp_version = (self.dpidr & DPIDR_VERSION_MASK) >> DPIDR_VERSION_SHIFT
        self.is_mindp = (self.dpidr & DPIDR_MIN_MASK) != 0
        logging.info("DP IDR = 0x%08x", self.dpidr)
        return self.dpidr

    def flush(self):
        try:
            self.link.flush()
        except exceptions.ProbeError as error:
            self._handle_error(error, self.next_access_number)
            raise

    def read_reg(self, addr, now=True):
        return self.read_dp(addr, now)

    def write_reg(self, addr, data):
        self.write_dp(addr, data)

    def power_up_debug(self):
        # select bank 0 (to access DRW and TAR)
        self.write_reg(DP_SELECT, 0)
        self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ)

        while True:
            r = self.read_reg(DP_CTRL_STAT)
            if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == (CDBGPWRUPACK | CSYSPWRUPACK):
                break

        self.write_reg(DP_CTRL_STAT, CSYSPWRUPREQ | CDBGPWRUPREQ | TRNNORMAL | MASKLANE)
        self.write_reg(DP_SELECT, 0)

    def power_down_debug(self):
        # select bank 0 (to access DRW and TAR)
        self.write_reg(DP_SELECT, 0)
        self.write_reg(DP_CTRL_STAT, 0)

    def reset(self):
        for ap in self.aps.values():
            ap.reset_did_occur()
        self.link.reset()

    def assert_reset(self, asserted):
        if asserted:
            for ap in self.aps.values():
                ap.reset_did_occur()
        self.link.assert_reset(asserted)

    def is_reset_asserted(self):
        return self.link.is_reset_asserted()

    def set_clock(self, frequency):
        self.link.set_clock(frequency)
        
    ## @brief Find valid APs.
    #
    # Scans for valid APs starting at APSEL=0 and stopping the first time a 0 is returned
    # when reading the AP's IDR.
    #
    # Note that a few MCUs will lock up when accessing invalid APs. Those MCUs will have to
    # modify the init call sequence to substitute a fixed list of valid APs. In fact, that
    # is a major reason this method is separated from create_aps().
    def find_aps(self):
        if self.valid_aps is not None:
            return
        self.valid_aps = []
        ap_num = 0
        while True:
            try:
                isValid = AccessPort.probe(self, ap_num)
                if not isValid:
                    return
                self.valid_aps.append(ap_num)
            except Exception as e:
                logging.error("Exception while probing AP#%d: %s", ap_num, repr(e))
                break
            ap_num += 1

    ## @brief Init task that returns a call sequence to create APs.
    #
    # For each AP in the #valid_aps list, an AccessPort object is created. The new objects
    # are added to the #aps dict, keyed by their AP number.
    def create_aps(self):
        seq = CallSequence()
        for ap_num in self.valid_aps:
            seq.append(
                ('create_ap.{}'.format(ap_num), lambda ap_num=ap_num: self.create_1_ap(ap_num))
                )
        return seq
    
    ## @brief Init task to create a single AP object.
    def create_1_ap(self, ap_num):
        try:
            ap = AccessPort.create(self, ap_num)
            logging.info("AP#%d IDR = 0x%08x", ap_num, ap.idr)
            self.aps[ap_num] = ap
        except Exception as e:
            logging.error("Exception reading AP#%d IDR: %s", ap_num, repr(e))
    
    ## @brief Init task that generates a call sequence to init all AP ROMs.
    def init_ap_roms(self):
        seq = CallSequence()
        for ap in [x for x in self.aps.values() if x.has_rom_table]:
            seq.append(
                ('init_ap.{}'.format(ap.ap_num), ap.init_rom_table)
                )
        return seq

    def read_dp(self, addr, now=True):
        num = self.next_access_number

        try:
            result_cb = self.link.read_dp(addr, now=False)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def read_dp_cb():
            try:
                result = result_cb()
                if LOG_DAP:
                    self.logger.info("read_dp:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr.value, result)
                return result
            except exceptions.ProbeError as error:
                self._handle_error(error, num)
                raise

        if now:
            return read_dp_cb()
        else:
            if LOG_DAP:
                self.logger.info("read_dp:%06d (addr=0x%08x) -> ...", num, addr.value)
            return read_dp_cb

    def write_dp(self, addr, data):
        num = self.next_access_number

        # Write the DP register.
        try:
            if LOG_DAP:
                self.logger.info("write_dp:%06d (addr=0x%08x) = 0x%08x", num, addr.value, data)
            self.link.write_dp(addr, data)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        return True

    def write_ap(self, addr, data):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number

        try:
            if LOG_DAP:
                self.logger.info("write_ap:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.link.write_ap(addr, data)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        return True

    def read_ap(self, addr, now=True):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number

        try:
            result_cb = self.link.read_ap(addr, now=False)
        except exceptions.ProbeError as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def read_ap_cb():
            try:
                result = result_cb()
                if LOG_DAP:
                    self.logger.info("read_ap:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except exceptions.ProbeError as error:
                self._handle_error(error, num)
                raise

        if now:
            return read_ap_cb()
        else:
            if LOG_DAP:
                self.logger.info("read_ap:%06d (addr=0x%08x) -> ...", num, addr)
            return read_ap_cb

    def _handle_error(self, error, num):
        if LOG_DAP:
            self.logger.info("error:%06d %s", num, error)
        # Clear sticky error for Fault errors only
        if isinstance(error, exceptions.TransferFaultError):
            self.clear_sticky_err()

    def clear_sticky_err(self):
        mode = self.link.wire_protocol
        if mode == DebugProbe.Protocol.SWD:
            self.write_reg(DP_ABORT, ABORT_STKERRCLR)
        elif mode == DebugProbe.Protocol.JTAG:
            self.write_reg(DP_CTRL_STAT, CTRLSTAT_STICKYERR)
        else:
            assert False



