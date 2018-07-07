"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

from ..pyDAPAccess import DAPAccess
import logging
import logging.handlers
import os
import os.path
import six

# !! This value are A[2:3] and not A[3:2]
DP_REG = {'IDCODE': DAPAccess.REG.DP_0x0,
          'ABORT': DAPAccess.REG.DP_0x0,
          'CTRL_STAT': DAPAccess.REG.DP_0x4,
          'SELECT': DAPAccess.REG.DP_0x8
          }
AP_REG = {'CSW' : 0x00,
          'TAR' : 0x04,
          'DRW' : 0x0C,
          'IDR' : 0xFC
          }

# DP Control / Status Register bit definitions
CTRLSTAT_STICKYORUN = 0x00000002
CTRLSTAT_STICKYCMP = 0x00000010
CTRLSTAT_STICKYERR = 0x00000020

IDCODE = 0 << 2
AP_ACC = 1 << 0
DP_ACC = 0 << 0
READ = 1 << 1
WRITE = 0 << 1
VALUE_MATCH = 1 << 4
MATCH_MASK = 1 << 5

A32 = 0x0c
APSEL_SHIFT = 24
APSEL = 0xff000000
APBANKSEL = 0x000000f0
APREG_MASK = 0x000000fc

DPIDR_MIN_MASK = 0x10000
DPIDR_VERSION_MASK = 0xf000
DPIDR_VERSION_SHIFT = 12

CSYSPWRUPACK = 0x80000000
CDBGPWRUPACK = 0x20000000
CSYSPWRUPREQ = 0x40000000
CDBGPWRUPREQ = 0x10000000

TRNNORMAL = 0x00000000
MASKLANE = 0x00000f00

# Set to True to enable logging of all DP and AP accesses.
LOG_DAP = False

def _ap_addr_to_reg(addr):
    return DAPAccess.REG(4 + ((addr & A32) >> 2))

class DebugPort(object):
    # DAP log file name.
    DAP_LOG_FILE = "pyocd_dap.log"

    def __init__(self, link):
        self.link = link
        self._csw = {}
        self._dp_select = -1
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
        self.read_id_code()
        self.clear_sticky_err()

    def read_id_code(self):
        # Read ID register and get DP version
        self.dpidr = self.read_reg(DP_REG['IDCODE'])
        self.dp_version = (self.dpidr & DPIDR_VERSION_MASK) >> DPIDR_VERSION_SHIFT
        self.is_mindp = (self.dpidr & DPIDR_MIN_MASK) != 0
        return self.dpidr

    def flush(self):
        try:
            self.link.flush()
        except DAPAccess.Error as error:
            self._handle_error(error, self.next_access_number)
            raise
        finally:
            self._csw = {}
            self._dp_select = -1

    def read_reg(self, addr, now=True):
        return self.readDP(addr, now)

    def write_reg(self, addr, data):
        self.writeDP(addr, data)

    def power_up_debug(self):
        # select bank 0 (to access DRW and TAR)
        self.write_reg(DP_REG['SELECT'], 0)
        self.write_reg(DP_REG['CTRL_STAT'], CSYSPWRUPREQ | CDBGPWRUPREQ)

        while True:
            r = self.read_reg(DP_REG['CTRL_STAT'])
            if (r & (CDBGPWRUPACK | CSYSPWRUPACK)) == (CDBGPWRUPACK | CSYSPWRUPACK):
                break

        self.write_reg(DP_REG['CTRL_STAT'], CSYSPWRUPREQ | CDBGPWRUPREQ | TRNNORMAL | MASKLANE)
        self.write_reg(DP_REG['SELECT'], 0)

    def power_down_debug(self):
        # select bank 0 (to access DRW and TAR)
        self.write_reg(DP_REG['SELECT'], 0)
        self.write_reg(DP_REG['CTRL_STAT'], 0)

    def reset(self):
        try:
            self.link.reset()
        finally:
            self._csw = {}
            self._dp_select = -1

    def assert_reset(self, asserted):
        self.link.assert_reset(asserted)
        self._csw = {}
        self._dp_select = -1

    def set_clock(self, frequency):
        self.link.set_clock(frequency)

    def find_aps(self):
        ap_num = 0
        while True:
            try:
                idr = self.readAP((ap_num << APSEL_SHIFT) | AP_REG['IDR'])
                if idr == 0:
                    break
                logging.info("AP#%d IDR = 0x%08x", ap_num, idr)
            except Exception as e:
                logging.error("Exception reading AP#%d IDR: %s", ap_num, repr(e))
                break
            ap_num += 1

    def readDP(self, addr, now=True):
        assert addr in DAPAccess.REG
        num = self.next_access_number

        try:
            result_cb = self.link.read_reg(addr, now=False)
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def readDPCb():
            try:
                result = result_cb()
                if LOG_DAP:
                    self.logger.info("readDP:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr.value, result)
                return result
            except DAPAccess.Error as error:
                self._handle_error(error, num)
                raise

        if now:
            return readDPCb()
        else:
            if LOG_DAP:
                self.logger.info("readDP:%06d (addr=0x%08x) -> ...", num, addr.value)
            return readDPCb

    def writeDP(self, addr, data):
        assert addr in DAPAccess.REG
        num = self.next_access_number

        # Skip writing DP SELECT register if its value is not changing.
        if addr == DP_REG['SELECT']:
            if data == self._dp_select:
                if LOG_DAP:
                    self.logger.info("writeDP:%06d cached (addr=0x%08x) = 0x%08x", num, addr.value, data)
                return
            self._dp_select = data

        # Write the DP register.
        try:
            if LOG_DAP:
                self.logger.info("writeDP:%06d (addr=0x%08x) = 0x%08x", num, addr.value, data)
            self.link.write_reg(addr, data)
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise

        return True

    def writeAP(self, addr, data):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number
        ap_sel = addr & APSEL
        bank_sel = addr & APBANKSEL
        ap_regaddr = addr & APREG_MASK

        # Don't need to write CSW if it's not changing value.
        if ap_regaddr == AP_REG['CSW']:
            if ap_sel in self._csw and data == self._csw[ap_sel]:
                if LOG_DAP:
                    self.logger.info("writeAP:%06d cached (addr=0x%08x) = 0x%08x", num, addr, data)
                return
            self._csw[ap_sel] = data

        # Select the AP and bank.
        self.writeDP(DP_REG['SELECT'], ap_sel | bank_sel)

        # Perform the AP register write.
        ap_reg = _ap_addr_to_reg(WRITE | AP_ACC | (addr & A32))
        try:
            if LOG_DAP:
                self.logger.info("writeAP:%06d (addr=0x%08x) = 0x%08x", num, addr, data)
            self.link.write_reg(ap_reg, data)
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise

        return True

    def readAP(self, addr, now=True):
        assert type(addr) in (six.integer_types)
        num = self.next_access_number
        res = None
        ap_reg = _ap_addr_to_reg(READ | AP_ACC | (addr & A32))

        try:
            ap_sel = addr & APSEL
            bank_sel = addr & APBANKSEL
            self.writeDP(DP_REG['SELECT'], ap_sel | bank_sel)
            result_cb = self.link.read_reg(ap_reg, now=False)
        except DAPAccess.Error as error:
            self._handle_error(error, num)
            raise

        # Read callback returned for async reads.
        def readAPCb():
            try:
                result = result_cb()
                if LOG_DAP:
                    self.logger.info("readAP:%06d %s(addr=0x%08x) -> 0x%08x", num, "" if now else "...", addr, result)
                return result
            except DAPAccess.Error as error:
                self._handle_error(error, num)
                raise

        if now:
            return readAPCb()
        else:
            if LOG_DAP:
                self.logger.info("readAP:%06d (addr=0x%08x) -> ...", num, addr)
            return readAPCb

    def _handle_error(self, error, num):
        if LOG_DAP:
            self.logger.info("error:%06d %s", num, error)
        # Invalidate cached registers
        self._csw = {}
        self._dp_select = -1
        # Clear sticky error for Fault errors only
        if isinstance(error, DAPAccess.TransferFaultError):
            self.clear_sticky_err()

    def clear_sticky_err(self):
        mode = self.link.get_swj_mode()
        if mode == DAPAccess.PORT.SWD:
            self.link.write_reg(DAPAccess.REG.DP_0x0, (1 << 2))
        elif mode == DAPAccess.PORT.JTAG:
            self.link.write_reg(DP_REG['CTRL_STAT'], CTRLSTAT_STICKYERR)
        else:
            assert False



