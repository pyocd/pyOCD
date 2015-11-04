"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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

from pyOCD.pyDAPAccess import DAPAccess
import logging
from time import sleep

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

APBANKSEL = 0x000000f0

# AP Control and Status Word definitions
CSW_SIZE     =  0x00000007
CSW_SIZE8    =  0x00000000
CSW_SIZE16   =  0x00000001
CSW_SIZE32   =  0x00000002
CSW_ADDRINC  =  0x00000030
CSW_NADDRINC =  0x00000000
CSW_SADDRINC =  0x00000010
CSW_PADDRINC =  0x00000020
CSW_DBGSTAT  =  0x00000040
CSW_TINPROG  =  0x00000080
CSW_HPROT    =  0x02000000
CSW_MSTRTYPE =  0x20000000
CSW_MSTRCORE =  0x00000000
CSW_MSTRDBG  =  0x20000000
CSW_RESERVED =  0x01000000

CSW_VALUE = (CSW_RESERVED | CSW_MSTRDBG | CSW_HPROT | CSW_DBGSTAT | CSW_SADDRINC)

TRANSFER_SIZE = {8: CSW_SIZE8,
                 16: CSW_SIZE16,
                 32: CSW_SIZE32
                 }

COMMANDS_PER_DAP_TRANSFER = 12


def _ap_addr_to_reg(addr):
    return DAPAccess.REG(4 + ((addr & 0x0c) >> 2))


class Dap(object):
    """
    This class implements the CMSIS-DAP protocol
    """
    def __init__(self, link):
        self.link = link
        self.csw = -1
        self.dp_select = -1

    def init(self):
        self._clear_sticky_err()

    def writeMem(self, addr, data, transfer_size=32):
        self.writeAP(AP_REG['CSW'], CSW_VALUE | TRANSFER_SIZE[transfer_size])
        if transfer_size == 8:
            data = data << ((addr & 0x03) << 3)
        elif transfer_size == 16:
            data = data << ((addr & 0x02) << 3)

        try:
            reg = _ap_addr_to_reg(WRITE | AP_ACC | AP_REG['TAR'])
            self.link.write_reg(reg, addr)
            reg = _ap_addr_to_reg(WRITE | AP_ACC | AP_REG['DRW'])
            self.link.write_reg(reg, data)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise

    def readMem(self, addr, transfer_size=32, now=True):
        res = None
        try:
            self.writeAP(AP_REG['CSW'], CSW_VALUE |
                         TRANSFER_SIZE[transfer_size])
            reg = _ap_addr_to_reg(WRITE | AP_ACC | AP_REG['TAR'])
            self.link.write_reg(reg, addr)
            reg = _ap_addr_to_reg(READ | AP_ACC | AP_REG['DRW'])
            result_cb = self.link.read_reg(reg, now=False)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise

        def readMemCb():
            try:
                res = result_cb()
                if transfer_size == 8:
                    res = (res >> ((addr & 0x03) << 3) & 0xff)
                elif transfer_size == 16:
                    res = (res >> ((addr & 0x02) << 3) & 0xffff)
            except DAPAccess.Error as error:
                self._handle_error(error)
                raise
            return res

        if now:
            return readMemCb()
        else:
            return readMemCb

    # write aligned word ("data" are words)
    def writeBlock32(self, addr, data):
        # put address in TAR
        self.writeAP(AP_REG['CSW'], CSW_VALUE | CSW_SIZE32)
        self.writeAP(AP_REG['TAR'], addr)
        try:
            reg = _ap_addr_to_reg(WRITE | AP_ACC | AP_REG['DRW'])
            self.link.reg_write_repeat(len(data), reg, data)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise

    # read aligned word (the size is in words)
    def readBlock32(self, addr, size):
        # put address in TAR
        self.writeAP(AP_REG['CSW'], CSW_VALUE | CSW_SIZE32)
        self.writeAP(AP_REG['TAR'], addr)
        try:
            reg = _ap_addr_to_reg(READ | AP_ACC | AP_REG['DRW'])
            resp = self.link.reg_read_repeat(size, reg)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise
        return resp

    def readDP(self, addr, now=True):
        assert addr in DAPAccess.REG

        try:
            result_cb = self.link.read_reg(addr, now=False)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise

        def readDPCb():
            try:
                return result_cb()
            except DAPAccess.Error as error:
                self._handle_error(error)
                raise

        if now:
            return readDPCb()
        else:
            return readDPCb

    def writeDP(self, addr, data):
        assert addr in DAPAccess.REG
        if addr == DP_REG['SELECT']:
            if data == self.dp_select:
                return
            self.dp_select = data

        try:
            self.link.write_reg(addr, data)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise
        return True

    def writeAP(self, addr, data):
        assert type(addr) in (int, long)
        ap_sel = addr & 0xff000000
        bank_sel = addr & APBANKSEL
        self.writeDP(DP_REG['SELECT'], ap_sel | bank_sel)

        if addr == AP_REG['CSW']:
            if data == self.csw:
                return
            self.csw = data

        ap_reg = _ap_addr_to_reg(WRITE | AP_ACC | (addr & 0x0c))
        try:
            self.link.write_reg(ap_reg, data)

        except DAPAccess.Error as error:
            self._handle_error(error)
            raise

        return True

    def readAP(self, addr, now=True):
        assert type(addr) in (int, long)
        res = None
        ap_reg = _ap_addr_to_reg(READ | AP_ACC | (addr & 0x0c))

        try:
            ap_sel = addr & 0xff000000
            bank_sel = addr & APBANKSEL
            self.writeDP(DP_REG['SELECT'], ap_sel | bank_sel)
            result_cb = self.link.read_reg(ap_reg, now=False)
        except DAPAccess.Error as error:
            self._handle_error(error)
            raise

        def readAPCb():
            try:
                return result_cb()
            except DAPAccess.Error as error:
                self._handle_error(error)
                raise

        if now:
            return readAPCb()
        else:
            return readAPCb

    def _handle_error(self, error):
        # Invalidate cached registers
        self.csw = -1
        self.dp_select = -1
        # Clear sticky error for Fault errors only
        if isinstance(error, DAPAccess.TransferFaultError):
            self._clear_sticky_err()

    def _clear_sticky_err(self):
        mode = self.link.get_swj_mode()
        if mode == DAPAccess.PORT.SWD:
            self.link.write_reg(DAPAccess.REG.DP_0x0, (1 << 2))
        elif mode == DAPAccess.PORT.JTAG:
            self.link.write_reg(DP_REG['CTRL_STAT'], CTRLSTAT_STICKYERR)
        else:
            assert False

