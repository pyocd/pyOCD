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

from cmsis_dap_core import CMSIS_DAP_Protocol
from transport import Transport, TransferError, READ_START, READ_NOW, READ_END
import logging
from time import sleep

# !! This value are A[2:3] and not A[3:2]
DP_REG = {'IDCODE' : 0x00,
          'ABORT' : 0x00,
          'CTRL_STAT': 0x04,
          'SELECT': 0x08
          }
AP_REG = {'CSW' : 0x00,
          'TAR' : 0x04,
          'DRW' : 0x0C,
          'IDR' : 0xFC
          }

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

CSW_VALUE  = (CSW_RESERVED | CSW_MSTRDBG | CSW_HPROT | CSW_DBGSTAT | CSW_SADDRINC)

TRANSFER_SIZE = {8: CSW_SIZE8,
                 16: CSW_SIZE16,
                 32: CSW_SIZE32
                 }

# Response values to DAP_Connect command
DAP_MODE_SWD = 1
DAP_MODE_JTAG = 2

# DP Control / Status Register bit definitions
CTRLSTAT_STICKYORUN = 0x00000002
CTRLSTAT_STICKYCMP = 0x00000010
CTRLSTAT_STICKYERR = 0x00000020

COMMANDS_PER_DAP_TRANSFER = 12

class CMSIS_DAP(Transport):
    """
    This class implements the CMSIS-DAP protocol
    """
    def __init__(self, interface):
        super(CMSIS_DAP, self).__init__(interface)
        self.protocol = CMSIS_DAP_Protocol(interface)
        self.packet_max_count = 0
        self.packet_max_size = 0
        self.csw = -1
        self.dp_select = -1
        self.deferred_transfer = False
        self.request_list = []
        self.data_list = []
        self.data_read_list = []

    def init(self, frequency = 1000000):
        # Flush to be safe
        self.flush()
        # connect to DAP, check for SWD or JTAG
        self.mode = self.protocol.connect()
        # set clock frequency
        self.protocol.setSWJClock(frequency)
        # configure transfer
        self.protocol.transferConfigure()
        if (self.mode == DAP_MODE_SWD):
            # configure swd protocol
            self.protocol.swdConfigure()
            # switch from jtag to swd
            self.JTAG2SWD()
            # read ID code
            logging.info('IDCODE: 0x%X', self.readDP(DP_REG['IDCODE']))
            # clear errors
            self.protocol.writeAbort(0x1e);
        elif (self.mode == DAP_MODE_JTAG):
            # configure jtag protocol
            self.protocol.jtagConfigure(4)
            # Test logic reset, run test idle
            self.protocol.swjSequence([0x1F])
            # read ID code
            logging.info('IDCODE: 0x%X', self.protocol.jtagIDCode())
            # clear errors
            self.writeDP(DP_REG['CTRL_STAT'], CTRLSTAT_STICKYERR | CTRLSTAT_STICKYCMP | CTRLSTAT_STICKYORUN)
        return

    def uninit(self):
        self.flush()
        self.protocol.disconnect()
        return

    def JTAG2SWD(self):
        data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        self.protocol.swjSequence(data)

        data = [0x9e, 0xe7]
        self.protocol.swjSequence(data)

        data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        self.protocol.swjSequence(data)

        data = [0x00]
        self.protocol.swjSequence(data)

    def info(self, request):
        self.flush()
        resp = None
        try:
            resp = self.protocol.dapInfo(request)
        except KeyError:
            logging.error('request %s not supported', request)
        return resp

    def clearStickyErr(self):
        if (self.mode == DAP_MODE_SWD):
            self.writeDP(0x0, (1 << 2))
        elif (self.mode == DAP_MODE_JTAG):
            self.writeDP(DP_REG['CTRL_STAT'], CTRLSTAT_STICKYERR)

    def writeMem(self, addr, data, transfer_size = 32):
        self.writeAP(AP_REG['CSW'], CSW_VALUE | TRANSFER_SIZE[transfer_size])

        if transfer_size == 8:
            data = data << ((addr & 0x03) << 3)
        elif transfer_size == 16:
            data = data << ((addr & 0x02) << 3)

        self._write(WRITE | AP_ACC | AP_REG['TAR'], addr)
        self._write(WRITE | AP_ACC | AP_REG['DRW'], data)

        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()

    def readMem(self, addr, transfer_size = 32, mode = READ_NOW):
        res = None
        if mode in (READ_START, READ_NOW):
            self.writeAP(AP_REG['CSW'], CSW_VALUE | TRANSFER_SIZE[transfer_size])
            self._write(WRITE | AP_ACC | AP_REG['TAR'], addr)
            self._write(READ | AP_ACC | AP_REG['DRW'])

        if mode in (READ_NOW, READ_END):
            resp = self._read()
            res =   (resp[0] << 0)  | \
                    (resp[1] << 8)  | \
                    (resp[2] << 16) | \
                    (resp[3] << 24)

            # All READ_STARTs must have been finished with READ_END before using READ_NOW
            assert (mode != READ_NOW) or (len(self.data_read_list) == 0)

            if transfer_size == 8:
                res = (res >> ((addr & 0x03) << 3) & 0xff)
            elif transfer_size == 16:
                res = (res >> ((addr & 0x02) << 3) & 0xffff)

        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()
        return res

    # write aligned word ("data" are words)
    def writeBlock32(self, addr, data):
        # put address in TAR
        self.writeAP(AP_REG['CSW'], CSW_VALUE | CSW_SIZE32)
        self.writeAP(AP_REG['TAR'], addr)
        try:
            self._transferBlock(len(data), WRITE | AP_ACC | AP_REG['DRW'], data)
        except TransferError:
            self.clearStickyErr()
            raise
        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()

    # read aligned word (the size is in words)
    def readBlock32(self, addr, size):
        # put address in TAR
        self.writeAP(AP_REG['CSW'], CSW_VALUE | CSW_SIZE32)
        self.writeAP(AP_REG['TAR'], addr)
        data = []
        try:
            resp = self._transferBlock(size, READ | AP_ACC | AP_REG['DRW'])
        except TransferError:
            self.clearStickyErr()
            raise
        for i in range(len(resp)/4):
            data.append( (resp[i*4 + 0] << 0)   | \
                         (resp[i*4 + 1] << 8)   | \
                         (resp[i*4 + 2] << 16)  | \
                         (resp[i*4 + 3] << 24))
        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()
        return data


    def readDP(self, addr, mode = READ_NOW):
        res = None
        if mode in (READ_START, READ_NOW):
            self._write(READ | DP_ACC | (addr & 0x0c))

        if mode in (READ_NOW, READ_END):
            resp = self._read()
            res =   (resp[0] << 0)  | \
                    (resp[1] << 8)  | \
                    (resp[2] << 16) | \
                    (resp[3] << 24)

            # All READ_STARTs must have been finished with READ_END before using READ_NOW
            assert (mode != READ_NOW) or (len(self.data_read_list) == 0)

        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()
        return res

    def writeDP(self, addr, data):
        if addr == DP_REG['SELECT']:
            if data == self.dp_select:
                return
            self.dp_select = data

        self._write(WRITE | DP_ACC | (addr & 0x0c), data)

        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()
        return True

    def writeAP(self, addr, data):
        ap_sel = addr & 0xff000000
        bank_sel = addr & APBANKSEL
        self.writeDP(DP_REG['SELECT'], ap_sel | bank_sel)

        if addr == AP_REG['CSW']:
            if data == self.csw:
                return
            self.csw = data

        self._write(WRITE | AP_ACC | (addr & 0x0c), data)
        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()

        return True

    def readAP(self, addr, mode = READ_NOW):
        res = None
        if mode in (READ_START, READ_NOW):
            ap_sel = addr & 0xff000000
            bank_sel = addr & APBANKSEL

            self.writeDP(DP_REG['SELECT'], ap_sel | bank_sel)
            self._write(READ | AP_ACC | (addr & 0x0c))

        if mode in (READ_NOW, READ_END):
            resp = self._read()
            res =   (resp[0] << 0)  | \
                    (resp[1] << 8)  | \
                    (resp[2] << 16) | \
                    (resp[3] << 24)

            # All READ_STARTs must have been finished with READ_END before using READ_NOW
            assert (mode != READ_NOW) or (len(self.data_read_list) == 0)

        # If not in deferred mode flush after calls to _read or _write
        if not self.deferred_transfer:
            self.flush()

        return res

    def reset(self):
        self.flush()
        self.protocol.setSWJPins(0, 'nRESET')
        sleep(0.1)
        self.protocol.setSWJPins(0x80, 'nRESET')
        sleep(0.1)

    def assertReset(self, asserted):
        self.flush()
        if asserted:
            self.protocol.setSWJPins(0, 'nRESET')
        else:
            self.protocol.setSWJPins(0x80, 'nRESET')

    def setClock(self, frequency):
        self.flush()
        self.protocol.setSWJClock(frequency)

    def setDeferredTransfer(self, enable):
        """
        Allow transfers to be delayed and buffered

        By default deferred transfers are turned off.  All reads and
        writes will be completed by the time the function returns.

        When enabled packets are buffered and sent all at once, which
        increases speed.  When memory is written to, the transfer
        might take place immediately, or might take place on a future
        memory write.  This means that an invalid write could cause an
        exception to occur on a later, unrelated write.  To guarantee
        that previous writes are complete call the flush() function.

        The behaviour of read operations is determined by the modes
        READ_START, READ_NOW and READ_END.  The option READ_NOW is the
        default and will cause the read to flush all previous writes,
        and read the data immediately.  To improve performance, multiple
        reads can be made using READ_START and finished later with READ_NOW.
        This allows the reads to be buffered and sent at once.  Note - All
        READ_ENDs must be called before a call using READ_NOW can be made.
        """
        if self.deferred_transfer and not enable:
            self.flush()
        self.deferred_transfer = enable

    def flush(self):
        """
        Flush out all commands
        """
        transfer_count = len(self.request_list)
        if transfer_count > 0:
            assert transfer_count <= COMMANDS_PER_DAP_TRANSFER
            try:
                data = self.protocol.transfer(transfer_count, self.request_list, self.data_list)
                self.data_read_list.extend(data)
            except TransferError:
                # Dump any pending commands
                self.request_list = []
                self.data_list = []
                # Dump any data read
                self.data_read_list = []
                # Invalidate cached registers
                self.csw = -1
                self.dp_select = -1
                # Clear error
                self.clearStickyErr()
                raise
            self.request_list = []
            self.data_list = []

    def _write(self, request, data = 0):
        """
        Write a single command
        """
        self.request_list.append(request)
        self.data_list.append(data)
        transfer_count = len(self.request_list)
        if (transfer_count >= COMMANDS_PER_DAP_TRANSFER):
            self.flush()

    def _read(self):
        """
        Read the response from a single command
        """
        if len(self.data_read_list) < 4:
            self.flush()
        data = self.data_read_list[0:4]
        self.data_read_list = self.data_read_list[4:]
        return data

    def _transferBlock(self, count, request, data = [0]):
        self.flush()
        return self.protocol.transferBlock(count, request, data)
