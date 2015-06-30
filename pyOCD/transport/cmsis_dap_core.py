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

import logging
import array
from transport import TransferError

COMMAND_ID = {'DAP_INFO': 0x00,
              'DAP_LED': 0x01,
              'DAP_CONNECT': 0x02,
              'DAP_DISCONNECT': 0x03,
              'DAP_TRANSFER_CONFIGURE': 0x04,
              'DAP_TRANSFER': 0x05,
              'DAP_TRANSFER_BLOCK': 0x06,
              'DAP_TRANSFER_ABORT': 0x07,
              'DAP_WRITE_ABORT': 0x08,
              'DAP_DELAY': 0x09,
              'DAP_RESET_TARGET': 0x0a,
              'DAP_SWJ_PINS': 0x10,
              'DAP_SWJ_CLOCK': 0x11,
              'DAP_SWJ_SEQUENCE': 0x12,
              'DAP_SWD_CONFIGURE': 0x13,
              'DAP_JTAG_SEQUENCE': 0x14,
              'DAP_JTAG_CONFIGURE': 0x15,
              'DAP_JTAG_IDCODE': 0x16,
              'DAP_VENDOR0': 0x80,
              }

ID_INFO = {'VENDOR_ID': 0x01,
           'PRODUCT_ID': 0x02,
           'SERIAL_NUMBER': 0x03,
           'CMSIS_DAP_FW_VERSION': 0x04,
           'TARGET_DEVICE_VENDOR': 0x05,
           'TARGET_DEVICE_NAME': 0x06,
           'CAPABILITIES': 0xf0,
           'PACKET_COUNT': 0xfe,
           'PACKET_SIZE': 0xff
           }

PINS = {'None': 0x00,
        'SWCLK_TCK': (1 << 0),
        'SWDIO_TMS': (1 << 1),
        'TDI': (1 << 2),
        'TDO': (1 << 3),
        'nTRST': (1 << 5),
        'nRESET': (1 << 7),
        }

DAP_DEFAULT_PORT = 0
DAP_SWD_PORT = 1
DAP_JTAG_POR = 2

DAP_OK = 0
DAP_ERROR = 0xff

# Responses to DAP_Transfer and DAP_TransferBlock
DAP_TRANSFER_OK = 1
DAP_TRANSFER_WAIT = 2
DAP_TRANSFER_FAULT = 4

MAX_PACKET_SIZE = 0x0E

## @brief This class implements the CMSIS-DAP wire protocol.
class CMSIS_DAP_Protocol(object):
    def __init__(self, interface):
        self.interface = interface

    def dapInfo(self, id_):
        cmd = []
        cmd.append(COMMAND_ID['DAP_INFO'])
        cmd.append(ID_INFO[id_])
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_INFO']:
            raise ValueError('DAP_INFO response error')

        if resp[1] == 0:
            return

        # Integer values
        if id_ in ('CAPABILITIES', 'PACKET_COUNT', 'PACKET_SIZE'):
            if resp[1] == 1:
                return resp[2]
            if resp[1] == 2:
                return (resp[3] << 8) | resp[2]

        # String values
        x = array.array('B', [i for i in resp[2:2+resp[1]]])

        return x.tostring()

    def setLed(self):
        #not yet implemented
        return

    def connect(self, mode = DAP_DEFAULT_PORT):
        cmd = []
        cmd.append(COMMAND_ID['DAP_CONNECT'])
        cmd.append(mode)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_CONNECT']:
            raise ValueError('DAP_CONNECT response error')

        if resp[1] == 0:
            raise ValueError('DAP Connect failed')

        if resp[1] == 1:
            logging.info('DAP SWD MODE initialised')

        if resp[1] == 2:
            logging.info('DAP JTAG MODE initialised')

        return resp[1]

    def disconnect(self):
        cmd = []
        cmd.append(COMMAND_ID['DAP_DISCONNECT'])
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_DISCONNECT']:
            raise ValueError('DAP_DISCONNECT response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP Disconnect failed')

        return resp[1]

    def writeAbort(self, data, dap_index = 0):
        cmd = []
        cmd.append(COMMAND_ID['DAP_WRITE_ABORT'])
        cmd.append(dap_index)
        cmd.append((data >> 0) & 0xff)
        cmd.append((data >> 8) & 0xff)
        cmd.append((data >> 16) & 0xff)
        cmd.append((data >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_WRITE_ABORT']:
            raise ValueError('DAP_WRITE_ABORT response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP Write Abort failed')

        return True

    def resetTarget(self):
        cmd = []
        cmd.append(COMMAND_ID['DAP_RESET_TARGET'])
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_RESET_TARGET']:
            raise ValueError('DAP_RESET_TARGET response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP Reset target failed')

        return resp[1]

    def transferConfigure(self, idle_cycles = 0x00, wait_retry = 0x0050, match_retry = 0x0000):
        cmd = []
        cmd.append(COMMAND_ID['DAP_TRANSFER_CONFIGURE'])
        cmd.append(idle_cycles)
        cmd.append(wait_retry & 0xff)
        cmd.append(wait_retry >> 8)
        cmd.append(match_retry & 0xff)
        cmd.append(match_retry >> 8)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_TRANSFER_CONFIGURE']:
            raise ValueError('DAP_TRANSFER_CONFIGURE response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP Transfer Configure failed')

        return resp[1]

    def transfer(self, count, request, data = [0], dap_index = 0):
        cmd = []
        cmd.append(COMMAND_ID['DAP_TRANSFER'])
        cmd.append(dap_index)
        cmd.append(count)
        count_write = count
        for i in range(count):
            cmd.append(request[i])
            if not ( request[i] & ((1 << 1) | (1 << 4))):
                cmd.append(data[i] & 0xff)
                cmd.append((data[i] >> 8) & 0xff)
                cmd.append((data[i] >> 16) & 0xff)
                cmd.append((data[i] >> 24) & 0xff)
                count_write -= 1
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_TRANSFER']:
            raise ValueError('DAP_TRANSFER response error')

        if resp[2] != DAP_TRANSFER_OK:
            if resp[2] == DAP_TRANSFER_FAULT:
                raise TransferError()
            raise ValueError('SWD Fault')

        # Check for count mismatch after checking for DAP_TRANSFER_FAULT
        # This allows TransferError to get thrown instead of ValueError
        if resp[1] != count:
            raise ValueError('Transfer not completed')

        return resp[3:3+count_write*4]

    def transferBlock(self, count, request, data = [0], dap_index = 0):
        packet_count = count
        max_pending_reads = self.interface.getPacketCount()
        reads_pending = 0
        nb = 0
        resp = []
        error_transfer = False
        error_response = False

        # we send successfully several packets if the size is bigger than MAX_PACKET_COUNT
        while packet_count > 0 or reads_pending > 0:
            # Make sure the transmit buffer stays saturated
            while packet_count > 0 and reads_pending < max_pending_reads:
                cmd = []
                cmd.append(COMMAND_ID['DAP_TRANSFER_BLOCK'])
                cmd.append(dap_index)
                packet_written = min(packet_count, MAX_PACKET_SIZE)
                cmd.append(packet_written & 0xff)
                cmd.append((packet_written >> 8) & 0xff)
                cmd.append(request)
                if not (request & ((1 << 1))):
                    for i in range(packet_written):
                        cmd.append(data[i + nb*MAX_PACKET_SIZE] & 0xff)
                        cmd.append((data[i + nb*MAX_PACKET_SIZE] >> 8) & 0xff)
                        cmd.append((data[i + nb*MAX_PACKET_SIZE] >> 16) & 0xff)
                        cmd.append((data[i + nb*MAX_PACKET_SIZE] >> 24) & 0xff)
                self.interface.write(cmd)
                packet_count = packet_count - MAX_PACKET_SIZE
                nb = nb + 1
                reads_pending = reads_pending + 1

            # Read data
            if reads_pending > 0:
                # we then read
                tmp = self.interface.read()
                if tmp[0] != COMMAND_ID['DAP_TRANSFER_BLOCK']:
                    # Error occurred - abort further writes
                    # but make sure to finish reading remaining packets
                    packet_count = 0
                    error_response = True

                if tmp[3] != DAP_TRANSFER_OK:
                    # Error occurred - abort further writes
                    # but make sure to finish reading remaining packets
                    packet_count = 0
                    if tmp[3] == DAP_TRANSFER_FAULT:
                        error_transfer = True
                    else:
                        error_response = True

                size_transfer = tmp[1] | (tmp[2] << 8)
                resp.extend(tmp[4:4+size_transfer*4])
                reads_pending = reads_pending - 1

        # Raise pending errors
        if error_response:
            raise ValueError('DAP_TRANSFER_BLOCK response error')
        elif error_transfer:
            raise TransferError()

        return resp

    def setSWJClock(self, clock = 1000000):
        cmd = []
        cmd.append(COMMAND_ID['DAP_SWJ_CLOCK'])
        cmd.append(clock & 0xff)
        cmd.append((clock >> 8) & 0xff)
        cmd.append((clock >> 16) & 0xff)
        cmd.append((clock >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_SWJ_CLOCK']:
                raise ValueError('DAP_SWJ_CLOCK response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP SWJ Clock failed')

        return resp[1]

    def setSWJPins(self, output, pin, wait = 0):
        cmd = []
        cmd.append(COMMAND_ID['DAP_SWJ_PINS'])
        try:
            p = PINS[pin]
        except KeyError:
                logging.error('cannot find %s pin', pin)
                return
        cmd.append(output & 0xff)
        cmd.append(p)
        cmd.append(wait & 0xff)
        cmd.append((wait >> 8) & 0xff)
        cmd.append((wait >> 16) & 0xff)
        cmd.append((wait >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_SWJ_PINS']:
                raise ValueError('DAP_SWJ_PINS response error')

        return resp[1]

    def swdConfigure(self, conf = 0):
        cmd = []
        cmd.append(COMMAND_ID['DAP_SWD_CONFIGURE'])
        cmd.append(conf)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_SWD_CONFIGURE']:
                raise ValueError('DAP_SWD_CONFIGURE response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP SWD Configure failed')

        return resp[1]

    def swjSequence(self, data):
        cmd = []
        cmd.append(COMMAND_ID['DAP_SWJ_SEQUENCE'])
        cmd.append(len(data)*8)
        for i in range(len(data)):
            cmd.append(data[i])
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_SWJ_SEQUENCE']:
                raise ValueError('DAP_SWJ_SEQUENCE response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP SWJ Sequence failed')

        return resp[1]

    def jtagSequence(self, info, tdi):
        cmd = []
        cmd.append(COMMAND_ID['DAP_JTAG_SEQUENCE'])
        cmd.append(1)
        cmd.append(info)
        cmd.append(tdi)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_JTAG_SEQUENCE']:
            raise ValueError('DAP_JTAG_SEQUENCE response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP JTAG Sequence failed')

        return resp[2]

    def jtagConfigure(self, irlen, dev_num = 1):
        cmd = []
        cmd.append(COMMAND_ID['DAP_JTAG_CONFIGURE'])
        cmd.append(dev_num)
        cmd.append(irlen)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_JTAG_CONFIGURE']:
            raise ValueError('DAP_JTAG_CONFIGURE response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP JTAG Configure failed')

        return resp[2:]

    def jtagIDCode(self, index = 0):
        cmd = []
        cmd.append(COMMAND_ID['DAP_JTAG_IDCODE'])
        cmd.append(index)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != COMMAND_ID['DAP_JTAG_IDCODE']:
            raise ValueError('DAP_JTAG_IDCODE response error')

        if resp[1] != DAP_OK:
            raise ValueError('DAP JTAG ID code failed')

        return  (resp[2] << 0)  | \
                (resp[3] << 8)  | \
                (resp[4] << 16) | \
                (resp[5] << 24)

    def vendor(self, index):
        cmd = []
        cmd.append(COMMAND_ID['DAP_VENDOR0'] + index)
        self.interface.write(cmd)

        resp = self.interface.read()

        if resp[0] != COMMAND_ID['DAP_VENDOR0'] + index:
            raise ValueError('DAP_VENDOR response error')
