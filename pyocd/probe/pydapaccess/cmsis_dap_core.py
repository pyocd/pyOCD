# pyOCD debugger
# Copyright (c) 2006-2013,2018-2019 Arm Limited
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

import array
from .dap_access_api import DAPAccessIntf

class Command:
    DAP_INFO = 0x00
    DAP_LED = 0x01
    DAP_CONNECT = 0x02
    DAP_DISCONNECT = 0x03
    DAP_TRANSFER_CONFIGURE = 0x04
    DAP_TRANSFER = 0x05
    DAP_TRANSFER_BLOCK = 0x06
    DAP_TRANSFER_ABORT = 0x07
    DAP_WRITE_ABORT = 0x08
    DAP_DELAY = 0x09
    DAP_RESET_TARGET = 0x0a
    DAP_SWJ_PINS = 0x10
    DAP_SWJ_CLOCK = 0x11
    DAP_SWJ_SEQUENCE = 0x12
    DAP_SWD_CONFIGURE = 0x13
    DAP_JTAG_SEQUENCE = 0x14
    DAP_JTAG_CONFIGURE = 0x15
    DAP_JTAG_IDCODE = 0x16
    DAP_SWO_TRANSPORT = 0x17
    DAP_SWO_MODE = 0x18
    DAP_SWO_BAUDRATE = 0x19
    DAP_SWO_CONTROL = 0x1A
    DAP_SWO_STATUS = 0x1B
    DAP_SWO_DATA = 0x1C
    DAP_SWD_SEQUENCE = 0x1D
    DAP_SWO_EXTENDED_STATUS = 0x1E
    DAP_QUEUE_COMMANDS = 0x7E
    DAP_EXECUTE_COMMANDS = 0x7F
    DAP_VENDOR0 = 0x80 # Start of vendor-specific command IDs.

class Capabilities:
    SWD = 0x01
    JTAG = 0x02
    SWO_UART = 0x04
    SWO_MANCHESTER = 0x08
    ATOMIC_COMMANDS = 0x10
    DAP_SWD_SEQUENCE = 0x20

class Pin:
    NONE = 0x00 # Used to read current pin values without changing.
    SWCLK_TCK = (1 << 0)
    SWDIO_TMS = (1 << 1)
    TDI = (1 << 2)
    TDO = (1 << 3)
    nTRST = (1 << 5)
    nRESET = (1 << 7)

# Info IDs that return integer values.
INTEGER_INFOS = [
    DAPAccessIntf.ID.CAPABILITIES,
    DAPAccessIntf.ID.SWO_BUFFER_SIZE,
    DAPAccessIntf.ID.MAX_PACKET_COUNT,
    DAPAccessIntf.ID.MAX_PACKET_SIZE
    ]

DAP_DEFAULT_PORT = 0
DAP_SWD_PORT = 1
DAP_JTAG_PORT = 2

DAP_LED_CONNECT = 0
DAP_LED_RUNNING = 1

# Options for DAP_SWO_TRANSPORT command.
class DAPSWOTransport:
    NONE = 0
    DAP_SWO_DATA = 1
    DAP_SWO_EP = 2

# SWO mode options.
class DAPSWOMode:
    OFF = 0
    UART = 1
    MANCHESTER = 2

# SWO control acions.
class DAPSWOControl:
    STOP = 0
    START = 1

# SWO status masks.
class DAPSWOStatus:
    CAPTURE = 0x01
    ERROR = 0x40
    OVERRUN = 0x80

DAP_OK = 0
DAP_ERROR = 0xff

class DAPTransferResponse:
    """! Responses to DAP_Transfer and DAP_TransferBlock"""
    ACK_MASK = 0x07 # Bits [2:0]
    PROTOCOL_ERROR_MASK = 0x08 # Bit [3]
    VALUE_MISMATCH_MASK = 0x08 # Bit [4]
    
    # Values for ACK bitfield.
    ACK_OK = 1
    ACK_WAIT = 2
    ACK_FAULT = 4
    ACK_NO_ACK = 7

class CMSISDAPProtocol(object):
    """! @brief This class implements the CMSIS-DAP wire protocol."""

    def __init__(self, interface):
        self.interface = interface

    def dap_info(self, id_):
        assert type(id_) is DAPAccessIntf.ID
            
        cmd = []
        cmd.append(Command.DAP_INFO)
        cmd.append(id_.value)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_INFO:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] == 0:
            return

        # Integer values
        if id_ in INTEGER_INFOS:
            if resp[1] == 1:
                return resp[2]
            if resp[1] == 2:
                return (resp[3] << 8) | resp[2]
            if resp[1] == 4:
                return (resp[5] << 24) | (resp[4] << 16) | (resp[3] << 8) | resp[2]

        # String values. They are sent as C strings with a terminating null char, so we strip it out.
        return bytearray(resp[2:2 + resp[1] - 1]).decode('ascii')

    def set_led(self, type, enabled):
        cmd = []
        cmd.append(Command.DAP_LED)
        cmd.append(type)
        cmd.append(int(enabled))
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_LED:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != 0:
            # Second response byte must be 0
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def connect(self, mode=DAP_DEFAULT_PORT):
        cmd = []
        cmd.append(Command.DAP_CONNECT)
        cmd.append(mode)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_CONNECT:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] == 0:
            # DAP connect failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def disconnect(self):
        cmd = []
        cmd.append(Command.DAP_DISCONNECT)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_DISCONNECT:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP Disconnect failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def write_abort(self, data, dap_index=0):
        cmd = []
        cmd.append(Command.DAP_WRITE_ABORT)
        cmd.append(dap_index)
        cmd.append((data >> 0) & 0xff)
        cmd.append((data >> 8) & 0xff)
        cmd.append((data >> 16) & 0xff)
        cmd.append((data >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_WRITE_ABORT:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP Write Abort failed
            raise DAPAccessIntf.CommandError()

        return True

    def reset_target(self):
        cmd = []
        cmd.append(Command.DAP_RESET_TARGET)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_RESET_TARGET:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP Reset target failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def transfer_configure(self, idle_cycles=0x00, wait_retry=0x0050, match_retry=0x0000):
        cmd = []
        cmd.append(Command.DAP_TRANSFER_CONFIGURE)
        cmd.append(idle_cycles)
        cmd.append(wait_retry & 0xff)
        cmd.append(wait_retry >> 8)
        cmd.append(match_retry & 0xff)
        cmd.append(match_retry >> 8)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_TRANSFER_CONFIGURE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP Transfer Configure failed
            raise DAPAccessIntf.CommandError()

        return resp[1]


    def set_swj_clock(self, clock=1000000):
        cmd = []
        cmd.append(Command.DAP_SWJ_CLOCK)
        cmd.append(clock & 0xff)
        cmd.append((clock >> 8) & 0xff)
        cmd.append((clock >> 16) & 0xff)
        cmd.append((clock >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWJ_CLOCK:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP SWJ Clock failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def set_swj_pins(self, output, pins, wait=0):
        cmd = []
        cmd.append(Command.DAP_SWJ_PINS)
        cmd.append(output & 0xff)
        cmd.append(pins)
        cmd.append(wait & 0xff)
        cmd.append((wait >> 8) & 0xff)
        cmd.append((wait >> 16) & 0xff)
        cmd.append((wait >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWJ_PINS:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        return resp[1]

    def swd_configure(self, turnaround=1, always_send_data_phase=False):
        assert 1 <= turnaround <= 4
        conf = (turnaround - 1) | (int(always_send_data_phase) << 2)
    
        cmd = []
        cmd.append(Command.DAP_SWD_CONFIGURE)
        cmd.append(conf)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWD_CONFIGURE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP SWD Configure failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def swj_sequence(self, length, bits):
        assert 0 <= length <= 256
        cmd = []
        cmd.append(Command.DAP_SWJ_SEQUENCE)
        cmd.append(0 if (length == 256) else length)
        for i in range((length + 7) // 8):
            cmd.append(bits & 0xff)
            bits >>= 8
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWJ_SEQUENCE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP SWJ Sequence failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def jtag_sequence(self, cycles, tms, read_tdo, tdi):
        assert 0 <= cycles <= 64
        info = (((0 if (cycles == 64) else cycles) & 0x3f)
                | ((tms & 1) << 6)
                | (int(read_tdo) << 7))
        
        cmd = []
        cmd.append(Command.DAP_JTAG_SEQUENCE)
        cmd.append(1)
        cmd.append(info)
        for i in range((cycles + 7) // 8):
            cmd.append(tdi & 0xff)
            tdi >>= 8
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_JTAG_SEQUENCE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP JTAG Sequence failed
            raise DAPAccessIntf.CommandError()

        return resp[2]

    def jtag_configure(self, devices_irlen=None):
        # Default to a single device with an IRLEN of 4.
        if devices_irlen is None:
            devices_irlen = [4]
        
        cmd = []
        cmd.append(Command.DAP_JTAG_CONFIGURE)
        cmd.append(len(devices_irlen))
        for irlen in devices_irlen:
            cmd.append(irlen)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_JTAG_CONFIGURE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # DAP JTAG Configure failed
            raise DAPAccessIntf.CommandError()

        return resp[2:]

    def jtag_id_code(self, index=0):
        cmd = []
        cmd.append(Command.DAP_JTAG_IDCODE)
        cmd.append(index)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_JTAG_IDCODE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # Operation failed
            raise DAPAccessIntf.CommandError()

        return  (resp[2] << 0) | \
                (resp[3] << 8) | \
                (resp[4] << 16) | \
                (resp[5] << 24)

    def swo_transport(self, transport):
        cmd = []
        cmd.append(Command.DAP_SWO_TRANSPORT)
        cmd.append(transport)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWO_TRANSPORT:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # Operation failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def swo_mode(self, mode):
        cmd = []
        cmd.append(Command.DAP_SWO_MODE)
        cmd.append(mode)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWO_MODE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # Operation failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def swo_baudrate(self, baudrate):
        cmd = []
        cmd.append(Command.DAP_SWO_BAUDRATE)
        cmd.append(baudrate & 0xff)
        cmd.append((baudrate >> 8) & 0xff)
        cmd.append((baudrate >> 16) & 0xff)
        cmd.append((baudrate >> 24) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWO_BAUDRATE:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        return  (resp[1] << 0) | \
                (resp[2] << 8) | \
                (resp[3] << 16) | \
                (resp[4] << 24)

    def swo_control(self, action):
        cmd = []
        cmd.append(Command.DAP_SWO_CONTROL)
        cmd.append(action)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWO_CONTROL:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        if resp[1] != DAP_OK:
            # Operation failed
            raise DAPAccessIntf.CommandError()

        return resp[1]

    def swo_status(self):
        cmd = []
        cmd.append(Command.DAP_SWO_STATUS)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWO_STATUS:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        return (resp[1],
                    (resp[2] << 0) | \
                    (resp[3] << 8) | \
                    (resp[4] << 16) | \
                    (resp[5] << 24)
                )

    def swo_data(self, count):
        cmd = []
        cmd.append(Command.DAP_SWO_DATA)
        cmd.append(count & 0xff)
        cmd.append((count >> 8) & 0xff)
        self.interface.write(cmd)

        resp = self.interface.read()
        if resp[0] != Command.DAP_SWO_DATA:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        status = resp[1]
        count = (resp[2] << 0) | \
                    (resp[3] << 8)
        if count > 0:
            data = resp[4:]
        else:
            data = []
        return (status, count, data)

    def vendor(self, index, data):
        cmd = []
        cmd.append(Command.DAP_VENDOR0 + index)
        cmd.extend(data)
        self.interface.write(cmd)

        resp = self.interface.read()

        if resp[0] != Command.DAP_VENDOR0 + index:
            # Response is to a different command
            raise DAPAccessIntf.DeviceError()

        return resp[1:]
