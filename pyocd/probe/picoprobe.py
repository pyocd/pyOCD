# pyOCD debugger
# Copyright (c) 2021 Federico Zuccardi Merli
# Copyright (c) 2021 Chris Reed
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

from array import array

from time import sleep
from usb import core, util

import platform
import errno
import logging
from typing import List

from .debug_probe import DebugProbe
from .common import show_no_libusb_warning
from ..core import exceptions
from ..core.options import OptionInfo
from ..core.plugin import Plugin
from ..utility.mask import parity32_high

LOG = logging.getLogger(__name__)


class PicoLink(object):
    """! @brief Wrapper to handle picoprobe USB.

    Just to hide details of USB and Picoprobe command layer
    """

    CLASS = 0xFF    # Vendor Specific

    CMD_HDR_LEN = 6  # do not include pico packet header
    PKT_HDR_LEN = 4  # pico packet header
    HDR_LEN = PKT_HDR_LEN + CMD_HDR_LEN

    PROBE_INVALID = 0       # Invalid command
    PROBE_WRITE_BITS = 1    # Host wants us to write bits
    PROBE_READ_BITS = 2     # Host wants us to read bits
    PROBE_SET_FREQ = 3      # Set TCK
    PROBE_RESET = 4         # Reset all state: it's a no-op!
    PROBE_TARGET_RESET = 5  # Reset target (Hardware nreset)

    BUFFER_SIZE = 8192      # Size of buffers in the picoprobe

    def __init__(self, dev):
        self._dev = dev
        self._probe_id = dev.serial_number
        self._vend = dev.manufacturer
        self._prod = dev.product
        # USB interface and endpoints, will be assigned in open()
        self._if = None
        self._wr_ep = None
        self._rd_ep = None
        # Progressive command id
        self._id = 0
        # Probe command queue
        self._queue = array('B', (0, 0, 0, 0))
        self._qulen = self.PKT_HDR_LEN
        # Buffer for endpoint reads
        self._bits = array('B', (0 for _ in range(self.BUFFER_SIZE)))

    # ------------------------------------------- #
    #          Picoprobe Access functions
    # ------------------------------------------- #
    def open(self):
        # If we get here, the device should be accessible, and with a valid configuration
        # so, check for 'Picoprobeness'
        # Search the Vendor Specific interface in first configuration
        for i in self._dev[0]:
            if i.bInterfaceClass == PicoLink.CLASS:
                self._if = i
                break
        # Check for a missing device interface
        if self._if is None:
            raise exceptions.ProbeError()
        # Scan and assign Endpoints
        for e in self._if:
            if util.endpoint_direction(e.bEndpointAddress) == util.ENDPOINT_OUT:
                self._wr_ep = e
            else:
                self._rd_ep = e
        # Something is missing from this probe!
        if self._wr_ep is None or self._rd_ep is None:
            raise exceptions.ProbeError("Unrecognized Picoprobe interface")

    def close(self):
        self._if = None
        self._wr_ep = None
        self._rd_ep = None

    @classmethod
    def enumerate_picoprobes(cls, uid=None) -> List["PicoLink"]:
        """! @brief Find and return all Picoprobes """
        try:
            # Use a custom matcher to make sure the probe is a Picoprobe and accessible.
            return [PicoLink(probe) for probe in core.find(find_all=True, custom_match=FindPicoprobe(uid))]
        except core.NoBackendError:
            show_no_libusb_warning()
            return []

    def q_read_bits(self, bits):
        """! @brief Queue a read request for 'bits' bits to the probe """
        # Cannot be called with bits = 0
        self._queue_cmd_header(self.PROBE_READ_BITS, bits)

    def q_write_bits(self, data, bits=None):
        """! @brief Queue a write reeust 'bits' bits.
        @param data Values to be weritten. Either int or iterable yielding bytes (0-255).
        @param bits How many bits to write. Mandatory if data is int.
        """
        if bits is None:
            bits = 8 * len(data)  # will raise TypeError if data is int
        count = (bits + 7) // 8
        self._queue_cmd_header(self.PROBE_WRITE_BITS, bits, count)
        self._queue.extend(data if type(data) is not int else data.to_bytes(count, 'little'))

    def flush_queue(self):
        """! @brief Execute all the queued probe actions"""
        # Put in the packet header (byte count)
        self._queue[:self.PKT_HDR_LEN] = array(
            'B', self._qulen.to_bytes(4, 'little'))
        try:
            self._wr_ep.write(self._queue)
        except:
            # Anything from the USB layer assumes probe is no longer connected
            raise exceptions.ProbeDisconnected(
                'Cannot access probe ' + self._probe_id)
        finally:
            # Make sure there are no leftovers
            self._clear_queue()

    def get_bits(self):
        """! @briefExecute all the queued probe actions and return read values"""
        self.flush_queue()
        try:
            # A single read is enough, as the 8 kB buffer in the Picoprobe can
            # contain about 454 ACKs+Register reads, and I never queue more than 256
            received = self._rd_ep.read(self._bits)
        except Exception:
            # Anything from the USB layer assumes probe is no longer connected
            raise exceptions.ProbeDisconnected(
                'Cannot access probe ' + self._probe_id)

        # Check for correct length of received data
        remaining = int.from_bytes(self._bits[:self.PKT_HDR_LEN], 'little')
        if remaining != received:
            # Something went wrong, wrong number of bytes received
            raise exceptions.ProbeError(
                'Mismatched header from %s: expected %d, received %d' % (self._probe_id, remaining, received))

        remaining -= self.PKT_HDR_LEN
        offset = self.PKT_HDR_LEN
        result = []
        # Loop over the received data, creating a list of ints
        while remaining > 0:
            # Check for a real read header
            if self._bits[offset+1] != self.PROBE_READ_BITS:
                # Something went wrong: wrong command in received header
                # Possible sign we are misaligned
                raise exceptions.ProbeError('Wrong header received from %s')
            # Get the bytes count for the operation
            # The receiver must know how many bits they are interested in!
            count = (int.from_bytes(self._bits[offset + 2:offset + 6], 'little') + 7) // 8
            offset += self.CMD_HDR_LEN
            result.append(int.from_bytes(self._bits[offset:offset + count], 'little'))
            offset += count
            remaining -= self.CMD_HDR_LEN + count
        return result

    def set_swd_frequency(self, f):
        self.start_queue()
        # Write a packet with SET_FREQ and the new value, bypass the queue
        self._queue_cmd_header(self.PROBE_SET_FREQ, f)
        self.flush_queue()

    def assert_target_reset(self, state):
        self.start_queue()
        # Write a packet with PROBE_TARGET_RESET and the reset pin state
        self._queue_cmd_header(self.PROBE_TARGET_RESET, state)
        self.flush_queue()

    def get_unique_id(self):
        return self._probe_id

    @property
    def vendor_name(self):
        return self._vend

    @property
    def product_name(self):
        return self._prod

    # ------------------------------------------- #
    #          Picoprobe intenal functions
    # ------------------------------------------- #
    def _next_id(self):
        """! @brief Returns a progressive id for a Picoprobe command"""
        id = self._id
        self._id = (self._id + 1) % 0x100
        return id

    def _queue_cmd_header(self, cmd, bits, length=0, id=None):
        """! @brief Prepare a header structure in _queue byte array"""
        if id is None:
            id = self._next_id()
        length += self.CMD_HDR_LEN
        # update packet header, packet is for sure shorter than 64
        self._qulen += length
        self._queue.extend((id, cmd))
        self._queue.extend(bits.to_bytes(4, 'little'))

    def _clear_queue(self):
        # Empty send queue and reset packet header
        del self._queue[self.PKT_HDR_LEN:]
        self._qulen = self.PKT_HDR_LEN

    def start_queue(self):
        # Might not need anything else.
        self._clear_queue()


class FindPicoprobe(object):
    """! @brief Custom matcher for Picoprobe to be used in core.find() """

    VID_PID_CLASS = (0x2E8A, 0x0004, 0x00)  # Match for a Picoprobe

    def __init__(self, serial=None):
        """! @brief Create a new FindPicoprobe object with an optional serial number"""
        self._serial = serial

    def __call__(self, dev):
        """! @brief Return True if this is a Picoprobe device, False otherwise"""

        # Check if vid, pid and the device class are valid ones for Picoprobe.
        if (dev.idVendor, dev.idProduct, dev.bDeviceClass) != self.VID_PID_CLASS:
            return False

        # Make sure the device has an active configuration
        try:
            # This can fail on Linux if the configuration is already active.
            dev.set_configuration()
        except Exception:
            # But do no act on possible errors, they'll be caught in the next try: clause
            pass

        try:
            # This raises when no configuration is set
            dev.get_active_configuration()

            # Now read the serial. This will raise if there are access problems.
            serial = dev.serial_number

        except core.USBError as error:
            if error.errno == errno.EACCES and platform.system() == "Linux":
                msg = ("%s while trying to interrogate a USB device "
                       "(VID=%04x PID=%04x). This can probably be remedied with a udev rule. "
                       "See <https://github.com/pyocd/pyOCD/tree/master/udev> for help." %
                       (error, dev.idVendor, dev.idProduct))
                LOG.warning(msg)
            else:
                LOG.warning("Error accessing USB device (VID=%04x PID=%04x): %s",
                            dev.idVendor, dev.idProduct, error)
            return False
        except (IndexError, NotImplementedError, ValueError, UnicodeDecodeError) as error:
            LOG.debug("Error accessing USB device (VID=%04x PID=%04x): %s",
                      dev.idVendor, dev.idProduct, error)
            return False

        # Check the passed serial number
        if self._serial is not None:
            # Picoprobe serial will be "123456" (older FW) or an actual unique serial from the flash.
            if self._serial == "" and serial is None:
                return True
            if self._serial != serial:
                return False
        return True


class Picoprobe(DebugProbe):
    """! @brief Wraps a Picolink link as a DebugProbe. """

    # Address of read buffer register in DP.
    RDBUFF = 0xC

    # Bitmasks for AP/DP register address field.
    A32 = 0x0000000c

    # SWD command format
    SWD_CMD_START = (1 << 0)    # always set
    SWD_CMD_APnDP = (1 << 1)    # set only for AP access
    SWD_CMD_RnW = (1 << 2)      # set only for read access
    SWD_CMD_A32 = (3 << 3)      # bits A[3:2] of register addr
    SWD_CMD_PARITY = (1 << 5)   # parity of APnDP|RnW|A32
    SWD_CMD_STOP = (0 << 6)     # always clear for synch SWD
    SWD_CMD_PARK = (1 << 7)     # driven high by host

    # APnDP constants.
    DP = 0
    AP = 1

    # Read and write constants.
    READ = 1
    WRITE = 0

    # ACK values
    ACK_OK = 0b001
    ACK_WAIT = 0b010
    ACK_FAULT = 0b100
    ACK_ALL = ACK_FAULT | ACK_WAIT | ACK_OK

    ACK_EXCEPTIONS = {
        ACK_OK: None,
        ACK_WAIT: exceptions.TransferTimeoutError("Picoprobe: ACK WAIT received"),
        ACK_FAULT: exceptions.TransferFaultError("Picoprobe: ACK FAULT received"),
        ACK_ALL: exceptions.TransferError("Picoprobe: Protocol fault"),
    }

    SAFESWD_OPTION = 'picoprobe.safeswd'

    PARITY_BIT = 0x100000000

    @ classmethod
    def get_all_connected_probes(cls, unique_id=None, is_explicit=False):
        return [cls(dev) for dev in PicoLink.enumerate_picoprobes()]

    @ classmethod
    def get_probe_with_id(cls, unique_id, is_explicit=False):
        probes = PicoLink.enumerate_picoprobes(unique_id)
        if probes:
            return cls(probes[0])

    def __init__(self, picolink):
        super(Picoprobe, self).__init__()
        self._link = picolink
        self._is_connected = False
        self._is_open = False
        self._unique_id = self._link.get_unique_id()
        self._reset = False

    @ property
    def description(self):
        return self.vendor_name + " " + self.product_name

    @ property
    def vendor_name(self):
        return self._link.vendor_name

    @ property
    def product_name(self):
        return self._link.product_name

    @ property
    def supported_wire_protocols(self):
        return [DebugProbe.Protocol.DEFAULT, DebugProbe.Protocol.SWD]

    @ property
    def unique_id(self):
        return self._unique_id

    @ property
    def wire_protocol(self):
        """! @brief Only valid after connecting."""
        return DebugProbe.Protocol.SWD if self._is_connected else None

    @ property
    def is_open(self):
        return self._is_open

    @ property
    def capabilities(self):
        return {DebugProbe.Capability.SWJ_SEQUENCE, DebugProbe.Capability.SWD_SEQUENCE}

    def open(self):
        self._link.open()
        self._is_open = True

    def close(self):
        self._link.close()
        self._is_open = False

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        """! @brief Connect to the target via SWD."""
        # Make sure the protocol is supported
        if (protocol is None) or (protocol == DebugProbe.Protocol.DEFAULT):
            protocol = DebugProbe.Protocol.SWD

        # Validate selected protocol.
        if protocol != DebugProbe.Protocol.SWD:
            raise ValueError("unsupported wire protocol %s" % protocol)

        self._is_connected = True
        # Use the bulk or safe read and write functions according to option
        if self.session.options.get(self.SAFESWD_OPTION):
            self.read_ap_multiple = self._safe_read_ap_multiple
            self.write_ap_multiple = self._safe_write_ap_multiple
        else:
            self.read_ap_multiple = self._bulk_read_ap_multiple
            self.write_ap_multiple = self._bulk_write_ap_multiple
        # Subscribe to option change events
        self.session.options.subscribe(self._change_options, [self.SAFESWD_OPTION])
        # Do I need to do anything else here?
        # SWJ switch sequence is handled externally...

    def swj_sequence(self, length, bits):
        self._link.start_queue()
        self._link.q_write_bits(bits, length)
        self._link.flush_queue()

    def swd_sequence(self, sequences):
        """! @brief Send a sequences of bits on the SWDIO signal.

        Each sequence in the _sequences_ parameter is a tuple with 1 or 2 members in this order:
        - 0: int: number of TCK cycles from 1-64
        - 1: int: the SWDIO bit values to transfer. The presence of this tuple member indicates the sequence is
            an output sequence; the absence means that the specified number of TCK cycles of SWDIO data will be
            read and returned.

        @param self
        @param sequences A sequence of sequence description tuples as described above.

        @return A 2-tuple of the response status, and a sequence of bytes objects, one for each input
            sequence. The length of the bytes object is (<TCK-count> + 7) / 8. Bits are in LSB first order.
        """
        # Init leghts to pack and cmd queue
        reads_lengths = []
        self._link.start_queue()
        # Take each sequence 'seq' in sequences
        for seq in sequences:
            if len(seq) == 1:
                bits = seq[0]
                self._link.q_read_bits(bits)
                reads_lengths.append((bits + 7) // 8)
            elif len(seq) == 2:
                self._link.q_write_bits(seq[1], seq[0])
            else:
                # Ignore malformed entry, raise or return failure? Ignore for the moment.
                pass
        # Check if some read were queued
        if len(reads_lengths) == 0:
            # Just execute the queue
            self._link.flush_queue()
            return (0,)
        else:
            reads = self._link.get_bits()
            # Is there a status definition, no check in caller?
            return (0, [v.to_bytes(l, 'little') for v, l in zip(reads, reads_lengths)])

    def disconnect(self):
        self._is_connected = False

    def set_clock(self, frequency):
        self._link.set_swd_frequency(frequency // 1000)

    def reset(self):
        self.assert_reset(True)
        sleep(self.session.options.get('reset.hold_time'))
        self.assert_reset(False)
        sleep(self.session.options.get('reset.post_delay'))

    def assert_reset(self, asserted):
        self._link.assert_target_reset(asserted)
        self._reset = asserted

    def is_reset_asserted(self):
        # No support for reading back the current state
        return self._reset

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #
    def read_dp(self, addr, now=True):
        val = self._read_reg(addr, self.DP)

        # Return the result or the result callback for deferred reads
        def read_dp_result_callback():

            return val
        return val if now else read_dp_result_callback

    def write_dp(self, addr, value):
        self._write_reg(addr, self.DP, value)

    def read_ap(self, addr, now=True):
        (ret,) = self.read_ap_multiple(addr)

        def read_ap_cb():
            return ret
        return ret if now else read_ap_cb

    def write_ap(self, addr, value):
        self.write_ap_multiple(addr, (value,))

    def _safe_read_ap_multiple(self, addr, count=1, now=True):
        # Send a read request for the AP, discard the stale result
        self._read_reg(addr, self.AP)
        # Read count - 1 new values
        results = [self._read_reg(addr, self.AP) for n in range(count - 1)]
        # and read the last result from the RDBUFF register
        results.append(self.read_dp(self.RDBUFF))

        def read_ap_multiple_result_callback():
            return results

        return results if now else read_ap_multiple_result_callback

    def _safe_write_ap_multiple(self, addr, values):
        # Send repeated read request for the AP
        for v in values:
            self._write_reg(addr, self.AP, v)

    def _bulk_read_ap_multiple(self, addr, count=1, now=True):
        # Start queueing - queue a max of 256 AP reads not to exceed Picoprobe buffers
        # Theoretical maximum for the Picoprobe internal 8 kB buffer is ~454
        # Raising the chunk size brings no great benefit, though.
        reads = []
        while count > 0:
            chunk = 256 if count > 256 else count
            count -= chunk
            self._link.start_queue()

            # Queue reads for 1 old value plus count - 1 new values
            for _ in range(chunk):
                # Queue read command
                self._swd_command(self.READ, self.AP, addr)
                # Queue read value + parity + TrN
                self._link.q_read_bits(32 + 1 + 1)

            if count == 0:
                # Now queue final read from RDBUFF
                self._swd_command(self.READ, self.DP, self.RDBUFF)
                # Queue read value + parity + TrN
                self._link.q_read_bits(32 + 1 + 1)
                # Queue write 3 idle bits (enough?)
                self._link.q_write_bits(0, 3)

            # Run and collect all the reads in this chunk
            reads.extend(self._link.get_bits())

        # Check all the acks (including the one for discarded read!)
        self._check_swd_acks(reads[0::2])

        # Skip first read and zero parity if no errors
        results = [(v & 0x1FFFFFFFF) ^ parity32_high(v) for v in reads[3::2]]

        # Parity check
        if any(v & self.PARITY_BIT for v in results):
            raise exceptions.ProbeError('Bad parity in SWD read')

        def read_ap_multiple_result_callback():
            return results

        return results if now else read_ap_multiple_result_callback

    def _bulk_write_ap_multiple(self, addr, values):
        acks = []
        left = len(values)
        done = 0
        # Use 256 chunks. Max is about 340.
        while left > 0:
            chunk = 256 if left > 256 else left
            self._link.start_queue()
            for value in values[done:done+chunk]:
                # Queue write command
                self._swd_command(self.WRITE, self.AP, addr)
                # Prepare the write buffer
                value |= parity32_high(value)
                # Send the value: 32 (data) + 1 (parity) bits (no Trn needed)
                # Insert also 3 bits of idle
                self._link.q_write_bits(value, 32 + 1 + 3)
            left -= chunk
            done += chunk

            # Now collect all the ACK reads!
            acks.extend(self._link.get_bits())

        self._check_swd_acks(acks)

    # ------------------------------------------- #
    #          Internal implementation functions
    # ------------------------------------------- #

    def _read_reg(self, addr, APnDP):
        # This is a safe read
        self._link.start_queue()
        # Send a command with a read AP/DP request
        self._swd_command(self.READ, APnDP, addr)
        self._read_check_swd_ack()

        # Read + 32 (data) + 1 (parity) + 1 (Trn) bits
        self._link.q_read_bits(32 + 1 + 1)
        # insert idle
        self._link.q_write_bits(0, 3)

        reg = self._link.get_bits()[0]
        # Unpack the returned value
        val = reg & 0xFFFFFFFF
        # Remove the Trn bit
        par = reg & self.PARITY_BIT
        # Check for correct parity value
        if par != parity32_high(val):
            raise exceptions.ProbeError('Bad parity in SWD read')

        return val

    def _write_reg(self, addr, APnDP, value):
        # This is a safe write
        self._link.start_queue()
        # Send a command with a write AP/DP request
        self._swd_command(self.WRITE, APnDP, addr)
        self._read_check_swd_ack()

        # Prepare the write buffer
        value |= parity32_high(value)

        # Send the value: 32 (data) + 1 (parity) bits (no Trn needed)
        # Insert also 3 bits of idle
        self._link.q_write_bits(value, 32 + 1 + 3)
        self._link.flush_queue()

    def _swd_command(self, RnW, APnDP, addr):
        """! @brief Builds and queues an SWD command byte plus an ACK read"""
        cmd = (APnDP << 1) + (RnW << 2) + ((addr << 1) & self.SWD_CMD_A32)
        cmd |= parity32_high(cmd) >> (32 - 5)
        cmd |= self.SWD_CMD_START | self.SWD_CMD_STOP | self.SWD_CMD_PARK

        # Write the command to the probe
        self._link.q_write_bits(cmd, 8)
        # Queue also ACK reading, plus TrN if needed
        self._link.q_read_bits(1 + 3 + 1 - RnW)

    def _read_check_swd_ack(self):
        # Reads Trn + ACK, plus a following Trn bit if the cmd was a write
        ack = self._link.get_bits()
        self._check_swd_acks(ack)

    def _check_swd_acks(self, raw_acks):
        # Extract ACKs and collapse identical elements
        acks = set((ack >> 1) & self.ACK_ALL for ack in raw_acks)

        # Remove ACK OK only if present
        acks.difference_update({self.ACK_OK})

        # If there's something left, we had a problem.
        if len(acks) == 0:
            return
        else:
            try:
                # Raise the exception for the first problem found in set.
                e = self.ACK_EXCEPTIONS[acks.pop()]
            except KeyError:
                e = self.ACK_EXCEPTIONS[self.ACK_ALL]
            raise e

    def _change_options(self, notification):
        # Only this option, ATM
        if notification.event == self.SAFESWD_OPTION:
            if notification.data.new_value:
                self.read_ap_multiple = self._safe_read_ap_multiple
                self.write_ap_multiple = self._safe_write_ap_multiple
            else:
                self.read_ap_multiple = self._bulk_read_ap_multiple
                self.write_ap_multiple = self._bulk_write_ap_multiple


class PicoprobePlugin(Plugin):
    """! @brief Plugin class for Picoprobe."""

    def load(self):
        return Picoprobe

    @ property
    def name(self):
        return "picoprobe"

    @ property
    def description(self):
        return "Raspberry Pi Pico Probe"

    @ property
    def options(self):
        """! @brief Returns picoprobe options."""
        return [
            OptionInfo(Picoprobe.SAFESWD_OPTION, bool, False,
                       "Use safe but slower SWD transfer functions with Picoprobe.")]
