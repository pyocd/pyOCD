# pyOCD debugger
# Copyright (c) 2006-2019 Arm Limited
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

import logging
import threading
import socket
import six
import queue

CTRL_C = b'\x03'

LOG = logging.getLogger(__name__)

TRACE_ACK = LOG.getChild("trace.ack")
TRACE_ACK.setLevel(logging.CRITICAL)

TRACE_PACKETS = LOG.getChild("trace.packet")
TRACE_PACKETS.setLevel(logging.CRITICAL)

def checksum(data):
    return ("%02x" % (sum(six.iterbytes(data)) % 256)).encode()

class ConnectionClosedException(Exception):
    """! @brief Exception used to signal the GDB server connection closed."""
    pass

class GDBServerPacketIOThread(threading.Thread):
    """! @brief Packet I/O thread.
    
    This class is a thread used by the GDBServer class to perform all RSP packet I/O. It
    handles verifying checksums, acking, and receiving Ctrl-C interrupts. There is a queue
    for received packets. The interface to this queue is the receive() method. The send()
    method writes outgoing packets to the socket immediately.
    """
    
    def __init__(self, abstract_socket):
        super(GDBServerPacketIOThread, self).__init__()
        self.name = "gdb-packet-thread-port%d" % abstract_socket.port
        self._abstract_socket = abstract_socket
        self._receive_queue = queue.Queue()
        self._shutdown_event = threading.Event()
        self.interrupt_event = threading.Event()
        self.send_acks = True
        self._clear_send_acks = False
        self._buffer = b''
        self._expecting_ack = False
        self.drop_reply = False
        self._last_packet = b''
        self._closed = False
        self.setDaemon(True)
        self.start()

    def set_send_acks(self, ack):
        if ack:
            self.send_acks = True
        else:
            self._clear_send_acks = True

    def stop(self):
        self._shutdown_event.set()

    def send(self, packet):
        if self._closed or not packet:
            return
        if not self.drop_reply:
            self._last_packet = packet
            self._write_packet(packet)
        else:
            self.drop_reply = False
            LOG.debug("GDB dropped reply %s", packet)

    def receive(self, block=True):
        if self._closed:
            raise ConnectionClosedException()
        while True:
            try:
                # If block is false, we'll get an Empty exception immediately if there
                # are no packets in the queue. Same if block is true and it times out
                # waiting on an empty queue.
                return self._receive_queue.get(block, 0.1)
            except queue.Empty:
                # Only exit the loop if block is false or connection closed.
                if not block:
                    return None
                if self._closed:
                    raise ConnectionClosedException()

    def run(self):
        LOG.debug("Starting GDB server packet I/O thread")

        self._abstract_socket.set_timeout(0.01)

        while not self._shutdown_event.is_set():
            try:
                data = self._abstract_socket.read()

                # Handle closed connection
                if len(data) == 0:
                    LOG.debug("GDB packet thread: other side closed connection")
                    self._closed = True
                    break

                TRACE_PACKETS.debug('-->>>> GDB read %d bytes: %s', len(data), data)

                self._buffer += data
            except socket.error:
                pass

            if self._shutdown_event.is_set():
                break

            self._process_data()

        LOG.debug("GDB packet thread stopping")

    def _write_packet(self, packet):
        TRACE_PACKETS.debug('--<<<< GDB send %d bytes: %s', len(packet), packet)

        # Make sure the entire packet is sent.
        remaining = len(packet)
        while remaining:
            written = self._abstract_socket.write(packet)
            remaining -= written
            if remaining:
                packet = packet[written:]

        if self.send_acks:
            self._expecting_ack = True

    def _check_expected_ack(self):
        # Handle expected ack.
        c = self._buffer[0:1]
        if c in (b'+', b'-'):
            self._buffer = self._buffer[1:]
            TRACE_ACK.debug('got ack: %s', c)
            if c == b'-':
                # Handle nack from gdb
                self._write_packet(self._last_packet)
                return

            # Handle disabling of acks.
            if self._clear_send_acks:
                self.send_acks = False
                self._clear_send_acks = False
        else:
            LOG.debug("GDB: expected n/ack but got '%s'", c)

    def _process_data(self):
        """! @brief Process all incoming data until there are no more complete packets."""
        while len(self._buffer):
            if self._expecting_ack:
                self._expecting_ack = False
                self._check_expected_ack()

            # Check for a ctrl-c.
            if len(self._buffer) and self._buffer[0:1] == CTRL_C:
                self.interrupt_event.set()
                self._buffer = self._buffer[1:]

            try:
                # Look for complete packet and extract from buffer.
                pkt_begin = self._buffer.index(b"$")
                pkt_end = self._buffer.index(b"#") + 2
                if pkt_begin >= 0 and pkt_end < len(self._buffer):
                    pkt = self._buffer[pkt_begin:pkt_end + 1]
                    self._buffer = self._buffer[pkt_end + 1:]
                    self._handling_incoming_packet(pkt)
                else:
                    break
            except ValueError:
                # No complete packet received yet.
                break

    def _handling_incoming_packet(self, packet):
        # Compute checksum
        data, cksum = packet[1:].split(b'#')
        computedCksum = checksum(data)
        goodPacket = (computedCksum.lower() == cksum.lower())

        if self.send_acks:
            ack = b'+' if goodPacket else b'-'
            self._abstract_socket.write(ack)
            TRACE_ACK.debug(ack)

        if goodPacket:
            self._receive_queue.put(packet)

