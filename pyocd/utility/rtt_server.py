# pyOCD debugger
# Copyright (c) 2022 Samuel Dewan
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

from abc import ABC, abstractmethod
import selectors
import socket
from typing import Optional, Sequence

from ..core.soc_target import SoCTarget
from ..core import exceptions
from ..debug.rtt import RTTControlBlock, RTTUpChannel, RTTDownChannel


class RTTChanWorker(ABC):
    """@brief Source and sink for data to be transferred over RTT. """

    @abstractmethod
    def write_up_data(self, data: bytes) -> int:
        """@brief Write data that has been received from an up channel to the
                  correct destination.

        @param data The data to be written.
        @return The number of bytes that were successfully written.
        """
        pass

    @abstractmethod
    def get_down_data(self) -> bytes:
        """@brief Get data that should be written to a down channel if there is
                  any.

        @return Data to be written to down channel.
        """
        pass

    @abstractmethod
    def close(self):
        """@brief Cleanup channel worker and close any file descriptors."""
        pass


class RTTChanTCPWorker(RTTChanWorker):
    """@brief Implementation of channel worker that forwards RTT data via a TCP
              socket. """

    port: int

    def __init__(self, port: int, listen: bool = True):
        """
        @param port The port to connect to or to listen for connects on.
        @param listen If true a server will be started to accept one connection
                      at a time on the given port. If false a connection will be
                      made as a TCP client to a server running on the given
                      port on localhost.
        """
        if listen:
            self.server = socket.socket()
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(('localhost', port))
            self.server.listen(1)
            self.server.setblocking(False)
            self.client = None
        else:
            self.server = None
            self.client = socket.create_connection(('localhost', port), timeout = 1.0)
            self.client.setblocking(False)

        self.port = port

    def _check_for_new_client(self):
        if self.server is None:
            return

        sel = selectors.DefaultSelector()
        sel.register(self.server, selectors.EVENT_READ, None)
        events = sel.select(timeout = 0)
        for key, _ in events:
            if key.fileobj == self.server:
                self.client, _ = self.server.accept()
                self.client.setblocking(False)

    def write_up_data(self, data: bytes):
        if self.client is None:
            self._check_for_new_client()
            if self.client is None:
                return 0

        return self.client.send(data)

    def get_down_data(self):
        if self.client is None:
            self._check_for_new_client()
            if self.client is None:
                return b''

        sel = selectors.DefaultSelector()
        sel.register(self.client, selectors.EVENT_READ, None)
        events = sel.select(timeout = 0)
        for key, _ in events:
            if key.fileobj == self.client:
                data = self.client.recv(4096)
                if not data:
                    # client socket closed at other end
                    self.client.close()
                    self.client = None
                return data

        return bytes()

    def close(self):
        if self.server is not None:
            self.server.close()
        if self.client is not None:
            self.client.close()

class RTTChanFileWorker(RTTChanWorker):
    """@brief Implementation of channel worker that write data from RTT channel
              to a file and optionally reads data from a file into an RTT
              channel. """


class RTTServer:
    """@brief Keeps track of polling for multiple active RTT channels and the
              sources and sinks of data for each channel. """
    control_block: RTTControlBlock
    workers: Optional[Sequence[Optional[RTTChanWorker]]]
    up_buffers: Optional[Sequence[bytes]]
    down_buffers: Optional[Sequence[bytes]]

    def __init__(self, target: SoCTarget, address: int, size: int,
                 control_block_id: bytes):
        """
        @param target The target with which RTT communication is desired.
        @param address Base address for control block search range.
        @param size Control block search range. If 0 the control block will be
                    expected to be located at the provided address.
        @param control_block_id The control block ID string to search for. Must
                                be at most 16 bytes long.  Will be padded with
                                zeroes if less than 16 bytes.
        """
        self.control_block = RTTControlBlock.from_target(target, address = address,
                                    size = size, control_block_id = control_block_id)

        self.workers = None
        self.up_buffers = None
        self.down_buffers = None

    def poll(self):
        """@brief Reads from and writes to active RTT channels. """
        if not self.running:
            # not yet started
            return

        for i, worker in enumerate(self.workers):
            if worker is None:
                continue

            # Read from up channel
            try:
                up_chan: RTTUpChannel = self.control_block.up_channels[i]
            except IndexError:
                pass
            else:
                self.up_buffers[i] += up_chan.read()

            # Write to worker
            bytes_written = worker.write_up_data(self.up_buffers[i])
            self.up_buffers[i] = self.up_buffers[i][bytes_written:]

            # Read from worker
            self.down_buffers[i] += worker.get_down_data()

            # Write data to down channel
            try:
                down_chan: RTTDownChannel = self.control_block.down_channels[i]
            except IndexError:
                pass
            else:
                bytes_out: int = down_chan.write(self.down_buffers[i])
                self.down_buffers[i] = self.down_buffers[i][bytes_out:]

    def start(self):
        """@brief Find and parse RTT control block. """
        self.control_block.start()

        num_up_chans: int = len(self.control_block.up_channels)
        num_down_chans: int = len(self.control_block.down_channels)
        num_chans: int = max(num_up_chans, num_down_chans)

        self.workers = [None] * num_chans
        self.up_buffers = [bytes()] * num_up_chans
        self.down_buffers = [bytes()] * num_down_chans

    def stop(self):
        """@brief Close all RTT workers. """
        if not self.running:
            return

        for i, worker in enumerate(self.workers):
            if worker is not None:
                worker.close()

        self.workers = None
        self.up_buffers = None
        self.down_buffers = None

    @property
    def running(self):
        """@brief True if RTT is started. """
        return self.workers is not None

    def add_server(self, port: int, channel: int):
        """@brief Start a new TCP server to communicate with a given RTT channel.

        @param port The port on which the server should listen for new connections.
        @param channel The RTT channel which should be exposed over TCP.
        """
        if not self.running:
            raise exceptions.RTTError("RTT is not yet started")
        elif self.workers[channel] is not None:
            raise exceptions.RTTError(f"RTT is already started for channel {channel}")

        self.workers[channel] = RTTChanTCPWorker(port, listen = True)

    def stop_server(self, port: int):
        """@brief Stop a TCP server.

        @param port The port of the server to be stopped.
        """

        if not self.running:
            return

        for i, worker in enumerate(self.workers):
            if isinstance(worker, RTTChanTCPWorker):
                if worker.port == port:
                    worker.close()
                    self.workers[i] = None
