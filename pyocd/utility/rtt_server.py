# pyOCD debugger
# Copyright (c) 2022 Samuel Dewan
# Copyright (c) 2026 Arm Limited
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

from __future__ import annotations

from abc import ABC, abstractmethod
import selectors
import socket
from typing import Optional, Sequence, Callable, IO
import os
from time import sleep
from pathlib import Path
import logging

from ..core.soc_target import SoCTarget
from ..core import exceptions
from ..debug.rtt import RTTControlBlock, RTTUpChannel, RTTDownChannel
from ..utility.stdio import StdioHandler

LOG = logging.getLogger(__name__)

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
    """@brief Implementation of channel worker that writes data from RTT channel
              to a file and optionally reads data from a file into an RTT
              channel. """
    _f_out: Optional[IO[bytes]]
    _f_in: Optional[IO[bytes]]
    _f_out_path: Optional[str]
    _f_in_path: Optional[str]

    def __init__(self, channel: int, file_out: str, file_in: Optional[str] = None):
        """
        @param file_out The file to write RTT channel data to.
        @param file_in The file to read data from into the RTT channel. If None, no data will be read.
        """
        self._f_out = None
        self._f_in = None
        self._f_out_path = None
        self._f_in_path = None

        # Check if the folder exists for output file
        dir_out = os.path.dirname(file_out)
        if dir_out and not os.path.exists(dir_out):
            f_name_out = os.path.basename(file_out)
            raise FileNotFoundError(
                f"Output directory '{dir_out}' for RTT channel {channel} (file '{f_name_out}') does not exist."
            )
        try:
            self._f_out = open(file_out, 'wb')
            self._f_out_path = file_out
        except OSError as e:
            raise OSError(f"Failed to open RTT output file {file_out}: {e}")

        if file_in is not None:
            if os.path.exists(file_in):
                self._f_in = open(file_in, 'rb')
                self._f_in_path = file_in
            else:
                LOG.debug("Input file '%s' for RTT channel %d does not exist",  os.path.basename(file_in), channel)

    def write_up_data(self, data: bytes):
        if self._f_out is None:
            return 0
        return self._f_out.write(data)

    def get_down_data(self):
        if self._f_in is None:
            return b''
        return self._f_in.read(4096)

    def close(self):
        if self._f_out is not None:
            self._f_out.close()
        if self._f_in is not None:
            self._f_in.close()

class RTTChanSysViewFileWorker(RTTChanWorker):
    """@brief Implementation of channel worker that writes data from RTT channel
              to a SystemView file and handles START and STOP commands. """
    _START_CMD = b"\x01"
    _STOP_CMD  = b"\x02"
    _START_SEQ = b"\x00" * 10

    def __init__(self, rtt_server: RTTServer, rtt_channel: int, file_out: str, auto_start: bool = True, auto_stop: bool = True):
        self._rtt_server = rtt_server
        self._rtt_channel = rtt_channel
        self._auto_start = auto_start
        self._auto_stop = auto_stop

        self._started = not auto_start
        self._up_buffer = b""
        self._f_out = None
        self._f_out_path = None

        # Check if the folder exists for output file
        dir_out = os.path.dirname(file_out)
        if dir_out and not os.path.exists(dir_out):
            f_name_out = os.path.basename(file_out)
            raise FileNotFoundError(
                f"Output directory '{dir_out}' for RTT channel {self._rtt_channel} (file '{f_name_out}') does not exist."
            )
        try:
            self._f_out = open(file_out, 'wb')
            self._f_out_path = file_out
        except OSError as e:
            raise OSError(f"Failed to open SystemView output file {file_out}: {e}")

    def write_up_data(self, data: bytes):
        if self._f_out is None:
            return 0

        # If not started: search for start sequence; drop everything before it.
        if not self._started:
            self._up_buffer += data
            pos = self._up_buffer.find(self._START_SEQ)
            if pos < 0:
                # Keep last few bytes in case start sequence is split across writes, but drop the rest
                seq_len = len(self._START_SEQ)
                if len(self._up_buffer) > seq_len:
                    self._up_buffer = self._up_buffer[-seq_len:]
                return len(data)
            else:
                self._started = True
                to_write = self._up_buffer[pos:]
                self._up_buffer = b""
                self._f_out.write(to_write)
                return len(data)

        # Started (or auto_start disabled): write everything
        self._f_out.write(data)
        return len(data)

    def get_down_data(self):
        if not self._started:
            if self._rtt_server.is_channel_configured(self._rtt_channel) == False:
                # Should not happen
                LOG.error("SystemView worker for channel %d does not have a configured RTT channel; ignoring start request", self._rtt_channel)
                return b''
            down_chan: RTTDownChannel = self._rtt_server.control_block.down_channels[self._rtt_channel]
            if down_chan.bytes_free == down_chan.size:
                # Channel is empty, can start
                LOG.debug("SystemView START command for channel %d sent", self._rtt_channel)
                down_chan.write(self._START_CMD)
        return b""

    def close(self):
        if self._auto_stop:
            if self._rtt_server.is_channel_configured(self._rtt_channel) == False:
                # Should not happen
                LOG.error("SystemView worker for channel %d does not have a configured RTT channel; ignoring stop request", self._rtt_channel)
            else:
                down_chan: RTTDownChannel = self._rtt_server.control_block.down_channels[self._rtt_channel]
                LOG.debug("SystemView STOP command for channel %d sent", self._rtt_channel)
                down_chan.write(self._STOP_CMD)
        if self._f_out is not None:
            self._f_out.close()

class RTTChanSysViewTCPWorker(RTTChanTCPWorker):
    """@brief Implementation of channel worker that handles SystemView Hello messages and
              forwards RTT data via a TCP socket. """

    _HELLO_MSG = b"SEGGER SystemView"

    hello_received: bool

    def __init__(self, port: int, listen: bool = True):
        super().__init__(port, listen)
        self.hello_received = False

    def get_down_data(self):
        data = super().get_down_data()

        if self.client is None:
            self.hello_received = False
            return b''

        if not data:
            return b''

        if not self.hello_received:
            # First message from SystemView client should be 32 byte hello message starting with _HELLO_MSG
            if len(data) == 32 and data.startswith(self._HELLO_MSG):
                self.hello_received = True
                LOG.debug("Received hello message from SystemView client on port %d; connection established", self.port)
                # Return hello response
                response = self._HELLO_MSG
                response += b"\x00" * (32 - len(response))
                self.client.send(response)
            else:
                LOG.debug("Received non-hello message from SystemView client before hello message; ignoring")
            return b''

        return data

class RTTChanStdioWorker(RTTChanWorker):
    """@brief Implementation of channel worker that forwards RTT data via a STDIO"""

    _stdio: StdioHandler

    def __init__(self, channel: int, stdio: StdioHandler):
        """
        @param stdio The STDIO handler to use for RTT channel data.
        """
        self._stdio = stdio

    def write_up_data(self, data: bytes):
        if self._stdio is None:
            return 0
        return self._stdio.write(data)

    def get_down_data(self):
        if self._stdio is None:
            return b''
        return self._stdio.read(4096)

    def close(self):
        pass
        # if self._stdio is not None:
        #     self._stdio.shutdown()

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

    def _channel_handler(self, ch_idx: int, worker: RTTChanWorker):
        # Read from up channel
        try:
            up_chan: RTTUpChannel = self.control_block.up_channels[ch_idx]
        except IndexError:
            pass
        else:
            self.up_buffers[ch_idx] += up_chan.read()

        # Write to worker
        bytes_written = worker.write_up_data(self.up_buffers[ch_idx])
        self.up_buffers[ch_idx] = self.up_buffers[ch_idx][bytes_written:]

        # Read from worker
        self.down_buffers[ch_idx] += worker.get_down_data()

        # Write data to down channel
        try:
            down_chan: RTTDownChannel = self.control_block.down_channels[ch_idx]
        except IndexError:
            pass
        else:
            bytes_out: int = down_chan.write(self.down_buffers[ch_idx])
            self.down_buffers[ch_idx] = self.down_buffers[ch_idx][bytes_out:]

    def poll(self):
        """@brief Reads from and writes to active RTT channels. """
        if not self.running:
            # not yet started
            return

        for i, worker in enumerate(self.workers):
            if worker is None:
                continue
            self._channel_handler(i, worker)

    def start(self):
        """@brief Find and parse RTT control block. """
        self.control_block.start()

        num_up_chans: int = len(self.control_block.up_channels)
        num_down_chans: int = len(self.control_block.down_channels)
        num_chans: int = max(num_up_chans, num_down_chans)

        self.workers = [None] * num_chans
        self.up_buffers = [bytes()] * num_chans
        self.down_buffers = [bytes()] * num_chans

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

    def is_channel_idx_valid(self, channel: int) -> bool:
        """Return True if channel is a valid index for current workers."""
        if not isinstance(channel, int):
            return False
        if not self.running:
            return False
        return 0 <= channel < len(self.workers)

    def is_channel_configured(self, channel: int) -> bool:
        """Return True if channel is a valid index for current workers and has a worker configured."""
        if not self.is_channel_idx_valid(channel):
            return False
        return self.workers[channel] is not None

    def add_channel_worker(self, channel: int, worker: Callable[[], RTTChanWorker]):
        self.workers[channel] = worker()

    def remove_channel_worker(self, channel: int):
        if not self.is_channel_idx_valid(channel):
            raise exceptions.RTTError(f"Invalid channel index {channel}")
        worker = self.workers[channel]
        if worker is not None:
            worker.close()
            self.workers[channel] = None

    def add_server(self, port: int, channel: int):
        """@brief Start a new TCP server to communicate with a given RTT channel.

        @param port The port on which the server should listen for new connections.
        @param channel The RTT channel which should be exposed over TCP.
        """
        if not self.running:
            raise exceptions.RTTError("RTT is not yet started")
        elif self.workers[channel] is not None:
            raise exceptions.RTTError(f"RTT is already started for channel {channel}")
        self.add_channel_worker(channel, lambda: RTTChanTCPWorker(port, listen = True))

    def stop_server(self, channel: Optional[int] = None, port: Optional[int] = None):
        """@brief Stop a TCP server.

        @param port The port of the server to be stopped.
        """

        if not self.running:
            return
        if channel is not None:
            return self.remove_channel_worker(channel)

        # Fallback: if channel not specified, search for server with given port and stop it
        for i, worker in enumerate(self.workers):
            if isinstance(worker, RTTChanTCPWorker):
                if worker.port == port:
                    worker.close()
                    self.workers[i] = None
