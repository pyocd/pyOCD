# pyOCD debugger
# Copyright (c) 2015-2019 Arm Limited
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

from .sockets import ListenerSocket
from .compatibility import to_bytes_safe

LOG = logging.getLogger(__name__)

class StreamServer(threading.Thread):
    """! @brief File-like object that serves data over a TCP socket.
    
    The user can connect to the socket with telnet or netcat.
    
    The server thread will automatically be started by the constructor. To shut down the
    server and its thread, call the stop() method.
    """
    
    def __init__(self, port, serve_local_only=True, name=None, is_read_only=True, extra_info=None):
        """! @brief Constructor.
        
        Starts the server immediately.
        
        @param self
        @param port The TCP/IP port number on which the server should listen. If 0 is passed,
            then an arbitrary unused port is selected by the OS. In this case, the `port` property
            can be used to get the actual port number.
        @param serve_local_only Whether to allow connections from remote clients.
        @param name Optional server name.
        @param is_read_only If the server is read-only, from the perspective of the client,
            then any incoming data sent by the client is discarded. Otherwise it is buffered so
            it can be read with the read() methods.
        @param extra_info Optional string with extra information about the server, e.g. "core 0".
        """
        super(StreamServer, self).__init__()
        self.name = name
        self._name = name
        self._extra_info = extra_info
        self._formatted_name = (name + " ") if (name is not None) else ""
        self._is_read_only = is_read_only
        self._abstract_socket = None
        self._abstract_socket = ListenerSocket(port, 4096)
        if not serve_local_only:
            # We really should be binding to explicit interfaces, not all available.
            self._abstract_socket.host = ''
        self._abstract_socket.init()
        self._port = self._abstract_socket.port
        self._buffer = bytearray()
        self._buffer_lock = threading.Lock()
        self.connected = None
        self._shutdown_event = threading.Event()
        self.daemon = True
        self.start()
    
    @property
    def port(self):
        return self._port

    def stop(self):
        self._shutdown_event.set()
        self.join()

    def run(self):
        LOG.info("%sserver started on port %d%s", self._formatted_name, self._port,
            (" (%s)" % self._extra_info) if self._extra_info else "")
        self.connected = None
        try:
            while not self._shutdown_event.is_set():
                # Wait for a client to connect.
                # TODO support multiple client connections
                while not self._shutdown_event.is_set():
                    self.connected = self._abstract_socket.connect()
                    if self.connected is not None:
                        LOG.debug("%sclient connected", self._formatted_name)
                        break

                if self._shutdown_event.is_set():
                    break

                # Set timeout on new connection.
                self._abstract_socket.set_timeout(0.1)

                # Keep reading from the client until we either get a shutdown event, or
                # the client disconnects. The incoming data is appended to our read buffer.
                while not self._shutdown_event.is_set():
                    try:
                        data = self._abstract_socket.read()
                        if len(data) == 0:
                            # Client disconnected.
                            self._abstract_socket.close()
                            self.connected = None
                            break

                        if not self._is_read_only:
                            self._buffer_lock.acquire()
                            self._buffer += bytearray(data)
                            self._buffer_lock.release()
                    except socket.timeout:
                        pass
        finally:
            self._abstract_socket.cleanup()
        LOG.info("%sserver stopped", self._formatted_name)

    def write(self, data):
        """! @brief Write bytes into the connection."""
        # If nobody is connected, act like all data was written anyway.
        if self.connected is None:
            return 0
        data = to_bytes_safe(data)
        size = len(data)
        remaining = size
        while remaining:
            count = self._abstract_socket.write(data)
            remaining -= count
            if remaining:
                data = data[count:]
        return size

    def _get_input(self, length=-1):
        """! @brief Extract requested amount of data from the read buffer."""
        self._buffer_lock.acquire()
        try:
            if length == -1:
                actualLength = len(self._buffer)
            else:
                actualLength = min(length, len(self._buffer))
            if actualLength:
                data = self._buffer[:actualLength]
                self._buffer = self._buffer[actualLength:]
            else:
                data = bytearray()
            return data
        finally:
            self._buffer_lock.release()

    def read(self, size=-1):
        """! @brief Return bytes read from the connection."""
        if self.connected is None:
            return None

        # Extract requested amount of data from the read buffer.
        data = self._get_input(size)

        return data

    def readinto(self, b):
        """! @brief Read bytes into a mutable buffer."""
        if self.connected is None:
            return None

        # Extract requested amount of data from the read buffer.
        b[:] = self._get_input()

        if len(b):
            return len(b)
        else:
            return None

