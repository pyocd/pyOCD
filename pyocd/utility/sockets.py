# pyOCD debugger
# Copyright (c) 2006-2020 Arm Limited
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

import socket
import select

class ListenerSocket(object):
    def __init__(self, port, packet_size):
        self.packet_size = packet_size
        self.listener = None
        self.conn = None
        self.port = port
        self.host = 'localhost'

    def init(self):
        if self.listener is None:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((self.host, self.port))
            # If we were asked for port 0, that's treated as "auto".
            # Read back the port - allows our user to find (and print) it,
            # and means that if we're closed then re-opened, as happens when
            # persisting for multiple sessions, we reuse the same port, which
            # is convenient.
            if self.port == 0:
                self.port = self.listener.getsockname()[1]
            self.listener.listen(1)

    def connect(self):
        self.conn = None
        self.init()
        rr, _, _ = select.select([self.listener], [], [], 0.5)
        if rr:
            self.conn, _ = self.listener.accept()

        return self.conn

    def read(self, packet_size=None):
        if packet_size is None:
            packet_size = self.packet_size
        return self.conn.recv(packet_size)

    def write(self, data):
        return self.conn.send(data)

    def close(self):
        return_value = None
        if self.conn is not None:
            return_value = self.conn.close()
            self.conn = None

        return return_value

    def cleanup(self):
        self.close()
        if self.listener is not None:
            self.listener.close()
            self.listener = None

    def set_blocking(self, blocking):
        self.conn.setblocking(blocking)

    def set_timeout(self, timeout):
        self.conn.settimeout(timeout)

class ClientSocket(object):
    """! @brief Simple client-side TCP socket.
    
    Provides a file-like interface to a TCP socket. Blocking and timeout are configurable.
    """
    
    DEFAULT_TIMEOUT = 10.0
    
    def __init__(self, host, port, packet_size=4096, timeout=None):
        self._address = (host, port)
        self._packet_size = packet_size
        self._timeout = timeout or self.DEFAULT_TIMEOUT
        self._socket = None
        self._buffer = bytearray()
    
    def connect(self):
        self._socket = socket.create_connection(self._address, self._timeout)
    
    def close(self):
        if self._socket is not None:
            # Close both ends of the connection, then close the socket itself.
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            self._socket = None

    def set_blocking(self, blocking):
        self._socket.setblocking(blocking)

    def set_timeout(self, timeout):
        """! @brief Change the socket to blocking with timeout mode."""
        self._socket.settimeout(timeout)

    def read(self, packet_size=None):
        if packet_size is None:
            packet_size = self._packet_size
        # Pull from the buffer first.
#         if len(self._buffer):
#             length = min(len(self._buffer), packet_size)
#             data =  self._buffer[:length]
#             self._buffer = self._buffer[length:]
#             return data
        return self._socket.recv(packet_size)

    def write(self, data):
        return self._socket.sendall(data)
    
    def readline(self):
        while True:
            # Try to extract a line from the buffer.
            offset = self._buffer.find(b'\n')
            if offset != -1:
                offset += 1 # include lf
                data =  self._buffer[:offset]
                del self._buffer[:offset]
                return data
            # Read a chunk and put in the buffer, then try again.
            while True:
                try:
                    data = self.read()
                except socket.timeout:
                    pass
                else:
                    break
            self._buffer += data
