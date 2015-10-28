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

import socket, select

class GDBSocket(object):
    def __init__(self, port, packet_size):
        self.packet_size = packet_size
        self.s = None
        self.conn = None
        self.port = port
        self.host = ''

    def init(self):
        if self.s is None:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind((self.host, self.port))
            self.s.listen(5)

    def connect(self):
        self.conn = None
        self.init()
        rr, _, _ = select.select([self.s], [], [], 0.5)
        if rr:
            self.conn, _ = self.s.accept()

        return self.conn

    def read(self):
        return self.conn.recv(self.packet_size)

    def write(self, data):
        return self.conn.send(data)

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

        return_value = None
        if self.s is not None:
            return_value = self.s.close()
            self.s = None

        return return_value


    def setBlocking(self, blocking):
        self.conn.setblocking(blocking)

    def setTimeout(self, timeout):
        self.conn.settimeout(timeout)
