"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

import os
from ..target.semihost import SemihostIOHandler

# Open mode flags
O_RDONLY = 0x0
O_WRONLY = 0x1
O_RDWR   = 0x2
O_APPEND = 0x8
O_CREAT  = 0x200
O_TRUNC  = 0x400
O_EXCL   = 0x800

##
# @brief Abstract interface for semihosting file I/O handlers.
class GDBSyscallIOHandler(SemihostIOHandler):
    def __init__(self, server):
        super(GDBSyscallIOHandler, self).__init__()
        self._server = server

    def open(self, fnptr, fnlen, mode):
        # Convert mode string to flags.
        modeval = 0
        hasplus = '+' in mode
        if 'r' in mode:
            if hasplus:
                modeval |= O_RDWR
            else:
                modeval |= O_RDONLY
        elif 'w' in mode:
            if hasplus:
                modeval |= O_RDWR | O_CREAT | O_TRUNC
            else:
                modeval |= O_WRONLY | O_CREAT | O_TRUNC
        elif 'a' in mode:
            if hasplus:
                modeval |= O_RDWR | O_APPEND | O_CREAT
            else:
                modeval |= O_WRONLY | O_APPEND | O_CREAT

        result, self._errno = self._server.syscall('open,%x/%x,%x,%x' % (fnptr, fnlen, 0777, modeval))
        return result

    def close(self, fd):
        result, self._errno = self._server.syscall('close,%x' % (fd))
        return result

    def write(self, fd, ptr, length):
        result, self._errno = self._server.syscall('write,%x,%x,%x' % (fd, ptr, length))
        return result

    def read(self, fd, ptr, length):
        result, self._errno = self._server.syscall('read,%x,%x,%x' % (fd, ptr, length))
        return result

    def readc(self):
        ptr = self.agent.target.readCoreRegister('sp') - 4
        result, self._errno = self._server.syscall('read,0,%x,1' % (ptr))
        if result != -1:
            result = self.agent.target.read8(ptr)
        return result

    def istty(self, fd):
        result, self._errno = self._server.syscall('isatty,%x' % (fd))
        return result

    def seek(self, fd, pos):
        result, self._errno = self._server.syscall('lseek,%x,%x,0' % (fd, pos))
        return 0 if result is not -1 else -1

    def flen(self, fd):
        ptr = self.agent.target.readCoreRegister('sp') - 64
        result, self._errno = self._server.syscall('fstat,%x,%x' % (fd, ptr))
        if result != -1:
            # Fields in stat struct are big endian as written by gdb.
            size = self.agent.target.readBlockMemoryUnaligned8(ptr, 8)
            result = (size[0] << 56) \
                    | (size[1] << 48) \
                    | (size[2] << 40) \
                    | (size[3] << 32) \
                    | (size[4] << 24) \
                    | (size[5] << 16) \
                    | (size[6] << 8) \
                    | (size[7])
        return result

