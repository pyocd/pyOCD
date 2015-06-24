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
import sys
import io
import pyOCD
#from pyOCD.target import cortex_m #import (DFSR, DFSR_BKPT)
import logging
import time
import datetime
import threading
import socket
from ..gdbserver.gdb_socket import GDBSocket
from ..gdbserver.gdb_websocket import GDBWebSocket

## bkpt #0xab instruction
BKPT_INSTR = 0xbeab

# ARM semihosting request numbers.
TARGET_SYS_OPEN        = 0x01
TARGET_SYS_CLOSE       = 0x02
TARGET_SYS_WRITEC      = 0x03
TARGET_SYS_WRITE0      = 0x04
TARGET_SYS_WRITE       = 0x05
TARGET_SYS_READ        = 0x06
TARGET_SYS_READC       = 0x07
TARGET_SYS_ISERROR     = 0x08
TARGET_SYS_ISTTY       = 0x09
TARGET_SYS_SEEK        = 0x0a
TARGET_SYS_FLEN        = 0x0c
TARGET_SYS_TMPNAM      = 0x0d
TARGET_SYS_REMOVE      = 0x0e
TARGET_SYS_RENAME      = 0x0f
TARGET_SYS_CLOCK       = 0x10
TARGET_SYS_TIME        = 0x11
TARGET_SYS_SYSTEM      = 0x12
TARGET_SYS_ERRNO       = 0x13
TARGET_SYS_GET_CMDLINE = 0x15
TARGET_SYS_HEAPINFO    = 0x16
# angel_SWIreason_EnterSVC = 0x17
TARGET_SYS_EXIT        = 0x18 # angel_SWIreason_ReportException
TARGET_SYS_ELAPSED     = 0x30
TARGET_SYS_TICKFREQ    = 0x31

# Pseudo-file descriptor numbers. The fds must be non-zero according to the
# ARM semihosting spec.
STDIN_FD = 1
STDOUT_FD = 2
STDERR_FD = 3

## Maximum length of a null-terminated string we'll attempt to read from target memory.
#
# The length is limited in case the string isn't terminated.
#
# @see SemihostAgent::_get_string()
MAX_STRING_LENGTH = 2048

##
# @brief Abstract interface for semihosting file I/O handlers.
class SemihostIOHandler(object):
    def __init__(self):
        self.agent = None
        self._errno = 0

    @property
    def errno(self):
        return self._errno

    def open(self, fnptr, fnlen, mode):
        raise NotImplementedError()

    def close(self, fd):
        raise NotImplementedError()

    def write(self, fd, ptr, length):
        raise NotImplementedError()

    def read(self, fd, ptr, length):
        raise NotImplementedError()

    def readc(self):
        raise NotImplementedError()

    def istty(self, fd):
        raise NotImplementedError()

    def seek(self, fd, pos):
        raise NotImplementedError()

    def flen(self, fd):
        raise NotImplementedError()

    def remove(self, ptr, length):
        raise NotImplementedError()

    def rename(self, oldptr, oldlength, newptr, newlength):
        raise NotImplementedError()

##
# @brief Implements semihosting requests directly in the Python process.
class InternalSemihostIOHandler(SemihostIOHandler):
    def __init__(self):
        super(InternalSemihostIOHandler, self).__init__()
        self.next_fd = STDERR_FD + 1

        # Go ahead and connect standard I/O.
        self.open_files = {
                STDIN_FD : sys.stdin,
                STDOUT_FD : sys.stdout,
                STDERR_FD : sys.stderr
            }

    def _is_valid_fd(self, fd):
         return self.open_files.has_key(fd) and self.open_files[fd] is not None

    def open(self, fnptr, fnlen, mode):
        filename = self.agent._get_string(fnptr, fnlen)

        # Handle standard I/O.
        if filename == ':tt':
            if mode == 'r':
                fd = STDIN_FD
            elif mode == 'w':
                fd = STDOUT_FD
            elif mode == 'a':
                fd = STDERR_FD
            else:
                logging.warning("Unrecognized semihosting console file combination: mode=%s", mode)
                return -1
            return fd

        try:
            fd = self.next_fd
            self.next_fd += 1

            f = io.open(filename, mode)

            self.open_files[fd] = f

            return fd
        except IOError as e:
            self._errno = e.errno
            logging.error("Semihost: failed to open file '%s'", filename)
            return -1

    def close(self, fd):
        if fd > STDERR_FD:
            if not self._is_valid_fd(fd):
                return -1
            f = self.open_files.pop(fd)
            try:
                f.close()
            except OSError:
                # Ignore errors closing files.
                pass
        return 0

    def write(self, fd, ptr, length):
        if not self._is_valid_fd(fd):
            # Return byte count not written.
            return length
        data = self.agent._get_string(ptr, length)
        try:
            f = self.open_files[fd]
            if 'b' not in f.mode:
                data = unicode(data)
            f.write(data)
            return 0
        except IOError as e:
            self._errno = e.errno
            logging.debug("Semihost: exception: %s", e)
            return -1

    def read(self, fd, ptr, length):
        if not self._is_valid_fd(fd):
            # Return byte count not read.
            return length
        try:
            f = self.open_files[fd]
            data = f.read(length)
            if 'b' not in f.mode:
                data = data.encode()
        except IOError as e:
            self._errno = e.errno
            logging.debug("Semihost: exception: %s", e)
            return -1
        self.target.writeBlockMemoryUnaligned8(ptr, data)
        return length - len(data)

    def readc(self):
        try:
            f = self.open_files[STDIN_FD]
            if f is not None:
                data = f.read(1)
                if 'b' not in f.mode:
                    data = data.encode()
                return data
            else:
                return 0
        except OSError as e:
            self._errno = e.errno
            return 0

    def istty(self, fd):
        if not self._is_valid_fd(fd):
            return -1
        return int(self.open_files[fd].isatty())

    def seek(self, fd, pos):
        if not self._is_valid_fd(fd):
            return -1
        try:
            self.open_files[fd].seek(pos)
        except IOError as e:
            self._errno = e.errno
            return -1

    def flen(self, fd):
        if not self._is_valid_fd(fd):
            return -1
        try:
            info = os.fstat(fd)
            return info.st_size
        except OSError as e:
            self._errno = e.errno
            return -1

##
# @brief Serves a telnet connection for semihosting.
class TelnetSemihostIOHandler(SemihostIOHandler):
    def __init__(self, port_or_url):
        super(TelnetSemihostIOHandler, self).__init__()
        self._abstract_socket = None
        self._wss_server = None
        self._port = 0
        if isinstance(port_or_url, str) == True:
            self._wss_server = port_or_url
            self._abstract_socket = GDBWebSocket(self._wss_server)
        else:
            self._port = port_or_url
            self._abstract_socket = GDBSocket(self._port, 4096)
        self.mode = 't'
        self.connected = None
        self._shutdown_event = threading.Event()
        self._thread = threading.Thread(target=self._server, name="semihost-telnet")
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._shutdown_event.set()

    def _server(self):
        logging.debug("Telnet: server thread started on port %s", str(self._port))
        self.connected = None
        while not self._shutdown_event.is_set():
            while not self._shutdown_event.is_set():
                self.connected = self._abstract_socket.connect()
                if self.connected is not None:
                    logging.debug("Telnet: client connected")
                    break
            self._abstract_socket.setTimeout(0.1)
            while not self._shutdown_event.is_set():
                try:
                    d = self._abstract_socket.read()
                    if len(d) == 0:
                        self._abstract_socket.close()
                        self.connected = None
                        break
                except socket.timeout:
                    pass
        self._abstract_socket.close()
        logging.debug("Telnet: server thread stopped")

    def writable(self):
        return self._abstract_socket.conn is not None

    def write(self, fd, ptr, length):
        if self.connected is None:
            return 0
        data = self.agent._get_string(ptr, length)
        remaining = len(data)
        while remaining:
            count = self._abstract_socket.write(data)
            remaining -= count
            if remaining:
                data = data[count:]
        return 0

##
# @brief Handler for ARM semihosting requests.
#
# Semihosting requests are made by the target by executing a 'bkpt #0xab' instruction. The
# requested operation is specified by R0 and any arguments by R1. Many requests use a block
# of word-sized arguments pointed to by R1. The return value is passed back to the target
# in R0.
#
# This class maintains its own list of pseudo-file descriptors for files opened by the
# debug target. By default, this class uses the system stdin, stdout, and stderr file objects
# for file desscriptors 1, 2, and 3. In all cases, debug console I/O is mapped to pseudo-file
# descriptors 1 and 2.
#
# The user of this class can provide their own file-like objects to the constructor if they
# wish to redirect standard I/O elsewhere. None may also be passed for standard I/O to the
# constructor, in order to disable the I/O.
#
# Any user-provided file-like objects must have 'mode' attributes. This attribute is used
# to determine whether the file accepts bytes (binary) or unicode (text) data for read and
# write.
class SemihostAgent(object):

    ## Index into this array is the file open mode argument to TARGET_SYS_OPEN.
    OPEN_MODES = ['r', 'rb', 'r+', 'r+b', 'w', 'wb', 'w+', 'w+b', 'a', 'ab', 'a+', 'a+b']

    def __init__(self, target, io_handler=None, console=None):
        self.target = target
        self.start_time = time.time()
        self.io_handler = io_handler if (io_handler is not None) else InternalSemihostIOHandler()
        self.io_handler.agent = self
        self.console = console if (console is not None) else self.io_handler
        self.console.agent = self

        # Go ahead and connect standard I/O
        self.open_files = {
                STDIN_FD : sys.stdin,
                STDOUT_FD : sys.stdout,
                STDERR_FD : sys.stderr
            }

        self.request_map = {
                TARGET_SYS_OPEN        : self.handle_sys_open,
                TARGET_SYS_CLOSE       : self.handle_sys_close,
                TARGET_SYS_WRITEC      : self.handle_sys_writec,
                TARGET_SYS_WRITE0      : self.handle_sys_write0,
                TARGET_SYS_WRITE       : self.handle_sys_write,
                TARGET_SYS_READ        : self.handle_sys_read,
                TARGET_SYS_READC       : self.handle_sys_readc,
                TARGET_SYS_ISERROR     : self.handle_sys_iserror,
                TARGET_SYS_ISTTY       : self.handle_sys_istty,
                TARGET_SYS_SEEK        : self.handle_sys_seek,
                TARGET_SYS_FLEN        : self.handle_sys_flen,
                TARGET_SYS_TMPNAM      : self.handle_sys_tmpnam,
                TARGET_SYS_REMOVE      : self.handle_sys_remove,
                TARGET_SYS_RENAME      : self.handle_sys_rename,
                TARGET_SYS_CLOCK       : self.handle_sys_clock,
                TARGET_SYS_TIME        : self.handle_sys_time,
                TARGET_SYS_SYSTEM      : self.handle_sys_system,
                TARGET_SYS_ERRNO       : self.handle_sys_errno,
                TARGET_SYS_GET_CMDLINE : self.handle_sys_get_cmdline,
                TARGET_SYS_HEAPINFO    : self.handle_sys_heapinfo,
                TARGET_SYS_EXIT        : self.handle_sys_exit,
                TARGET_SYS_ELAPSED     : self.handle_sys_elapsed,
                TARGET_SYS_TICKFREQ    : self.handle_sys_tickfreq
            }

    ## @brief Handle a semihosting request.
    #
    # This method should be called after the target has halted, to check if the halt was
    # due to a semihosting request. It first checks to see if the target halted because
    # of a breakpoint. If so, it reads the instruction at PC to make sure it is a 'bkpt #0xAB'
    # instruction. If so, the target is making a semihosting request. If not, nothing more is done.
    #
    # After the request is handled, the PC is advanced to the next instruction after the 'bkpt'.
    # A boolean is return indicating whether a semihosting request was handled. If True, the
    # caller should resume the target immediately.
    #
    # @retval True A semihosting request was handled.
    # @retval False The target halted for a reason other than semihosting, i.e. a user-installed
    #   debugging breakpoint.
    def checkAndHandleSemihostRequest(self):
        # Nothing to do if this is not a bkpt.
        if (self.target.read32(pyOCD.target.cortex_m.DFSR) & pyOCD.target.cortex_m.DFSR_BKPT) == 0:
            return False

        pc = self.target.readCoreRegister('pc')

        # Are we stopped due to one of our own breakpoints?
        bp = self.target.findBreakpoint(pc)
        if bp:
            return False

        # Get the instruction at the breakpoint.
        instr = self.target.read16(pc)

        # Check for semihost bkpt.
        if instr != BKPT_INSTR:
            return False

        # Advance PC beyond the bkpt instruction.
        self.target.writeCoreRegister('pc', pc + 2)

        # Get args
        op = self.target.readCoreRegister('r0')
        args = self.target.readCoreRegister('r1')

        logging.debug("Semihost: request pc=%x r0=%x r1=%x", pc, op, args)

        # Handle request
        handler = self.request_map.get(op, None)
        if handler:
            try:
                result = handler(args)
            except NotImplementedError:
                result = -1
        else:
            result = -1

        # Set return value.
        self.target.writeCoreRegister('r0', result)

        return True

    def _get_args(self, args, count):
        return self.target.readBlockMemoryAligned32(args, count)

    def _get_string(self, ptr, length=None):
        if length is not None:
            data = self.target.readBlockMemoryUnaligned8(ptr, length)
            return str(bytearray(data))

        target_str = ''
        # TODO - use memory map to make sure we don't try to read off the end of memory
        # Limit string size in case it isn't terminated.
        while len(target_str) < MAX_STRING_LENGTH:
            try:
                # Read 32 bytes at a time for efficiency.
                data = self.target.readBlockMemoryUnaligned8(ptr, 32)
                terminator = data.index(0)

                # Found a null terminator, append data up to but not including the null
                # and then exit the loop.
                target_str += str(bytearray(data[:terminator]))
                break
            except TransferError:
                # Failed to read some or all of the string.
                break
            except ValueError:
                # No null terminator was found. Append all of data.
                target_str += str(bytearray(data))
                ptr += 32
        return target_str

    def _is_valid_fd(self, fd):
         return self.open_files.has_key(fd) and self.open_files[fd] is not None

    def handle_sys_open(self, args):
        fnptr, mode, fnlen = self._get_args(args, 3)
        if mode >= len(self.OPEN_MODES):
            return -1
        mode = self.OPEN_MODES[mode]

        logging.debug("Semihost: open %x/%x, mode %s", fnptr, fnlen, mode)
        return self.io_handler.open(fnptr, fnlen, mode)

    def handle_sys_close(self, args):
        fd = self._get_args(args, 1)
        logging.debug("Semihost: close fd=%d", fd)
        return self.io_handler.close(fd)

    def handle_sys_writec(self, args):
        logging.debug("Semihost: writec %x", args)
        return self.console.write(STDOUT_FD, args, 1)

    def handle_sys_write0(self, args):
        msg = self._get_string(args)
        logging.debug("Semihost: write0 msg='%s'", msg)
        return self.console.write(STDOUT_FD, args, len(msg))

    def handle_sys_write(self, args):
        fd, data_ptr, length = self._get_args(args, 3)
        logging.debug("Semihost: write fd=%d ptr=%x len=%d", fd, data_ptr, length)
        if fd in (STDOUT_FD, STDERR_FD):
            return self.console.write(fd, data_ptr, length)
        else:
            return self.io_handler.write(fd, data_ptr, length)

    def handle_sys_read(self, args):
        fd, ptr, length = self._get_args(args, 3)
        logging.debug("Semihost: read fd=%d ptr=%x len=%d", fd, ptr, length)
        if fd == STDIN_FD:
            return self.console.read(fd, ptr, length)
        else:
            return self.io_handler.read(fd, ptr, length)

    def handle_sys_readc(self, args):
        logging.debug("Semihost: readc")
        return self.console.readc()

    def handle_sys_iserror(self, args):
        raise NotImplementedError()

    def handle_sys_istty(self, args):
        fd = self._get_args(args, 1)
        logging.debug("Semihost: istty fd=%d", fd)
        return self.io_handler.istty(fd)

    def handle_sys_seek(self, args):
        fd, pos = self._get_args(args, 2)
        logging.debug("Semihost: seek fd=%d pos=%d", fd, pos)
        return self.io_handler.seek(fd, pos)

    def handle_sys_flen(self, args):
        fd = self._get_args(args, 1)
        logging.debug("Semihost: flen fd=%d", fd)
        return self.io_handler.flen(fd)

    def handle_sys_tmpnam(self, args):
        raise NotImplementedError()

    def handle_sys_remove(self, args):
        ptr, length = self._get_args(args, 2)
        return self.io_handler.remove(ptr, length)

    def handle_sys_rename(self, args):
        oldptr, oldlength, newptr, newlength = self._get_args(args, 4)
        return self.io_handler.rename(oldptr, oldlength, newptr, newlength)

    def handle_sys_clock(self, args):
        now = time.time()
        delta = now - self.start_time
        return int(delta * 100)

    def handle_sys_time(self, args):
        epoch = datetime.datetime(1970, 1, 1)
        now = datetime.datetime.now()
        delta = now - epoch
        seconds = (delta.days * 86400) + delta.seconds
        return seconds

    def handle_sys_system(self, args):
        raise NotImplementedError()

    def handle_sys_errno(self, args):
        return self.io_handler.errno

    def handle_sys_get_cmdline(self, args):
        raise NotImplementedError()

    def handle_sys_heapinfo(self, args):
        raise NotImplementedError()

    def handle_sys_exit(self, args):
        raise NotImplementedError()

    def handle_sys_elapsed(self, args):
        raise NotImplementedError()

    def handle_sys_tickfreq(self, args):
        raise NotImplementedError()



