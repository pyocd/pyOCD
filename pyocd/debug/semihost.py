# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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

import os
import sys
import io
import logging
import time
import datetime
import six

from ..coresight.cortex_m import CortexM
from ..core import (exceptions, session)

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

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
angel_SWIreason_EnterSVC = 0x17 # pylint: disable=invalid-name
TARGET_SYS_EXIT        = 0x18 # Also called angel_SWIreason_ReportException
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

class SemihostIOHandler(object):
    """! @brief Interface for semihosting file I/O handlers.
    
    This class is also used as the default I/O handler if none is provided to SemihostAgent.
    In this case, all file I/O requests are rejected.
    """
    
    def __init__(self):
        self.agent = None
        self._errno = 0

    def cleanup(self):
        pass

    @property
    def errno(self):
        return self._errno

    def _std_open(self, fnptr, fnlen, mode):
        """! @brief Helper for standard I/O open requests.
        
        In the ARM semihosting spec, standard I/O files are opened using a filename of ":tt"
        with the open mode specifying which standard I/O file to open. This method takes care
        of these special open requests, and is intended to be used by concrete I/O handler
        subclasses.
        
        @return A 2-tuple of the file descriptor and filename. The filename is returned so it
          only has to be read from target memory once if the request is not for standard I/O.
          The returned file descriptor may be one of 0, 1, or 2 for the standard I/O files,
          -1 if an invalid combination was requested, or None if the request was not for
          a standard I/O file (i.e., the filename was not ":tt"). If None is returned for the
          file descriptor, the caller must handle the open request.
        """
        filename = self.agent._get_string(fnptr, fnlen)
        LOG.debug("Semihost: open '%s' mode %s", filename, mode)

        # Handle standard I/O.
        if filename == ':tt':
            if mode == 'r':
                fd = STDIN_FD
            elif mode == 'w':
                fd = STDOUT_FD
            elif mode == 'a':
                fd = STDERR_FD
            else:
                LOG.warning("Unrecognized semihosting console open file combination: mode=%s", mode)
                return -1, filename
            return fd, filename
        return None, filename

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

class InternalSemihostIOHandler(SemihostIOHandler):
    """! @brief Implements semihosting requests directly in the Python process.
    
    This class maintains its own list of pseudo-file descriptors for files opened by the
    debug target. By default, this class uses the system stdin, stdout, and stderr file objects
    for file desscriptors 1, 2, and 3.
    """
    
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
         return fd in self.open_files and self.open_files[fd] is not None

    def cleanup(self):
        for f in (self.open_files[k] for k in self.open_files if k > STDERR_FD):
            f.close()

    def open(self, fnptr, fnlen, mode):
        fd, filename = self._std_open(fnptr, fnlen, mode)
        if fd is not None:
            return fd

        try:
            fd = self.next_fd
            self.next_fd += 1

            f = io.open(filename, mode)

            self.open_files[fd] = f

            return fd
        except IOError as e:
            self._errno = e.errno
            LOG.error("Semihost: failed to open file '%s'", filename, exc_info=session.Session.get_current().log_tracebacks)
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
            if 'b' in f.mode:
                data = six.ensure_binary(data)
            else:
                data = six.ensure_str(data)
            f.write(data)
            f.flush()
            return 0
        except IOError as e:
            self._errno = e.errno
            LOG.debug("Semihost: exception: %s", e)
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
            LOG.debug("Semihost: exception: %s", e)
            return -1
        data = bytearray(data)
        self.agent.context.write_memory_block8(ptr, data)
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
        # Just assume that stdio is a terminal and other files aren't.
        return int(not fd > STDERR_FD)

    def seek(self, fd, pos):
        if not self._is_valid_fd(fd):
            return -1
        try:
            self.open_files[fd].seek(pos)
            return 0
        except IOError as e:
            self._errno = e.errno
            return -1

    def flen(self, fd):
        if not self._is_valid_fd(fd):
            return -1
        try:
            info = os.fstat(self.open_files[fd].fileno())
            return info.st_size
        except OSError as e:
            self._errno = e.errno
            return -1

class ConsoleIOHandler(SemihostIOHandler):
    """! @brief Simple IO handler for console."""
    
    def __init__(self, stdin_file, stdout_file=None):
        super(ConsoleIOHandler, self).__init__()
        self._stdin_file = stdin_file
        self._stdout_file = stdout_file or stdin_file

    def write(self, fd, ptr, length):
        data = self.agent._get_string(ptr, length)
        self._stdout_file.write(data)
        return 0

    def read(self, fd, ptr, length):
        data = self._stdin_file.read(length)

        # Stuff data into provided buffer.
        if data:
            self.agent.context.write_memory_block8(ptr, data)

        result = length - len(data)
        if not data:
            self._errno = 5
            return -1
        return result

    def readc(self):
        data = self._stdin_file.read(1)

        if data:
            return data[0]
        else:
            return -1

class SemihostAgent(object):
    """! @brief Handler for ARM semihosting requests.
    
    Semihosting requests are made by the target by executing a 'bkpt #0xab' instruction. The
    requested operation is specified by R0 and any arguments by R1. Many requests use a block
    of word-sized arguments pointed to by R1. The return value is passed back to the target
    in R0.
    
    This class does not handle any file-related requests by itself. It uses I/O handler objects
    passed in to the constructor. The requests handled directly by this class are #TARGET_SYS_CLOCK
    and #TARGET_SYS_TIME.
    
    There are two types of I/O handlers used by this class. The main I/O handler, set
    with the constructor's @i io_handler parameter, is used for most file operations.
    You may optionally pass another I/O handler for the @i console constructor parameter. The
    console handler is used solely for standard I/O and debug console I/O requests. If no console
    handler is provided, the main handler is used instead. TARGET_SYS_OPEN requests are not
    passed to the console handler in any event, they are always passed to the main handler.
    
    If no main I/O handler is provided, the class will use SemihostIOHandler, which causes all
    file I/O requests to be rejected as an error.
    
    The SemihostAgent assumes standard I/O file descriptor numbers are #STDIN_FD, #STDOUT_FD,
    and #STDERR_FD. When it receives a read or write request for one of these descriptors, it
    passes the request to the console handler. This means the main handler must return these
    numbers for standard I/O open requests (those with a file name of ":tt").
    
    Not all semihosting requests are supported. Those that are not implemented are:
    - TARGET_SYS_TMPNAM
    - TARGET_SYS_SYSTEM
    - TARGET_SYS_GET_CMDLINE
    - TARGET_SYS_HEAPINFO
    - TARGET_SYS_EXIT
    - TARGET_SYS_ELAPSED
    - TARGET_SYS_TICKFREQ
    """

    ## Index into this array is the file open mode argument to TARGET_SYS_OPEN.
    OPEN_MODES = ['r', 'rb', 'r+', 'r+b', 'w', 'wb', 'w+', 'w+b', 'a', 'ab', 'a+', 'a+b']

    EPOCH = datetime.datetime(1970, 1, 1)

    def __init__(self, context, io_handler=None, console=None):
        self.context = context
        self.start_time = time.time()
        self.io_handler = io_handler or SemihostIOHandler()
        self.io_handler.agent = self
        self.console = console or self.io_handler
        self.console.agent = self

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

    def check_and_handle_semihost_request(self):
        """! @brief Handle a semihosting request.
        
        This method should be called after the target has halted, to check if the halt was
        due to a semihosting request. It first checks to see if the target halted because
        of a breakpoint. If so, it reads the instruction at PC to make sure it is a 'bkpt #0xAB'
        instruction. If so, the target is making a semihosting request. If not, nothing more is done.
        
        After the request is handled, the PC is advanced to the next instruction after the 'bkpt'.
        A boolean is return indicating whether a semihosting request was handled. If True, the
        caller should resume the target immediately.
        
        @retval True A semihosting request was handled.
        @retval False The target halted for a reason other than semihosting, i.e. a user-installed
          debugging breakpoint.
        """
        # Nothing to do if this is not a bkpt.
        if (self.context.read32(CortexM.DFSR) & CortexM.DFSR_BKPT) == 0:
            return False

        pc = self.context.read_core_register('pc')

        # Are we stopped due to one of our own breakpoints?
        bp = self.context.core.find_breakpoint(pc)
        if bp:
            return False

        # Get the instruction at the breakpoint.
        instr = self.context.read16(pc)

        # Check for semihost bkpt.
        if instr != BKPT_INSTR:
            return False

        # Advance PC beyond the bkpt instruction.
        self.context.write_core_register('pc', pc + 2)

        # Get args
        op = self.context.read_core_register('r0')
        args = self.context.read_core_register('r1')

        # Handle request
        handler = self.request_map.get(op, None)
        if handler:
            try:
                result = handler(args)
            except NotImplementedError:
                LOG.warning("Semihost: unimplemented request pc=%x r0=%x r1=%x", pc, op, args)
                result = -1
            except (exceptions.Error, IOError) as e:
                LOG.error("Exception while handling semihost request: %s", e,
                    exc_info=session.Session.get_current().log_tracebacks)
                result = -1
        else:
            result = -1

        # Set return value.
        self.context.write_core_register('r0', result)

        return True

    def cleanup(self):
        """! @brief Clean up any resources allocated by semihost requests.
        
        @note May be called more than once.
        """
        self.io_handler.cleanup()
        if self.console is not self.io_handler:
            self.console.cleanup()

    def _get_args(self, args, count):
        args = self.context.read_memory_block32(args, count)
        if count == 1:
            return args[0]
        else:
            return args

    def _get_string(self, ptr, length=None):
        if length is not None:
            data = self.context.read_memory_block8(ptr, length)
            return bytes(data).decode()

        target_str = ''
        # TODO - use memory map to make sure we don't try to read off the end of memory
        # Limit string size in case it isn't terminated.
        while len(target_str) < MAX_STRING_LENGTH:
            try:
                # Read 32 bytes at a time for efficiency.
                data = self.context.read_memory_block8(ptr, 32)
                terminator = data.index(0)

                # Found a null terminator, append data up to but not including the null
                # and then exit the loop.
                target_str += bytes(data[:terminator]).decode()
                break
            except exceptions.TransferError:
                # Failed to read some or all of the string.
                break
            except ValueError:
                # No null terminator was found. Append all of data.
                target_str += bytes(data).decode()
                ptr += 32
        return target_str

    def handle_sys_open(self, args):
        fnptr, mode, fnlen = self._get_args(args, 3)
        if mode >= len(self.OPEN_MODES):
            return -1
        mode = self.OPEN_MODES[mode]

        TRACE.debug("Semihost: open %x/%x, mode %s", fnptr, fnlen, mode)
        return self.io_handler.open(fnptr, fnlen, mode)

    def handle_sys_close(self, args):
        fd = self._get_args(args, 1)
        TRACE.debug("Semihost: close fd=%d", fd)
        return self.io_handler.close(fd)

    def handle_sys_writec(self, args):
        TRACE.debug("Semihost: writec %x", args)
        return self.console.write(STDOUT_FD, args, 1)

    def handle_sys_write0(self, args):
        msg = self._get_string(args)
        TRACE.debug("Semihost: write0 msg='%s'", msg)
        return self.console.write(STDOUT_FD, args, len(msg))

    def handle_sys_write(self, args):
        fd, data_ptr, length = self._get_args(args, 3)
        TRACE.debug("Semihost: write fd=%d ptr=%x len=%d", fd, data_ptr, length)
        if fd in (STDOUT_FD, STDERR_FD):
            return self.console.write(fd, data_ptr, length)
        else:
            return self.io_handler.write(fd, data_ptr, length)

    def handle_sys_read(self, args):
        fd, ptr, length = self._get_args(args, 3)
        TRACE.debug("Semihost: read fd=%d ptr=%x len=%d", fd, ptr, length)
        if fd == STDIN_FD:
            return self.console.read(fd, ptr, length)
        else:
            return self.io_handler.read(fd, ptr, length)

    def handle_sys_readc(self, args):
        TRACE.debug("Semihost: readc")
        return self.console.readc()

    def handle_sys_iserror(self, args):
        raise NotImplementedError()

    def handle_sys_istty(self, args):
        fd = self._get_args(args, 1)
        TRACE.debug("Semihost: istty fd=%d", fd)
        return self.io_handler.istty(fd)

    def handle_sys_seek(self, args):
        fd, pos = self._get_args(args, 2)
        TRACE.debug("Semihost: seek fd=%d pos=%d", fd, pos)
        return self.io_handler.seek(fd, pos)

    def handle_sys_flen(self, args):
        fd = self._get_args(args, 1)
        TRACE.debug("Semihost: flen fd=%d", fd)
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
        now = datetime.datetime.now()
        delta = now - self.EPOCH
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



