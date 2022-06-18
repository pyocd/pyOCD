# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2022 NXP
# Copyright (c) 2022-2023 Chris Reed
# Copyright (c) 2023 Hardy Griech
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
import pathlib
from enum import (Enum, IntEnum)
from typing import (IO, TYPE_CHECKING, Callable, Dict, List, Optional, Tuple, Union, cast, overload)
from typing_extensions import Literal

from ..coresight.cortex_m import CortexM
from ..core import (exceptions, session)

if TYPE_CHECKING:
    from .context import DebugContext

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

## bkpt #0xab instruction
BKPT_INSTR = 0xbeab

class SemihostingRequests(IntEnum):
    """@brief Arm semihosting request numbers."""
    SYS_OPEN            = 0x01
    SYS_CLOSE           = 0x02
    SYS_WRITEC          = 0x03
    SYS_WRITE0          = 0x04
    SYS_WRITE           = 0x05
    SYS_READ            = 0x06
    SYS_READC           = 0x07
    SYS_ISERROR         = 0x08
    SYS_ISTTY           = 0x09
    SYS_SEEK            = 0x0a
    SYS_FLEN            = 0x0c
    SYS_TMPNAM          = 0x0d
    SYS_REMOVE          = 0x0e
    SYS_RENAME          = 0x0f
    SYS_CLOCK           = 0x10
    SYS_TIME            = 0x11
    SYS_SYSTEM          = 0x12
    SYS_ERRNO           = 0x13
    SYS_GET_CMDLINE     = 0x15
    SYS_HEAPINFO        = 0x16
    angel_SWIreason_EnterSVC = 0x17 # pylint: disable=invalid-name
    SYS_EXIT            = 0x18 # Also called angel_SWIreason_ReportException
    SYS_EXIT_EXTENDED   = 0x20
    SYS_ELAPSED         = 0x30
    SYS_TICKFREQ        = 0x31

# Pseudo-file descriptor numbers.
# Note: According to Arm semihosting spec, the fds must be non-zero.  But to achive POSIX compatibility
#       it has been chosen to use 0 for STDIN_FD.  OpenOCD behaves the same.
STDIN_FD = 0
STDOUT_FD = 1
STDERR_FD = 2

## Maximum length of a null-terminated string we'll attempt to read from target memory.
#
# The length is limited in case the string isn't terminated, this is relevant only for TARGET_SYS_WRITE0
#
# @see SemihostAgent::get_data()
MAX_STRING_LENGTH = 2048

## Enumsused for the file ID to indicate a special file was opened.
class SpecialFile(Enum):
    # ":semihosting-features"
    SEMIHOSTING_FEATURES_FILE = object()

class SemihostIOHandler:
    """@brief Interface for semihosting file I/O handlers.

    This class is also used as the default I/O handler if none is provided to SemihostAgent.
    In this case, all file I/O requests are rejected.
    """

    agent: Optional["SemihostAgent"]
    _errno: int

    def __init__(self) -> None:
        self.agent = None
        self._errno = 0

    def cleanup(self) -> None:
        pass

    @property
    def errno(self) -> int:
        return self._errno

    def _std_open(self, fnptr: int, fnlen: int, mode: str) -> Tuple[Optional[Union[int, SpecialFile]], str]:
        """@brief Helper for standard I/O open requests.

        In the Arm semihosting spec, standard I/O files are opened using a filename of ":tt"
        with the open mode specifying which standard I/O file to open. This method takes care
        of these special open requests, and is intended to be used by concrete I/O handler
        subclasses.

        Another special file is the ":semihosting-features" file used for semihosting feature bit
        reporting. This method recognised this file name, checks the requested file mode against
        allowed modes, and returns `SpecialFile.SEMIHOSTING_FEATURES_FILE` as the file ID.

        @return A 2-tuple of the file descriptor and filename. The filename is returned so it
          only has to be read from target memory once if the request is not for standard I/O.
          The returned file descriptor may be one of 0, 1, or 2 for the standard I/O files,
          -1 if an invalid combination was requested, or None if the request was not for
          a standard I/O file (i.e., the filename was not ":tt"). If None is returned for the
          file descriptor, the caller must handle the open request.
          SpecialFile.SEMIHOSTING_FEATURES_FILE can also be returned as the file ID in case
          the special ":semihosting-features" file is opened.
        @exception IOError Raised if an invalid file mode is used for a special file.
        """
        assert self.agent
        filename = self.agent.get_data(fnptr, fnlen).decode()
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
        # Semihosting features file, not currently supported.
        elif filename == ':semihosting-features':
            # All modes other than 'r' and 'rb' must fail.
            if mode not in ('r', 'rb'):
                raise IOError("attempt to open :semihosting-features with invalid mode "
                                "(only r and rb are allowed)")
            return SpecialFile.SEMIHOSTING_FEATURES_FILE, filename
        return None, filename

    def open(self, fnptr: int, fnlen: int, mode: str) -> int:
        raise NotImplementedError()

    def close(self, fd: int) -> int:
        raise NotImplementedError()

    def write(self, fd: int, ptr: int, length: int) -> int:
        raise NotImplementedError()

    def read(self, fd: int, ptr: int, length: int) -> int:
        raise NotImplementedError()

    def readc(self) -> int:
        raise NotImplementedError()

    def istty(self, fd: int) -> int:
        raise NotImplementedError()

    def seek(self, fd: int, pos: int) -> int:
        raise NotImplementedError()

    def flen(self, fd: int) -> int:
        raise NotImplementedError()

    def remove(self, ptr: int, length: int) -> int:
        raise NotImplementedError()

    def rename(self, oldptr: int, oldlength: int, newptr: int, newlength: int) -> int:
        raise NotImplementedError()

class InternalSemihostIOHandler(SemihostIOHandler):
    """@brief Implements semihosting requests directly in the Python process.

    This class maintains its own list of pseudo-file descriptors for files opened by the
    debug target. By default, this class uses the system stdin, stdout, and stderr file objects
    for file desscriptors 1, 2, and 3.
    """

    def __init__(self):
        super().__init__()
        self.next_fd = STDERR_FD + 1

        # Go ahead and connect standard I/O.
        self.open_files: Dict[int, Union[IO[str], IO[bytes]]] = {
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
        special_fd, filename = self._std_open(fnptr, fnlen, mode)
        # if special_fd is not None:
        #     return special_fd
        if (special_fd is not None) and (special_fd is not SpecialFile.SEMIHOSTING_FEATURES_FILE):
            return special_fd

        try:
            # Handle semihosting features.
            if special_fd is SpecialFile.SEMIHOSTING_FEATURES_FILE:
                # Features bits:
                # - Byte 0, bit 0 = 0: SH_EXT_EXIT_EXTENDED, whether SYS_EXIT_EXTENDED is supported
                # - Byte 0, bit 1 = 1: SH_EXT_STDOUT_STDERR, whether both stdout and stderr are supported
                f = io.BytesIO(b"SHFB\x02")
            else:
                # Expand user directory.
                filepath = pathlib.Path(filename).expanduser()

                # ensure directories are exists if mode is write/appened
                if ('w' in mode) or ('a' in mode):
                    filepath.parent.mkdir(parents=True, exist_ok=True)

                f = io.open(filepath, mode)

            fd = self.next_fd
            self.next_fd += 1

            self.open_files[fd] = f

            return fd
        except OSError as e:
            self._errno = e.errno
            LOG.error("Semihost: failed to open file '%s'", filename,
                    exc_info=(self.agent.context.session.log_tracebacks if self.agent else True))
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

        assert self.agent
        data = self.agent.get_data(ptr, length)
        f = self.open_files[fd]
        try:
            if 'b' in f.mode:
                cast(IO[bytes], f).write(data)
            else:
                cast(IO[str], f).write(data.decode(errors='ignore'))
            f.flush()
            return 0
        except OSError as e:
            self._errno = e.errno
            LOG.debug("Semihost: exception: %s", e)
            return -1

    def read(self, fd, ptr, length):
        assert self.agent

        if not self._is_valid_fd(fd):
            # Return byte count not read.
            return length

        try:
            f = self.open_files[fd]
            data = f.read(length)
        except OSError as e:
            self._errno = e.errno
            LOG.debug("Semihost: exception: %s", e)
            return -1

        if isinstance(data, str):
            data = data.encode()

        ba = bytearray(data)
        self.agent.context.write_memory_block8(ptr, ba)
        return length - len(ba)

    def readc(self):
        try:
            f = self.open_files[STDIN_FD]
            if f is not None:
                data = f.read(1)
                c = ord(data[0:1])
                return c
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
        except OSError as e:
            self._errno = e.errno
            return -1

    def flen(self, fd):
        if not self._is_valid_fd(fd):
            return -1
        f = self.open_files[fd]
        try:
            info = os.fstat(f.fileno())
            return info.st_size
        except io.UnsupportedOperation:
            # Try seeking to end to get size.
            saved_pos = f.tell()
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(saved_pos, os.SEEK_SET)
            return size
        except OSError as e:
            self._errno = e.errno
            return -1

class ConsoleIOHandler(SemihostIOHandler):
    """@brief Simple IO handler for console."""

    def __init__(self, stdin_file, stdout_file=None):
        super().__init__()
        self._stdin_file = stdin_file
        self._stdout_file = stdout_file or stdin_file

    def write(self, fd, ptr, length):
        assert self.agent
        data = self.agent.get_data(ptr, length)
        self._stdout_file.write(data)
        return 0

    def read(self, fd, ptr, length):
        assert self.agent
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
            return ord(data)
        else:
            return -1

class SemihostAgent:
    """@brief Handler for Arm semihosting requests.

    Semihosting requests are made by the target by executing a 'bkpt #0xab' instruction. The
    requested operation is specified by R0 and any arguments by R1. Many requests use a block
    of word-sized arguments pointed to by R1. The return value is passed back to the target
    in R0.

    This class does not handle any file-related requests by itself. It uses I/O handler objects
    passed in to the constructor. The requests handled directly by this class are SYS_CLOCK and
    SYS_TIME.

    There are two types of I/O handlers used by this class. The main I/O handler, set
    with the constructor's @i io_handler parameter, is used for most file operations.
    You may optionally pass another I/O handler for the @i console constructor parameter. The
    console handler is used solely for standard I/O and debug console I/O requests. If no console
    handler is provided, the main handler is used instead. SYS_OPEN requests are not
    passed to the console handler in any event, they are always passed to the main handler.

    If no main I/O handler is provided, the class will use SemihostIOHandler, which causes all
    file I/O requests to be rejected as an error.

    The SemihostAgent assumes standard I/O file descriptor numbers are #STDIN_FD, #STDOUT_FD,
    and #STDERR_FD. When it receives a read or write request for one of these descriptors, it
    passes the request to the console handler. This means the main handler must return these
    numbers for standard I/O open requests (those with a file name of ":tt").

    Not all semihosting requests are supported. Those that are not implemented are:
    - SYS_TMPNAM
    - SYS_SYSTEM
    - SYS_GET_CMDLINE
    - SYS_HEAPINFO
    - SYS_EXIT
    - SYS_ELAPSED
    - SYS_TICKFREQ
    """

    ## Index into this array is the file open mode argument to SYS_OPEN.
    OPEN_MODES = ['r', 'rb', 'r+', 'r+b', 'w', 'wb', 'w+', 'w+b', 'a', 'ab', 'a+', 'a+b']

    EPOCH = datetime.datetime(1970, 1, 1)

    def __init__(
            self,
            context: "DebugContext",
            io_handler: Optional[SemihostIOHandler] = None,
            console: Optional[SemihostIOHandler] = None
        ) -> None:
        self.context = context
        self.start_time = time.time()
        self.io_handler = io_handler or SemihostIOHandler()
        self.io_handler.agent = self
        self.console = console or self.io_handler
        self.console.agent = self

    def check_and_handle_semihost_request(self) -> bool:
        """@brief Handle a semihosting request.

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
        assert isinstance(pc, int)

        # Are we stopped due to one of our own breakpoints?
        # TODO check against watchpoints too!?
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
        assert isinstance(op, int)
        assert isinstance(args, int)

        # Handle request
        handler = self._REQUEST_MAP.get(op, None)
        if handler:
            try:
                result = handler(self, args)
            except NotImplementedError:
                LOG.warning("Semihost: unimplemented request pc=%x r0=%x r1=%x", pc, op, args)
                result = -1
            except (exceptions.Error, OSError) as e:
                LOG.error("Error while handling semihost request: %s", e,
                    exc_info=self.context.session.log_tracebacks)
                result = -1
        else:
            result = -1

        # Set return value.
        self.context.write_core_register('r0', result)

        return True

    def cleanup(self) -> None:
        """@brief Clean up any resources allocated by semihost requests.

        @note May be called more than once.
        """
        self.io_handler.cleanup()
        if self.console is not self.io_handler:
            self.console.cleanup()

    @overload
    def _get_args(self, args_address: int, count: Literal[1]) -> int:
        ...

    @overload
    def _get_args(self, args_address: int, count: int) -> List[int]:
        ...

    def _get_args(self, args_address: int, count):
        args = self.context.read_memory_block32(args_address, count)
        if count == 1:
            return args[0]
        else:
            return args

    def get_data(self, ptr: int, length: Optional[int] = None) -> bytes:
        if length is not None:
            data = self.context.read_memory_block8(ptr, length)
            return bytes(data)

        target_data = b''
        data = b''
        # TODO - use memory map to make sure we don't try to read off the end of memory
        # Limit string size in case it isn't terminated.
        while len(target_data) < MAX_STRING_LENGTH:
            try:
                # Read 32 bytes at a time for efficiency.
                data = self.context.read_memory_block8(ptr, 32)
                terminator = data.index(0)

                # Found a null terminator, append data up to but not including the null
                # and then exit the loop.
                target_data += bytes(data[:terminator])
                break
            except exceptions.TransferError:
                # Failed to read some or all of the string.
                break
            except ValueError:
                # No null terminator was found. Append all of data.
                target_data += bytes(data)
                ptr += 32
        return target_data

    def handle_sys_open(self, args: int) -> int:
        fnptr, mode, fnlen = self._get_args(args, 3)
        if mode >= len(self.OPEN_MODES):
            return -1
        mode = self.OPEN_MODES[mode]

        TRACE.debug("Semihost: open %x/%x, mode %s", fnptr, fnlen, mode)
        return self.io_handler.open(fnptr, fnlen, mode)

    def handle_sys_close(self, args: int) -> int:
        fd = self._get_args(args, 1)
        TRACE.debug("Semihost: close fd=%d", fd)
        return self.io_handler.close(fd)

    def handle_sys_writec(self, args: int) -> int:
        TRACE.debug("Semihost: writec %x", args)
        return self.console.write(STDOUT_FD, args, 1)

    def handle_sys_write0(self, args: int) -> int:
        msg = self.get_data(args)
        TRACE.debug("Semihost: write0 msg='%s'", msg)
        return self.console.write(STDOUT_FD, args, len(msg))

    def handle_sys_write(self, args: int) -> int:
        fd, data_ptr, length = self._get_args(args, 3)
        TRACE.debug("Semihost: write fd=%d ptr=%x len=%d", fd, data_ptr, length)
        if fd in (STDOUT_FD, STDERR_FD):
            return self.console.write(fd, data_ptr, length)
        else:
            return self.io_handler.write(fd, data_ptr, length)

    def handle_sys_read(self, args: int) -> int:
        fd, ptr, length = self._get_args(args, 3)
        TRACE.debug("Semihost: read fd=%d ptr=%x len=%d", fd, ptr, length)
        if fd == STDIN_FD:
            return self.console.read(fd, ptr, length)
        else:
            return self.io_handler.read(fd, ptr, length)

    def handle_sys_readc(self, args: int) -> int:
        TRACE.debug("Semihost: readc")
        return self.console.readc()

    def handle_sys_iserror(self, args: int) -> int:
        raise NotImplementedError()

    def handle_sys_istty(self, args: int) -> int:
        fd = self._get_args(args, 1)
        TRACE.debug("Semihost: istty fd=%d", fd)
        return self.io_handler.istty(fd)

    def handle_sys_seek(self, args: int) -> int:
        fd, pos = self._get_args(args, 2)
        TRACE.debug("Semihost: seek fd=%d pos=%d", fd, pos)
        return self.io_handler.seek(fd, pos)

    def handle_sys_flen(self, args: int) -> int:
        fd = self._get_args(args, 1)
        TRACE.debug("Semihost: flen fd=%d", fd)
        return self.io_handler.flen(fd)

    def handle_sys_tmpnam(self, args: int) -> int:
        raise NotImplementedError()

    def handle_sys_remove(self, args: int) -> int:
        ptr, length = self._get_args(args, 2)
        return self.io_handler.remove(ptr, length)

    def handle_sys_rename(self, args: int) -> int:
        oldptr, oldlength, newptr, newlength = self._get_args(args, 4)
        return self.io_handler.rename(oldptr, oldlength, newptr, newlength)

    def handle_sys_clock(self, args: int) -> int:
        now = time.time()
        delta = now - self.start_time
        return int(delta * 100)

    def handle_sys_time(self, args: int) -> int:
        now = datetime.datetime.now()
        delta = now - self.EPOCH
        seconds = (delta.days * 86400) + delta.seconds
        return seconds

    def handle_sys_system(self, args: int) -> int:
        raise NotImplementedError()

    def handle_sys_errno(self, args: int) -> int:
        return self.io_handler.errno

    def handle_sys_get_cmdline(self, args: int) -> int:
        cmdline = cast(str, self.context.session.options.get('semihost.commandline'))
        if not cmdline:
            return -1

        ptr, length = self._get_args(args, 2)
        cmdline_write_length = min(length - 1, len(cmdline)) # Ensure room for null byte.
        cmdline_bytes = cmdline.encode()[:cmdline_write_length] + b'\x00'
        self.context.write_memory_block8(ptr, cmdline_bytes)
        self.context.write32(args + 4, cmdline_write_length - 1) # TODO resume assumption about pointer size!
        return 0

    def handle_sys_heapinfo(self, args: int) -> int:
        """@brief Stub implementation of SYS_HEAPINFO.

        The args (r1) value is the address of a pointer to a four-word data block, to be filled in
        by the host.

        ```c
        struct block {
            int heap_base;
            int heap_limit;
            int stack_base;
            int stack_limit;
        };
        ```

        This implementation simply fills in the value 0 for each field. Zero is legal, and tells the
        caller that the host was unable to determine the value.
        """
        info_block = self._get_args(args, 1)
        self.context.write_memory_block32(info_block, [0, 0, 0, 0])
        return 0

    def handle_sys_exit(self, args: int) -> int:
        # TODO handle SYS_EXIT for a 'pyocd run' subcommand
        raise NotImplementedError()

    def handle_sys_exit_extended(self, args: int) -> int:
        raise NotImplementedError()

    def handle_sys_elapsed(self, args: int) -> int:
        raise NotImplementedError()

    def handle_sys_tickfreq(self, args: int) -> int:
        raise NotImplementedError()

    _REQUEST_MAP: Dict[int, Callable[["SemihostAgent", int], int]] = {
            SemihostingRequests.SYS_OPEN:            handle_sys_open,
            SemihostingRequests.SYS_CLOSE:           handle_sys_close,
            SemihostingRequests.SYS_WRITEC:          handle_sys_writec,
            SemihostingRequests.SYS_WRITE0:          handle_sys_write0,
            SemihostingRequests.SYS_WRITE:           handle_sys_write,
            SemihostingRequests.SYS_READ:            handle_sys_read,
            SemihostingRequests.SYS_READC:           handle_sys_readc,
            SemihostingRequests.SYS_ISERROR:         handle_sys_iserror,
            SemihostingRequests.SYS_ISTTY:           handle_sys_istty,
            SemihostingRequests.SYS_SEEK:            handle_sys_seek,
            SemihostingRequests.SYS_FLEN:            handle_sys_flen,
            SemihostingRequests.SYS_TMPNAM:          handle_sys_tmpnam,
            SemihostingRequests.SYS_REMOVE:          handle_sys_remove,
            SemihostingRequests.SYS_RENAME:          handle_sys_rename,
            SemihostingRequests.SYS_CLOCK:           handle_sys_clock,
            SemihostingRequests.SYS_TIME:            handle_sys_time,
            SemihostingRequests.SYS_SYSTEM:          handle_sys_system,
            SemihostingRequests.SYS_ERRNO:           handle_sys_errno,
            SemihostingRequests.SYS_GET_CMDLINE:     handle_sys_get_cmdline,
            SemihostingRequests.SYS_HEAPINFO:        handle_sys_heapinfo,
            SemihostingRequests.SYS_EXIT:            handle_sys_exit,
            SemihostingRequests.SYS_EXIT_EXTENDED:   handle_sys_exit_extended,
            SemihostingRequests.SYS_ELAPSED:         handle_sys_elapsed,
            SemihostingRequests.SYS_TICKFREQ:        handle_sys_tickfreq
        }

