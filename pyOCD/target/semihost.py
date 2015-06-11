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

import sys
import pyOCD
#from pyOCD.target import cortex_m #import (DFSR, DFSR_BKPT)
import logging

# bkpt #0xab instruction
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

class SemihostAgent(object):

    # Index into this array is the file open mode argument to TARGET_SYS_OPEN.
    OPEN_MODES = ['r', 'rb', 'r+', 'r+b', 'w', 'wb', 'w+', 'w+b', 'a', 'ab', 'a+', 'a+b']

    def __init__(self, target):
        self.target = target
        self.errno = 0
        self.next_fd = 4

        # Go ahead and "open" standard I/O
        self.open_files = {
                1 : sys.stdin,
                2 : sys.stdout,
                3 : sys.stderr
            }

        self.request_map = {
                TARGET_SYS_OPEN        : self.handle_sys_open,
                TARGET_SYS_CLOSE       : self.handle_sys_close,
                TARGET_SYS_WRITEC      : self.handle_sys_writec,
                TARGET_SYS_WRITE0      : self.handle_sys_write0,
                TARGET_SYS_WRITE       : self.handle_sys_write,
                TARGET_SYS_READ        : self.handle_sys_read,
                TARGET_SYS_READC       : self.handle_sys_readc,
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

    def checkAndHandleBreakpoint(self):
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

        logging.info("Semihost: request pc=%x r0=%x r1=%x", pc, op, args)

        # Handle request
        handler = self.request_map.get(op, None)
        if handler:
            result = handler(args)
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
        while True:
            # Read 32 bytes at a time for efficiency.
            data = self.target.readBlockMemoryUnaligned8(ptr, 32)
            try:
                terminator = data.index(0)
                target_str += str(bytearray(data[:terminator+1]))
                break
            except ValueError:
                # Append all of data.
                target_str += str(bytearray(data))
        return target_str

    def handle_sys_open(self, args):
        arg0, arg1, arg2 = self._get_args(args, 3)
        filename = self._get_string(arg0, arg2)
        if arg1 >= len(self.OPEN_MODES):
            return -1
        mode = self.OPEN_MODES[arg1]

        logging.info("Semihost: open '%s', mode %s", filename, mode)

        # Handle standard I/O.
        if filename == ':tt':
            if mode == 'r':
                fd = 1 # stdin
            elif mode == 'w':
                fd = 2 # stdout
            elif mode == 'a':
                fd = 3 # stderr
            else:
                logging.warning("Unrecognized semihosting console file combination: mode=%s", mode)
                return -1
            return fd

        try:
            fd = self.next_fd
            self.next_fd += 1

            f = file(filename, mode)

            self.open_files[fd] = f

            return fd
        except:
            logging.error("Semihost: failed to open file '%s'", filename)
            return -1

    def handle_sys_close(self, args):
        fd = self._get_args(args, 1)
        logging.debug("Semihost: close fd=%d", fd)
        if fd > 3:
            if not self.open_files.has_key(fd):
                return -1
            f = self.open_files.pop(fd)
            f.close()
        return 0

    def handle_sys_writec(self, args):
        c = chr(self.target.read8(args))
        logging.debug("Semihost: writec c='%s'", c)
        sys.stdout.write(c)
        return 0

    def handle_sys_write0(self, args):
        msg = self._get_string(args)
        logging.debug("Semihost: write0 msg='%s'", msg)
        sys.stdout.write(msg)
        return 0

    def handle_sys_write(self, args):
        fd, data_ptr, length = self._get_args(args, 3)
        logging.debug("Semihost: write fd=%d ptr=%x len=%d", fd, data_ptr, length)
        if not self.open_files.has_key(fd):
            return length
        data = self._get_string(data_ptr, length)
        try:
            self.open_files[fd].write(data)
            return 0
        except IOError, e:
            logging.debug("Semihost: exception: %s", e)
            return -1

    def handle_sys_read(self, args):
        fd, ptr, length = self._get_args(args, 3)
        logging.debug("Semihost: read fd=%d ptr=%x len=%d", fd, ptr, length)
        if not self.open_files.has_key(fd):
            return length
        try:
            data = self.open_files[fd].read(length)
        except IOError, e:
            logging.debug("Semihost: exception: %s", e)
            return -1
        self.target.writeBlockMemoryUnaligned8(ptr, data)
        return length - len(data)

    def handle_sys_readc(self, args):
        logging.debug("Semihost: readc")
        return sys.stdin.read(1)

    def handle_sys_istty(self, args):
        fd = self._get_args(args, 1)
        logging.debug("Semihost: istty fd=%d", fd)
        if not self.open_files.has_key(fd):
            return -1
        return 1 if (0 < fd <= 4) else 0

    def handle_sys_seek(self, args):
        return -1

    def handle_sys_flen(self, args):
        return -1

    def handle_sys_tmpnam(self, args):
        return -1

    def handle_sys_remove(self, args):
        return -1

    def handle_sys_rename(self, args):
        return -1

    def handle_sys_clock(self, args):
        return -1

    def handle_sys_time(self, args):
        return -1

    def handle_sys_system(self, args):
        return -1

    def handle_sys_errno(self, args):
        return self.errno

    def handle_sys_get_cmdline(self, args):
        return -1

    def handle_sys_heapinfo(self, args):
        return -1

    def handle_sys_exit(self, args):
        return -1

    def handle_sys_elapsed(self, args):
        return -1

    def handle_sys_tickfreq(self, args):
        return -1




