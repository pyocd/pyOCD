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

import pytest
import os
import sys
import logging
import pyOCD
from pyOCD.target.target import Target
from pyOCD.target import semihost
from elapsedtimer import ElapsedTimer
import telnetlib

@pytest.fixture(scope='module', autouse=True)
def debuglog():
    logging.basicConfig(level=logging.DEBUG)

@pytest.fixture(scope='module')
def tgt(request):
    board = None
    try:
        board = pyOCD.board.mbed_board.MbedBoard.chooseBoard(blocking=False, return_first=True)
    except Exception as error:
        pass
    if board is None:
        pytest.skip("No board present")
        return

    board.target.resetStopOnReset()

    def cleanup():
        board.uninit(resume=False)

    request.addfinalizer(cleanup)
    return board.target

@pytest.fixture(scope='function')
def semihostagent(tgt, request):
    io_handler = semihost.InternalSemihostIOHandler()
    agent = semihost.SemihostAgent(tgt, io_handler)
    def cleanup():
        agent.cleanup()
    request.addfinalizer(cleanup)
    return agent

@pytest.fixture(scope='module')
def ramrgn(tgt):
    map = tgt.getMemoryMap()
    for rgn in map:
        if rgn.isRam:
            return rgn
    pytest.fail("No RAM available to load test")

class TimeoutError(RuntimeError):
    pass

def run_til_halt(tgt, semihostagent):
    with ElapsedTimer('run_til_halt', logger=logging.getLogger('root'), loglevel=logging.INFO) as t:
        logging.info("Resuming target")
        tgt.resume()

        try:
            while True:
                if t.elapsed >= 2.0:
                    raise TimeoutError()
                if tgt.getState() == Target.TARGET_HALTED:
                    logging.info("Target halted")
                    didHandle = semihostagent.check_and_handle_semihost_request()
                    if didHandle:
                        logging.info("Semihost request handled")
                    else:
                        logging.info("Non-semihost break")
                    return didHandle
        except TimeoutError:
            tgt.halt()
            return False
        finally:
            assert tgt.getState() == Target.TARGET_HALTED

NOP = 0x46c0
BKPT_00 = 0xbe00
BKPT_AB = 0xbeab

## @brief Semihost IO handler that records output.
#
# This handler is only meant to be used for console I/O since it doesn't implement
# open() or close().
class RecordingSemihostIOHandler(semihost.SemihostIOHandler):
    def __init__(self):
        self._out_data = {}
        self._in_data = {}

    def set_input_data(self, fd, data):
        self._in_data[fd] = data

    def get_output_data(self, fd):
        if self._out_data.has_key(fd):
            return self._out_data[fd]
        else:
            return None

    def write(self, fd, ptr, length):
        if not self._out_data.has_key(fd):
            self._out_data[fd] = ''
        s = self.agent._get_string(ptr, length)
        self._out_data[fd] += s
        return 0

    def read(self, fd, ptr, length):
        if not self._in_data.has_key(fd):
            return length
        d = self._in_data[fd][:length]
        self._in_data[fd] = self._in_data[fd][length:]
        self.agent.target.writeBlockMemoryUnaligned8(ptr, bytearray(d))
        return length - len(d)

    def readc(self):
        if not self._in_data.has_key(semihost.STDIN_FD):
            return -1
        d = self._in_data[semihost.STDIN_FD][:1]
        self._in_data[semihost.STDIN_FD] = self._in_data[semihost.STDIN_FD][1:]
        if len(d):
            return ord(d[0])
        else:
            return -1

## @brief Utility to build code and set registers to perform a semihost request.
class SemihostRequestBuilder:
    def __init__(self, tgt, semihostagent, ramrgn):
        self.tgt = tgt
        self.semihostagent = semihostagent
        self.ramrgn = ramrgn

    def set_agent(self, agent):
        self.semihostagent = agent

    def setup_semihost_request(self, rqnum):
        assert self.tgt.getState() == Target.TARGET_HALTED

        self.tgt.write16(self.ramrgn.start, NOP)
        self.tgt.write16(self.ramrgn.start + 2, BKPT_AB)
        self.tgt.write16(self.ramrgn.start + 4, BKPT_00)

        self.tgt.writeCoreRegister('pc', self.ramrgn.start)
        self.tgt.writeCoreRegister('sp', self.ramrgn.start + 0x100)
        self.tgt.writeCoreRegister('r0', rqnum)
        self.tgt.writeCoreRegister('r1', self.ramrgn.start + 0x200)
        self.tgt.flush()
        return self.ramrgn.start + 0x200

    def do_open(self, filename, mode):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_OPEN)

        # Write filename
        filename = bytearray(filename + '\x00')
        self.tgt.writeBlockMemoryUnaligned8(argsptr + 12, filename)

        self.tgt.write32(argsptr, argsptr + 12) # null terminated filename
        self.tgt.write32(argsptr + 4, semihost.SemihostAgent.OPEN_MODES.index(mode)) # mode
        self.tgt.write32(argsptr + 8, len(filename) - 1) # filename length minus null terminator

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')
        return result

    def do_close(self, fd):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_CLOSE)
        self.tgt.write32(argsptr, fd)

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')
        return result

    def do_write(self, fd, data):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_WRITE)

        # Write data
        self.tgt.writeBlockMemoryUnaligned8(argsptr + 12, bytearray(data))

        self.tgt.write32(argsptr, fd) # fd
        self.tgt.write32(argsptr + 4, argsptr + 12) # data
        self.tgt.write32(argsptr + 8, len(data)) # data length
        self.tgt.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')
        return result

    def do_writec(self, c):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_WRITEC)
        self.tgt.write8(argsptr, ord(c))

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')
        return result

    def do_write0(self, s):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_WRITE0)

        s = bytearray(s + '\x00')
        self.tgt.writeBlockMemoryUnaligned8(argsptr, s)

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')
        return result

    def do_read(self, fd, length):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_READ)

        # Clear read buffer.
        self.tgt.writeBlockMemoryUnaligned8(argsptr + 12, bytearray('\x00') * length)

        self.tgt.write32(argsptr, fd) # fd
        self.tgt.write32(argsptr + 4, argsptr + 12) # ptr
        self.tgt.write32(argsptr + 8, length) # data length
        self.tgt.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')

        # Read data put into read buffer.
        data = str(bytearray(self.tgt.readBlockMemoryUnaligned8(argsptr + 12, length - result)))

        return result, data

    def do_seek(self, fd, pos):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_SEEK)

        self.tgt.write32(argsptr, fd) # fd
        self.tgt.write32(argsptr + 4, pos) # pos
        self.tgt.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')

        return result

    def do_flen(self, fd):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_FLEN)

        self.tgt.write32(argsptr, fd) # fd
        self.tgt.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')

        return result

    def do_istty(self, fd):
        argsptr = self.setup_semihost_request(semihost.TARGET_SYS_ISTTY)

        self.tgt.write32(argsptr, fd) # fd
        self.tgt.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')

        return result

    def do_no_args_call(self, rq):
        argsptr = self.setup_semihost_request(rq)
        self.tgt.writeCoreRegister('r1', 0) # r1 must be zero on entry

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.tgt.readCoreRegister('r0')
        return result

@pytest.fixture(scope='function')
def semihost_builder(tgt, semihostagent, ramrgn):
    return SemihostRequestBuilder(tgt, semihostagent, ramrgn)

@pytest.fixture(scope='function')
def console_semihost_builder(semihost_builder):
    console = RecordingSemihostIOHandler()
    agent = semihost.SemihostAgent(semihost_builder.tgt, console=console)
    semihost_builder.set_agent(agent)
    return semihost_builder

@pytest.fixture
def delete_testfile(request):
    def delete_it():
        try:
            os.remove("testfile")
        except IOError:
            pass
    request.addfinalizer(delete_it)

## @brief Tests for semihost requests.
class TestSemihosting:
    def test_open_stdio(self, semihost_builder):
        fd = semihost_builder.do_open(":tt", 'r') # stdin
        assert fd == 1

        fd = semihost_builder.do_open(":tt", 'w') # stdout
        assert fd == 2

        fd = semihost_builder.do_open(":tt", 'a') # stderr
        assert fd == 3

    def test_open_close_file(self, semihost_builder, delete_testfile):
        fd = semihost_builder.do_open("testfile", 'w+b')
        assert fd != 0 and fd > 3

        result = semihost_builder.do_close(fd)
        assert result == 0

    @pytest.mark.parametrize(("writeData", "pos", "readLen", "readResult"), [
            ("12345678", 0, 8, 0),
            ("hi", 0, 2, 0),
            ("hello", 2, 3, 0),
            ("", 0, 4, 4),
            ("abcd", -1, 0, 0)
        ])
    def test_file_write_read(self, semihost_builder, delete_testfile, writeData, pos, readLen, readResult):
        fd = semihost_builder.do_open("testfile", 'w+b')
        assert fd != 0 and fd > 3

        if len(writeData):
            result = semihost_builder.do_write(fd, writeData)
            assert result == 0

            result = semihost_builder.do_flen(fd)
            assert result == len(writeData)

        if pos != -1:
            result = semihost_builder.do_seek(fd, pos)
            assert result == 0

        result, data = semihost_builder.do_read(fd, readLen)
        assert result == readResult
        assert data == writeData[pos:pos + readLen]

        result = semihost_builder.do_close(fd)
        assert result == 0

    def test_console_write(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.tgt, console=console)
        semihost_builder.set_agent(agent)

        result = semihost_builder.do_write(semihost.STDOUT_FD, 'hello world')
        assert result == 0

        assert console.get_output_data(semihost.STDOUT_FD) == 'hello world'

    def test_console_writec(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.tgt, console=console)
        semihost_builder.set_agent(agent)

        for c in 'abcdef':
            result = semihost_builder.do_writec(c)
            assert result == 0

        assert console.get_output_data(semihost.STDOUT_FD) == 'abcdef'

    def test_console_write0(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.tgt, console=console)
        semihost_builder.set_agent(agent)

        result = semihost_builder.do_write0('this is a string')
        assert result == 0

        assert console.get_output_data(semihost.STDOUT_FD) == 'this is a string'

    @pytest.mark.parametrize(("data", "readlen"), [
            ("12345678", 8),
            ("hi", 2),
            ("hello", 3),
            ("", 4),
            ("abcd", 0)
        ])
    def test_console_read(self, semihost_builder, data, readlen):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.tgt, console=console)
        semihost_builder.set_agent(agent)

        console.set_input_data(semihost.STDIN_FD, data)

        result, resultData = semihost_builder.do_read(semihost.STDIN_FD, readlen)

        assert result == (readlen - min(readlen, len(data)))

        expectedData = data[:min(len(data), readlen)]
        assert resultData == expectedData

    def test_console_readc(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.tgt, console=console)
        semihost_builder.set_agent(agent)

        console.set_input_data(semihost.STDIN_FD, 'x')

        result = semihost_builder.do_no_args_call(semihost.TARGET_SYS_READC)
        assert chr(result) == 'x'

    def test_clock(self, semihost_builder):
        result = semihost_builder.do_no_args_call(semihost.TARGET_SYS_CLOCK)
        assert result != -1
        assert result != 0
        logging.info("clock = %d cs", result)

        result2 = semihost_builder.do_no_args_call(semihost.TARGET_SYS_CLOCK)
        assert result2 != -1
        assert result2 != 0
        assert result2 > result
        logging.info("clock = %d cs", result2)

    def test_time(self, semihost_builder):
        result = semihost_builder.do_no_args_call(semihost.TARGET_SYS_TIME)
        assert result != 0
        logging.info("time = %d sec", result)

    def test_errno_no_err(self, semihost_builder):
        result = semihost_builder.do_no_args_call(semihost.TARGET_SYS_ERRNO)
        assert result == 0

    @pytest.mark.parametrize(("fd"), [
            (semihost.STDIN_FD),
            (semihost.STDOUT_FD),
            (semihost.STDERR_FD),
        ])
    def test_istty_stdio(self, semihost_builder, fd):
        result = semihost_builder.do_istty(fd)
        assert result == 1

    def test_istty_non_stdio(self, semihost_builder, delete_testfile):
        fd = semihost_builder.do_open("testfile", 'w+b')
        assert fd != 0 and fd > 3

        result = semihost_builder.do_istty(fd)
        assert result == 0

        result = semihost_builder.do_close(fd)
        assert result == 0

@pytest.fixture(scope='function')
def telnet(request):
    telnet = semihost.TelnetSemihostIOHandler(4444)
    def stopit():
        telnet.stop()
    request.addfinalizer(stopit)
    return telnet

@pytest.fixture(scope='function')
def semihost_telnet_agent(tgt, telnet, request):
    agent = semihost.SemihostAgent(tgt, console=telnet)
    def cleanup():
        agent.cleanup()
    request.addfinalizer(cleanup)
    return agent

@pytest.fixture(scope='function')
def semihost_telnet_builder(tgt, semihost_telnet_agent, ramrgn):
    return SemihostRequestBuilder(tgt, semihost_telnet_agent, ramrgn)

@pytest.fixture(scope='function')
def telnet_conn(request):
    telnet = telnetlib.Telnet('localhost', 4444, 1.0)
    def cleanup():
        telnet.close()
    request.addfinalizer(cleanup)
    return telnet

class TestSemihostingTelnet:
    def test_connect(self, semihost_telnet_builder, telnet_conn):
        result = semihost_telnet_builder.do_no_args_call(semihost.TARGET_SYS_ERRNO)
        assert result == 0

    def test_write(self, semihost_telnet_builder, telnet_conn):
        result = semihost_telnet_builder.do_write(semihost.STDOUT_FD, 'hello world')
        assert result == 0

        index, _, text = telnet_conn.expect(['hello world'])
        assert index != -1
        assert text == 'hello world'

    def test_writec(self, semihost_telnet_builder, telnet_conn):
        for c in 'xyzzy':
            result = semihost_telnet_builder.do_writec(c)
            assert result == 0

            index, _, text = telnet_conn.expect([c])
            assert index != -1
            assert text == c

    def test_write0(self, semihost_telnet_builder, telnet_conn):
        result = semihost_telnet_builder.do_write0('hello world')
        assert result == 0

        index, _, text = telnet_conn.expect(['hello world'])
        assert index != -1
        assert text == 'hello world'

    def test_read(self, semihost_telnet_builder, telnet_conn):
        telnet_conn.write('hello world')

        result, data = semihost_telnet_builder.do_read(semihost.STDIN_FD, 11)
        assert result == 0
        assert data == 'hello world'

    def test_readc(self, semihost_telnet_builder, telnet_conn):
        telnet_conn.write('xyz')

        for c in 'xyz':
            rc = semihost_telnet_builder.do_no_args_call(semihost.TARGET_SYS_READC)
            assert chr(rc) == c

class TestSemihostAgent:
    def test_no_io_handler(self, tgt):
        a = semihost.SemihostAgent(tgt, io_handler=None, console=None)
        assert type(a.io_handler) is semihost.SemihostIOHandler
        assert type(a.console) is semihost.SemihostIOHandler
        assert a.console is a.io_handler

    def test_only_io_handler(self, tgt):
        c = RecordingSemihostIOHandler()
        a = semihost.SemihostAgent(tgt, io_handler=c, console=None)
        assert a.io_handler is c
        assert a.console is c

    def test_only_console(self, tgt):
        c = RecordingSemihostIOHandler()
        a = semihost.SemihostAgent(tgt, io_handler=None, console=c)
        assert type(a.io_handler) is semihost.SemihostIOHandler
        assert a.console is c

@pytest.fixture
def ioh(tgt):
    handler = semihost.SemihostIOHandler()
    agent = semihost.SemihostAgent(tgt, io_handler=handler)
    return handler, agent

class TestSemihostIOHandlerBase:
    @pytest.mark.parametrize(("filename", "mode", "expectedFd"), [
            (":tt", 'r', semihost.STDIN_FD),
            (":tt", 'w', semihost.STDOUT_FD),
            (":tt", 'a', semihost.STDERR_FD),
            (":tt", 'r+b', -1),
            ("somefile", 'r+b', None),
        ])
    def test_std_open(self, tgt, ramrgn, ioh, filename, mode, expectedFd):
        handler, agent = ioh
        tgt.writeBlockMemoryUnaligned8(ramrgn.start, bytearray(filename) + bytearray('\x00'))
        assert handler._std_open(ramrgn.start, len(filename), mode) == (expectedFd, filename)

    @pytest.mark.parametrize(("op", "args"), [
            ('open', (0, 0, 'r')),
            ('close', (1,)),
            ('write', (1, 0, 0)),
            ('read', (1, 0, 0)),
            ('readc', tuple()),
            ('istty', (1,)),
            ('seek', (1, 0)),
            ('flen', (1,)),
            ('remove', (0, 0)),
            ('rename', (0, 0, 0, 0)),
        ])
    def test_unimplemented(self, op, args):
        handler = semihost.SemihostIOHandler()
        with pytest.raises(NotImplementedError):
            handler.__getattribute__(op)(*args)


