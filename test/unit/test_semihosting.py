# pyOCD debugger
# Copyright (c) 2006-2020 Arm Limited
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

from pathlib import Path
import pytest
import os
import logging
# import telnetlib
import six

from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target
from pyocd.debug import semihost
from pyocd.utility.server import StreamServer
from pyocd.utility.timeout import Timeout

@pytest.fixture(scope='module')
def tgt(request):
    session = None
    try:
        session = ConnectHelper.session_with_chosen_probe(blocking=False, return_first=True)
    except Exception as error:
        logging.error("Exception during session_with_chosen_probe", exc_info=error)
    if session is None:
        pytest.skip("No probe present")
        return
    session.open()
    session.options['resume_on_disconnect'] = False
    assert session.target
    session.target.reset_and_halt()

    def close_session():
        session.close()

    request.addfinalizer(close_session)
    return session.target

@pytest.fixture(scope='module')
def ctx(tgt):
    return tgt.get_target_context()

@pytest.fixture(scope='function')
def semihostagent(ctx, request):
    io_handler = semihost.InternalSemihostIOHandler()
    agent = semihost.SemihostAgent(ctx, io_handler)
    def cleanup():
        agent.cleanup()
    request.addfinalizer(cleanup)
    return agent

@pytest.fixture(scope='module')
def ramrgn(tgt):
    map = tgt.get_memory_map()
    for rgn in map:
        if rgn.is_ram:
            return rgn
    pytest.skip("No RAM available to load test")

def run_til_halt(tgt, semihostagent):
    with Timeout(2.0) as t:
        logging.info("Resuming target")
        tgt.resume()

        while True:
            if not t.check():
                tgt.halt()
                return False
            if tgt.get_state() == Target.State.HALTED:
                logging.info("Target halted")
                didHandle = semihostagent.check_and_handle_semihost_request()
                if didHandle:
                    logging.info("Semihost request handled")
                else:
                    logging.info("Non-semihost break")
                return didHandle

NOP = 0x46c0
BKPT_00 = 0xbe00
BKPT_AB = 0xbeab

class RecordingSemihostIOHandler(semihost.SemihostIOHandler):
    """@brief Semihost IO handler that records output.

    This handler is only meant to be used for console I/O since it doesn't implement
    open() or close().
    """
    def __init__(self):
        self._out_data = {}
        self._in_data = {}

    def set_input_data(self, fd, data):
        self._in_data[fd] = data

    def get_output_data(self, fd):
        if fd in self._out_data:
            return self._out_data[fd]
        else:
            return None

    def write(self, fd, ptr, length):
        assert self.agent
        if fd not in self._out_data:
            self._out_data[fd] = b''
        assert self.agent
        s = self.agent.get_data(ptr, length)
        self._out_data[fd] += s
        return 0

    def read(self, fd, ptr, length):
        assert self.agent
        if fd not in self._in_data:
            return length
        d = self._in_data[fd][:length]
        self._in_data[fd] = self._in_data[fd][length:]
        assert self.agent
        self.agent.context.write_memory_block8(ptr, bytearray(six.ensure_binary(d)))
        return length - len(d)

    def readc(self):
        if semihost.STDIN_FD not in self._in_data:
            return -1
        d = self._in_data[semihost.STDIN_FD][:1]
        self._in_data[semihost.STDIN_FD] = self._in_data[semihost.STDIN_FD][1:]
        if len(d):
            return ord(d[0])
        else:
            return -1

class SemihostRequestBuilder:
    """@brief Utility to build code and set registers to perform a semihost request."""
    def __init__(self, tgt, semihostagent, ramrgn):
        self.tgt = tgt
        self.ctx = tgt.get_target_context()
        self.semihostagent = semihostagent
        self.ramrgn = ramrgn

    def set_agent(self, agent):
        self.semihostagent = agent

    def setup_semihost_request(self, rqnum):
        assert self.tgt.get_state() == Target.State.HALTED

        self.ctx.write16(self.ramrgn.start, NOP)
        self.ctx.write16(self.ramrgn.start + 2, BKPT_AB)
        self.ctx.write16(self.ramrgn.start + 4, BKPT_00)

        self.ctx.write_core_register('pc', self.ramrgn.start)
        self.ctx.write_core_register('sp', self.ramrgn.start + 0x100)
        self.ctx.write_core_register('r0', rqnum)
        self.ctx.write_core_register('r1', self.ramrgn.start + 0x200)
        self.ctx.flush()
        return self.ramrgn.start + 0x200

    def do_open(self, filename, mode):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_OPEN)

        # Write filename
        filename = bytearray(six.ensure_binary(filename) + b'\x00')
        self.ctx.write_memory_block8(argsptr + 12, filename)

        self.ctx.write32(argsptr, argsptr + 12) # null terminated filename
        self.ctx.write32(argsptr + 4, semihost.SemihostAgent.OPEN_MODES.index(mode)) # mode
        self.ctx.write32(argsptr + 8, len(filename) - 1) # filename length minus null terminator

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')
        return result

    def do_close(self, fd):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_CLOSE)
        self.ctx.write32(argsptr, fd)

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')
        return result

    def do_write(self, fd, data):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_WRITE)

        # Write data
        data = six.ensure_binary(data)
        self.ctx.write_memory_block8(argsptr + 12, data)

        self.ctx.write32(argsptr, fd) # fd
        self.ctx.write32(argsptr + 4, argsptr + 12) # data
        self.ctx.write32(argsptr + 8, len(data)) # data length
        self.ctx.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')
        return result

    def do_writec(self, c):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_WRITEC)
        self.ctx.write8(argsptr, ord(c))

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')
        return result

    def do_write0(self, data):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_WRITE0)

        data = data + b'\x00'
        self.ctx.write_memory_block8(argsptr, data)

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')
        return result

    def do_read(self, fd, length):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_READ)

        # Clear read buffer.
        self.ctx.write_memory_block8(argsptr + 12, bytearray(b'\x00') * length)

        self.ctx.write32(argsptr, fd) # fd
        self.ctx.write32(argsptr + 4, argsptr + 12) # ptr
        self.ctx.write32(argsptr + 8, length) # data length
        self.ctx.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')

        # Read data put into read buffer.
        data = bytes(self.tgt.read_memory_block8(argsptr + 12, length - result))

        return result, data

    def do_seek(self, fd, pos):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_SEEK)

        self.ctx.write32(argsptr, fd) # fd
        self.ctx.write32(argsptr + 4, pos) # pos
        self.ctx.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')

        return result

    def do_flen(self, fd):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_FLEN)

        self.ctx.write32(argsptr, fd) # fd
        self.ctx.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')

        return result

    def do_istty(self, fd):
        argsptr = self.setup_semihost_request(semihost.SemihostingRequests.SYS_ISTTY)

        self.ctx.write32(argsptr, fd) # fd
        self.ctx.flush()

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')

        return result

    def do_no_args_call(self, rq):
        argsptr = self.setup_semihost_request(rq)
        self.ctx.write_core_register('r1', 0) # r1 must be zero on entry

        was_semihost = run_til_halt(self.tgt, self.semihostagent)
        assert was_semihost

        result = self.ctx.read_core_register('r0')
        return result

@pytest.fixture(scope='function')
def semihost_builder(tgt, semihostagent, ramrgn):
    return SemihostRequestBuilder(tgt, semihostagent, ramrgn)

@pytest.fixture(scope='function')
def console_semihost_builder(semihost_builder):
    console = RecordingSemihostIOHandler()
    agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
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

class TestSemihosting:
    """@brief Tests for semihost requests."""
    def test_open_stdio(self, semihost_builder):
        fd = semihost_builder.do_open(":tt", 'r') # stdin
        assert fd == 0

        fd = semihost_builder.do_open(":tt", 'w') # stdout
        assert fd == 1

        fd = semihost_builder.do_open(":tt", 'a') # stderr
        assert fd == 2

    def test_open_home_file(self, semihost_builder, request):
        testfilepath = Path("~/testfile").expanduser()

        def delete_it():
            try:
                testfilepath.unlink()
            except OSError:
                pass
        request.addfinalizer(delete_it)

        fd = semihost_builder.do_open("~/testfile", 'wb')
        assert fd > 2

        result = semihost_builder.do_write(fd, b"foo")
        assert result == 0

        result = semihost_builder.do_close(fd)
        assert result == 0

        data = testfilepath.read_bytes()
        assert data == b"foo"

    def test_open_close_file(self, semihost_builder, delete_testfile):
        fd = semihost_builder.do_open("testfile", 'w+b')
        assert fd > 2

        result = semihost_builder.do_close(fd)
        assert result == 0

    @pytest.mark.parametrize(("mode", "writeData", "pos", "readLen", "readResult"), [
            ("w+b", b"12345678", 0, 8, 0),                                      # several testcases handling binary data
            ("w+b", b"hi", 0, 2, 0),
            ("w+b", b"hello", 2, 3, 0),
            ("w+b", b"", 0, 4, 4),
            ("w+b", b"abcd", -1, 0, 0),
            ("w+", "", 0, 0, 0),                                                # write strings
            ("w+", "1", 0, 1, 0),
            ("w+", "12", 0, 2, 0),
            ("w+", "123", 0, 3, 0),
            ("w+", "1234", 0, 4, 0),
            ("w+", "Hello this is an extraaaaaaaa long string", 0, 41, 0),      # write a long string
            ("w+", "äöüÄÖÜ😀\u4500", 0, 6*2+4+3, 0),                           # write string with some UTF-8 encodings
        ])
    def test_file_write_read(self, semihost_builder, delete_testfile, mode, writeData, pos, readLen, readResult):
        fd = semihost_builder.do_open("testfile", mode)
        assert fd > 2

        if len(writeData):
            result = semihost_builder.do_write(fd, writeData)
            assert result == 0

            result = semihost_builder.do_flen(fd)
            assert result == len(six.ensure_binary(writeData))

        if pos != -1:
            result = semihost_builder.do_seek(fd, pos)
            assert result == 0

        result, data = semihost_builder.do_read(fd, readLen)
        assert result == readResult
        assert data == six.ensure_binary(writeData[pos:pos + readLen])

        result = semihost_builder.do_close(fd)
        assert result == 0

    def test_console_write(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
        semihost_builder.set_agent(agent)

        result = semihost_builder.do_write(semihost.STDOUT_FD, b'hello world')
        assert result == 0

        assert console.get_output_data(semihost.STDOUT_FD) == b'hello world'

    def test_console_write_binary_pattern(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
        semihost_builder.set_agent(agent)

        binary_pattern = bytes.fromhex('8152666f72706cff08000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000016000000')
        assert len(binary_pattern) == 60
        result = semihost_builder.do_write(semihost.STDOUT_FD, binary_pattern)
        assert result == 0
        assert console.get_output_data(semihost.STDOUT_FD) == binary_pattern

    def test_console_writec(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
        semihost_builder.set_agent(agent)

        for c in 'abcdef':
            result = semihost_builder.do_writec(c)
            assert result == 0

        assert console.get_output_data(semihost.STDOUT_FD) == b'abcdef'

    def test_console_write0(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
        semihost_builder.set_agent(agent)

        result = semihost_builder.do_write0(b'this is a very looooooooooooooooooooooooooooooooooooooooooooong string with more than 32 characters')
        assert result == 0

        assert console.get_output_data(semihost.STDOUT_FD) == b'this is a very looooooooooooooooooooooooooooooooooooooooooooong string with more than 32 characters'

    @pytest.mark.parametrize(("data", "readlen"), [
            (b"12345678", 8),
            (b"hi", 2),
            (b"hello", 3),
            (b"", 4),
            (b"abcd", 0)
        ])
    def test_console_read(self, semihost_builder, data, readlen):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
        semihost_builder.set_agent(agent)

        console.set_input_data(semihost.STDIN_FD, data)

        result, resultData = semihost_builder.do_read(semihost.STDIN_FD, readlen)

        assert result == (readlen - min(readlen, len(data)))

        expectedData = data[:min(len(data), readlen)]
        assert resultData == expectedData

    def test_console_readc(self, semihost_builder):
        console = RecordingSemihostIOHandler()
        agent = semihost.SemihostAgent(semihost_builder.ctx, console=console)
        semihost_builder.set_agent(agent)

        console.set_input_data(semihost.STDIN_FD, 'x')

        result = semihost_builder.do_no_args_call(semihost.SemihostingRequests.SYS_READC)
        assert chr(result) == 'x'

    def test_clock(self, semihost_builder):
        result = semihost_builder.do_no_args_call(semihost.SemihostingRequests.SYS_CLOCK)
        assert result != -1
        assert result != 0
        logging.info("clock = %d cs", result)

        result2 = semihost_builder.do_no_args_call(semihost.SemihostingRequests.SYS_CLOCK)
        assert result2 != -1
        assert result2 != 0
        assert result2 > result
        logging.info("clock = %d cs", result2)

    def test_time(self, semihost_builder):
        result = semihost_builder.do_no_args_call(semihost.SemihostingRequests.SYS_TIME)
        assert result != 0
        logging.info("time = %d sec", result)

    def test_errno_no_err(self, semihost_builder):
        result = semihost_builder.do_no_args_call(semihost.SemihostingRequests.SYS_ERRNO)
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
        assert fd > 2

        result = semihost_builder.do_istty(fd)
        assert result == 0

        result = semihost_builder.do_close(fd)
        assert result == 0

    def test_feature_bits(self, semihost_builder):
        fd = semihost_builder.do_open(":semihosting-features", 'rb')
        assert fd > 2

        # Required requests: SYS_FLEN, SYS_ISTTY, SYS_SEEK, SYS_READ, SYS_CLOSE

        n = semihost_builder.do_flen(fd)
        assert n >= 5 # 4 magic bytes + at least 1 feature flags byte

        result = semihost_builder.do_istty(fd)
        assert result == 0

        result = semihost_builder.do_seek(fd, 0)
        assert result == 0

        # Verify header
        result, data = semihost_builder.do_read(fd, 4)
        assert result == 0
        assert data == b'SHFB'

        result = semihost_builder.do_seek(fd, 4)
        assert result == 0

        # Verify first feature byte.
        result, data = semihost_builder.do_read(fd, 1)
        assert result == 0
        assert (data[0] & 0x3) == 0x02 # Only check feature bits defined at the time this test was written.

        # Seek back to earlier.
        result = semihost_builder.do_seek(fd, 2)
        assert result == 0

        result, data = semihost_builder.do_read(fd, 2)
        assert result == 0
        assert data == b'FB'

        # Close.
        result = semihost_builder.do_close(fd)
        assert result == 0


@pytest.fixture(scope='function')
def telnet_server(request):
    telnet_server = StreamServer(
            0,          # port 0 to automatically allocate a free port
            True,       # local only
            "Semihost", # name
            False,      # is read only
            extra_info="test"
            )
    def stopit():
        telnet_server.stop()
    request.addfinalizer(stopit)
    return telnet_server

@pytest.fixture(scope='function')
def semihost_telnet_agent(ctx, telnet_server, request):
    semihost_console = semihost.ConsoleIOHandler(telnet_server)
    agent = semihost.SemihostAgent(ctx, console=semihost_console)
    def cleanup():
        agent.cleanup()
    request.addfinalizer(cleanup)
    return agent

@pytest.fixture(scope='function')
def semihost_telnet_builder(tgt, semihost_telnet_agent, ramrgn):
    return SemihostRequestBuilder(tgt, semihost_telnet_agent, ramrgn)

# Telnet based tests are commented out for the time being, until they can be rewritten
# to not use the telnetlib package that is now deprecated and will be removed in Python 3.13.

# @pytest.fixture(scope='function')
# def telnet_conn(request, telnet_server):
#     from time import sleep
#     # Sleep for a bit to ensure the semihost telnet server has started up in its own thread.
#     while not telnet_server.is_running:
#         sleep(0.005)
#     telnet = telnetlib.Telnet('localhost', telnet_server.port, 10.0)
#     def cleanup():
#         telnet.close()
#     request.addfinalizer(cleanup)
#     return telnet

# class TestSemihostingTelnet:
#     def test_connect(self, semihost_telnet_builder, telnet_conn):
#         result = semihost_telnet_builder.do_no_args_call(semihost.SemihostingRequests.TARGET_SYS_ERRNO)
#         assert result == 0

#     def test_write(self, semihost_telnet_builder, telnet_conn):
#         result = semihost_telnet_builder.do_write(semihost.STDOUT_FD, b'hello world')
#         assert result == 0

#         index, _, text = telnet_conn.expect([b'hello world'])
#         assert index != -1
#         assert text == b'hello world'

#     def test_writec(self, semihost_telnet_builder, telnet_conn):
#         for c in (bytes([i]) for i in b'xyzzy'):
#             result = semihost_telnet_builder.do_writec(c)
#             assert result == 0

#             index, _, text = telnet_conn.expect([c])
#             assert index != -1
#             assert text == c

#     def test_write0(self, semihost_telnet_builder, telnet_conn):
#         result = semihost_telnet_builder.do_write0(b'hello world')
#         assert result == 0

#         index, _, text = telnet_conn.expect([b'hello world'])
#         assert index != -1
#         assert text == b'hello world'

#     def test_read(self, semihost_telnet_builder, telnet_conn):
#         telnet_conn.write(b'hello world')

#         result, data = semihost_telnet_builder.do_read(semihost.STDIN_FD, 11)
#         assert result == 0
#         assert data == b'hello world'

#     def test_readc(self, semihost_telnet_builder, telnet_conn):
#         telnet_conn.write(b'xyz')

#         for c in 'xyz':
#             rc = semihost_telnet_builder.do_no_args_call(semihost.SemihostingRequests.TARGET_SYS_READC)
#             assert chr(rc) == c

class TestSemihostAgent:
    def test_no_io_handler(self, ctx):
        a = semihost.SemihostAgent(ctx, io_handler=None, console=None)
        assert type(a.io_handler) is semihost.SemihostIOHandler
        assert type(a.console) is semihost.SemihostIOHandler
        assert a.console is a.io_handler

    def test_only_io_handler(self, ctx):
        c = RecordingSemihostIOHandler()
        a = semihost.SemihostAgent(ctx, io_handler=c, console=None)
        assert a.io_handler is c
        assert a.console is c

    def test_only_console(self, ctx):
        c = RecordingSemihostIOHandler()
        a = semihost.SemihostAgent(ctx, io_handler=None, console=c)
        assert type(a.io_handler) is semihost.SemihostIOHandler
        assert a.console is c

@pytest.fixture
def ioh(ctx):
    handler = semihost.SemihostIOHandler()
    agent = semihost.SemihostAgent(ctx, io_handler=handler)
    return handler, agent

class TestSemihostIOHandlerBase:
    @pytest.mark.parametrize(("filename", "mode", "expectedFd"), [
            (":tt", 'r', semihost.STDIN_FD),
            (":tt", 'w', semihost.STDOUT_FD),
            (":tt", 'a', semihost.STDERR_FD),
            (":tt", 'r+b', -1),
            ("somefile", 'r+b', None),
        ])
    def test_std_open(self, ctx, ramrgn, ioh, filename, mode, expectedFd):
        handler, agent = ioh
        ctx.write_memory_block8(ramrgn.start, bytearray(six.ensure_binary(filename) + b'\x00'))
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


