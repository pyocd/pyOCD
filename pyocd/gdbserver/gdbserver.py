"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2018 ARM Limited

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

from ..core import exceptions
from ..core.target import Target
from ..utility.cmdline import convert_vector_catch
from ..utility.conversion import (hex_to_byte_list, hex_encode, hex_decode, hex8_to_u32le)
from ..utility.progress import print_progress
from ..utility.py3_helpers import (iter_single_bytes, to_bytes_safe)
from .gdb_socket import GDBSocket
from .gdb_websocket import GDBWebSocket
from .syscall import GDBSyscallIOHandler
from ..debug import semihost
from ..debug.cache import MemoryAccessError
from .context_facade import GDBDebugContextFacade
from .symbols import GDBSymbolProvider
from ..rtos import RTOS
from . import signals
import logging, threading, socket
from struct import unpack
from time import (sleep, time)
import sys
import traceback
import six
from six.moves import queue
from xml.etree.ElementTree import (Element, SubElement, tostring)

CTRL_C = b'\x03'

# Logging options. Set to True to enable.
LOG_MEM = False # Log memory accesses.
LOG_ACK = False # Log ack or nak.
LOG_PACKETS = False # Log all packets sent and received.

def checksum(data):
    return ("%02x" % (sum(six.iterbytes(data)) % 256)).encode()

## @brief De-escapes binary data from Gdb.
#
# @param data Bytes-like object with possibly escaped values.
# @return List of integers in the range 0-255, with all escaped bytes de-escaped.
def unescape(data):
    data_idx = 0

    # unpack the data into binary array
    str_unpack = str(len(data)) + 'B'
    data = unpack(str_unpack, data)
    data = list(data)

    # check for escaped characters
    while data_idx < len(data):
        if data[data_idx] == 0x7d:
            data.pop(data_idx)
            data[data_idx] = data[data_idx] ^ 0x20
        data_idx += 1

    return data

## @brief Escape binary data to be sent to Gdb.
#
# @param data Bytes-like object containing raw binary.
# @return Bytes object with the characters in '#$}*' escaped as required by Gdb.
def escape(data):
    result = b''
    for c in iter_single_bytes(data):
        if c in b'#$}*':
            result += b'}' + six.int2byte(six.byte2int(c) ^ 0x20)
        else:
            result += c
    return result

## @brief Exception used to signal the GDB server connection closed.
class ConnectionClosedException(Exception):
    pass

## @brief Packet I/O thread.
#
# This class is a thread used by the GDBServer class to perform all RSP packet I/O. It
# handles verifying checksums, acking, and receiving Ctrl-C interrupts. There is a queue
# for received packets. The interface to this queue is the receive() method. The send()
# method writes outgoing packets to the socket immediately.
class GDBServerPacketIOThread(threading.Thread):
    def __init__(self, abstract_socket):
        super(GDBServerPacketIOThread, self).__init__(name="gdb-packet-thread")
        self.log = logging.getLogger('gdbpacket.%d' % abstract_socket.port)
        self._abstract_socket = abstract_socket
        self._receive_queue = queue.Queue()
        self._shutdown_event = threading.Event()
        self.interrupt_event = threading.Event()
        self.send_acks = True
        self._clear_send_acks = False
        self._buffer = b''
        self._expecting_ack = False
        self.drop_reply = False
        self._last_packet = b''
        self._closed = False
        self.setDaemon(True)
        self.start()

    def set_send_acks(self, ack):
        if ack:
            self.send_acks = True
        else:
            self._clear_send_acks = True

    def stop(self):
        self._shutdown_event.set()

    def send(self, packet):
        if self._closed or not packet:
            return
        if not self.drop_reply:
            self._last_packet = packet
            self._write_packet(packet)
        else:
            self.drop_reply = False
            self.log.debug("GDB dropped reply %s", packet)

    def receive(self, block=True):
        if self._closed:
            raise ConnectionClosedException()
        while True:
            try:
                # If block is false, we'll get an Empty exception immediately if there
                # are no packets in the queue. Same if block is true and it times out
                # waiting on an empty queue.
                return self._receive_queue.get(block, 0.1)
            except queue.Empty:
                # Only exit the loop if block is false or connection closed.
                if not block:
                    return None
                if self._closed:
                    raise ConnectionClosedException()

    def run(self):
        self._abstract_socket.set_timeout(0.01)

        while not self._shutdown_event.is_set():
            try:
                data = self._abstract_socket.read()

                # Handle closed connection
                if len(data) == 0:
                    self.log.debug("GDB packet thread: other side closed connection")
                    self._closed = True
                    break

                if LOG_PACKETS:
                    self.log.debug('-->>>>>>>>>>>> GDB read %d bytes: %s', len(data), data)

                self._buffer += data
            except socket.error:
                pass

            if self._shutdown_event.is_set():
                break

            self._process_data()

        self.log.debug("GDB packet thread stopping")

    def _write_packet(self, packet):
        if LOG_PACKETS:
            self.log.debug('--<<<<<<<<<<<< GDB send %d bytes: %s', len(packet), packet)

        # Make sure the entire packet is sent.
        remaining = len(packet)
        while remaining:
            written = self._abstract_socket.write(packet)
            remaining -= written
            if remaining:
                packet = packet[written:]

        if self.send_acks:
            self._expecting_ack = True

    def _check_expected_ack(self):
        # Handle expected ack.
        c = self._buffer[0:1]
        if c in (b'+', b'-'):
            self._buffer = self._buffer[1:]
            if LOG_ACK:
                self.log.debug('got ack: %s', c)
            if c == '-':
                # Handle nack from gdb
                self._write_packet(self._last_packet)
                return

            # Handle disabling of acks.
            if self._clear_send_acks:
                self.send_acks = False
                self._clear_send_acks = False
        else:
            self.log.debug("GDB: expected n/ack but got '%s'", c)

    def _process_data(self):
        # Process all incoming data until there are no more complete packets.
        while len(self._buffer):
            if self._expecting_ack:
                self._expecting_ack = False
                self._check_expected_ack()

            # Check for a ctrl-c.
            if len(self._buffer) and self._buffer[0:1] == CTRL_C:
                self.interrupt_event.set()
                self._buffer = self._buffer[1:]

            try:
                # Look for complete packet and extract from buffer.
                pkt_begin = self._buffer.index(b"$")
                pkt_end = self._buffer.index(b"#") + 2
                if pkt_begin >= 0 and pkt_end < len(self._buffer):
                    pkt = self._buffer[pkt_begin:pkt_end + 1]
                    self._buffer = self._buffer[pkt_end + 1:]
                    self._handling_incoming_packet(pkt)
                else:
                    break
            except ValueError:
                # No complete packet received yet.
                break

    def _handling_incoming_packet(self, packet):
        # Compute checksum
        data, cksum = packet[1:].split(b'#')
        computedCksum = checksum(data)
        goodPacket = (computedCksum.lower() == cksum.lower())

        if self.send_acks:
            ack = b'+' if goodPacket else b'-'
            self._abstract_socket.write(ack)
            if LOG_ACK:
                self.log.debug(ack)

        if goodPacket:
            self._receive_queue.put(packet)

class GDBServer(threading.Thread):
    """
    This class start a GDB server listening a gdb connection on a specific port.
    It implements the RSP (Remote Serial Protocol).
    """
    def __init__(self, board, port_urlWSS, options={}, core=None):
        threading.Thread.__init__(self)
        self.board = board
        if core is None:
            self.core = 0
            self.target = board.target
        else:
            self.core = core
            self.target = board.target.cores[core]
        self.log = logging.getLogger('gdbserver')
        self.flash = board.flash
        self.abstract_socket = None
        self.wss_server = None
        self.port = 0
        if isinstance(port_urlWSS, str) == True:
            self.wss_server = port_urlWSS
        else:
            self.port = port_urlWSS
        self.vector_catch = options.get('vector_catch', Target.CATCH_HARD_FAULT)
        self.target.set_vector_catch(self.vector_catch)
        self.step_into_interrupt = options.get('step_into_interrupt', False)
        self.persist = options.get('persist', False)
        self.soft_bkpt_as_hard = options.get('soft_bkpt_as_hard', False)
        self.chip_erase = options.get('chip_erase', None)
        self.hide_programming_progress = options.get('hide_programming_progress', False)
        self.fast_program = options.get('fast_program', False)
        self.enable_semihosting = options.get('enable_semihosting', False)
        self.semihost_console_type = options.get('semihost_console_type', 'telnet')
        self.telnet_port = options.get('telnet_port', 4444)
        self.semihost_use_syscalls = options.get('semihost_use_syscalls', False)
        self.server_listening_callback = options.get('server_listening_callback', None)
        self.serve_local_only = options.get('serve_local_only', True)
        self.packet_size = 2048
        self.packet_io = None
        self.gdb_features = []
        self.non_stop = False
        self.is_target_running = (self.target.get_state() == Target.TARGET_RUNNING)
        self.flash_builder = None
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.detach_event = threading.Event()
        if core is None:
            self.target_context = self.board.target.get_target_context()
        else:
            self.target_context = self.board.target.get_target_context(core=core)
        self.target_facade = GDBDebugContextFacade(self.target_context)
        self.thread_provider = None
        self.did_init_thread_providers = False
        self.current_thread_id = 0
        self.first_run_after_reset_or_flash = True
        if self.wss_server == None:
            self.abstract_socket = GDBSocket(self.port, self.packet_size)
            if self.serve_local_only:
                self.abstract_socket.host = 'localhost'
        else:
            self.abstract_socket = GDBWebSocket(self.wss_server)

        self.target.subscribe(Target.EVENT_POST_RESET, self.event_handler)

        # Init semihosting and telnet console.
        if self.semihost_use_syscalls:
            semihost_io_handler = GDBSyscallIOHandler(self)
        else:
            # Use internal IO handler.
            semihost_io_handler = semihost.InternalSemihostIOHandler()

        if self.semihost_console_type == 'telnet':
            self.telnet_console = semihost.TelnetSemihostIOHandler(self.telnet_port, self.serve_local_only)
            semihost_console = self.telnet_console
        else:
            self.log.info("Semihosting will be output to console")
            self.telnet_console = None
            semihost_console = semihost_io_handler
        self.semihost = semihost.SemihostAgent(self.target_context, io_handler=semihost_io_handler, console=semihost_console)

        # pylint: disable=invalid-name
        
        # Command handler table.
        #
        # The dict keys are the first character of the incoming command from gdb. Values are a
        # bi-tuple. The first element is the handler method, and the second element is the start
        # offset of the command string passed to the handler.
        #
        # Start offset values:
        #  0 - Special case: handler method does not take any parameters.
        #  1 - Strip off leading "$" from command.
        #  2 - Strip leading "$" plus character matched through this table.
        #  3+ - Supported, but not very useful.
        #
        self.COMMANDS = {
        #       CMD    HANDLER                   START    DESCRIPTION
                b'?' : (self.stop_reason_query,  0   ), # Stop reason query.
                b'c' : (self.resume,             1   ), # Continue (at addr)
                b'C' : (self.resume,             1   ), # Continue with signal.
                b'D' : (self.detach,             1   ), # Detach.
                b'g' : (self.get_registers,      0   ), # Read general registers.
                b'G' : (self.set_registers,      2   ), # Write general registers.
                b'H' : (self.set_thread,         2   ), # Set thread for subsequent operations.
                b'k' : (self.kill,               0   ), # Kill.
                b'm' : (self.get_memory,         2   ), # Read memory.
                b'M' : (self.write_memory_hex,   2   ), # Write memory (hex).
                b'p' : (self.read_register,      2   ), # Read register.
                b'P' : (self.write_register,     2   ), # Write register.
                b'q' : (self.handle_query,       2   ), # General query.
                b'Q' : (self.handle_general_set, 2   ), # General set.
                b's' : (self.step,               1   ), # Single step.
                b'S' : (self.step,               1   ), # Step with signal.
                b'T' : (self.is_thread_alive,    1   ), # Thread liveness query.
                b'v' : (self.v_command,          2   ), # v command.
                b'X' : (self.write_memory,       2   ), # Write memory (binary).
                b'z' : (self.breakpoint,         1   ), # Insert breakpoint/watchpoint.
                b'Z' : (self.breakpoint,         1   ), # Remove breakpoint/watchpoint.
            }

        # Commands that kill the connection to gdb.
        self.DETACH_COMMANDS = (b'D', b'k')

        # pylint: enable=invalid-name

        self.setDaemon(True)
        self.start()

    def restart(self):
        if self.isAlive():
            self.detach_event.set()

    def stop(self):
        if self.isAlive():
            self.shutdown_event.set()
            while self.isAlive():
                pass
            self.log.info("GDB server thread killed")
        self.board.uninit()

    def set_board(self, board, stop=True):
        self.lock.acquire()
        if stop:
            self.restart()
        self.board = board
        self.target = board.target
        self.flash = board.flash
        self.lock.release()
        return

    def _cleanup(self):
        self.log.debug("GDB server cleaning up")
        if self.packet_io:
            self.packet_io.stop()
            self.packet_io = None
        if self.semihost:
            self.semihost.cleanup()
            self.semihost = None
        if self.telnet_console:
            self.telnet_console.stop()
            self.telnet_console = None

    def _cleanup_for_next_connection(self):
        self.non_stop = False
        self.thread_provider = None
        self.did_init_thread_providers = False
        self.current_thread_id = 0

    def run(self):
        self.log.info('GDB server started at port:%d', self.port)

        while True:
            try:
                self.detach_event.clear()

                # Inform callback that the server is running.
                if self.server_listening_callback:
                    self.server_listening_callback(self)

                while not self.shutdown_event.isSet() and not self.detach_event.isSet():
                    connected = self.abstract_socket.connect()
                    if connected != None:
                        self.packet_io = GDBServerPacketIOThread(self.abstract_socket)
                        break

                if self.shutdown_event.isSet():
                    self._cleanup()
                    return

                if self.detach_event.isSet():
                    continue

                self.log.info("One client connected!")
                self._run_connection()

            except Exception as e:
                self.log.error("Unexpected exception: %s", e)
                traceback.print_exc()

    def _run_connection(self):
        while True:
            try:
                if self.shutdown_event.isSet():
                    self._cleanup()
                    return

                if self.detach_event.isSet():
                    break

                if self.packet_io.interrupt_event.isSet():
                    if self.non_stop:
                        self.target.halt()
                        self.is_target_running = False
                        self.send_stop_notification()
                    else:
                        self.log.error("Got unexpected ctrl-c, ignoring")
                    self.packet_io.interrupt_event.clear()

                if self.non_stop and self.is_target_running:
                    try:
                        if self.target.get_state() == Target.TARGET_HALTED:
                            self.log.debug("state halted")
                            self.is_target_running = False
                            self.send_stop_notification()
                    except Exception as e:
                        self.log.error("Unexpected exception: %s", e)
                        traceback.print_exc()

                # read command
                try:
                    packet = self.packet_io.receive(block=not self.non_stop)
                except ConnectionClosedException:
                    break

                if self.shutdown_event.isSet():
                    self._cleanup()
                    return

                if self.detach_event.isSet():
                    break

                if self.non_stop and packet is None:
                    sleep(0.1)
                    continue

                self.lock.acquire()

                if len(packet) != 0:
                    # decode and prepare resp
                    resp, detach = self.handle_message(packet)

                    if resp is not None:
                        # send resp
                        self.packet_io.send(resp)

                    if detach:
                        self.abstract_socket.close()
                        self.packet_io.stop()
                        self.packet_io = None
                        self.lock.release()
                        if self.persist:
                            self._cleanup_for_next_connection()
                            break
                        else:
                            self.shutdown_event.set()
                            return

                self.lock.release()

            except Exception as e:
                self.log.error("Unexpected exception: %s", e)
                traceback.print_exc()

    def handle_message(self, msg):
        try:
            assert msg[0:1] == b'$', "invalid first char of message != $"

            try:
                handler, msgStart = self.COMMANDS[msg[1:2]]
            except (KeyError, IndexError):
                self.log.error("Unknown RSP packet: %s", msg)
                return self.create_rsp_packet(b""), 0

            if msgStart == 0:
                reply = handler()
            else:
                reply = handler(msg[msgStart:])
            detach = 1 if msg[1:2] in self.DETACH_COMMANDS else 0
            return reply, detach

        except Exception as e:
            self.log.error("Unhandled exception in handle_message: %s", e)
            traceback.print_exc()
            return self.create_rsp_packet(b"E01"), 0

    def detach(self, data):
        self.log.info("Client detached")
        resp = b"OK"
        return self.create_rsp_packet(resp)

    def kill(self):
        self.log.debug("GDB kill")
        # Keep target halted and leave vector catches if in persistent mode.
        if not self.persist:
            self.board.target.set_vector_catch(Target.CATCH_NONE)
            self.board.target.resume()
        return self.create_rsp_packet(b"")

    def breakpoint(self, data):
        # handle breakpoint/watchpoint commands
        split = data.split(b'#')[0].split(b',')
        addr = int(split[1], 16)
        self.log.debug("GDB breakpoint %s%d @ %x" % (data[0:1], int(data[1:2]), addr))

        # handle software breakpoint Z0/z0
        if data[1:2] == b'0' and not self.soft_bkpt_as_hard:
            if data[0:1] == b'Z':
                if not self.target.set_breakpoint(addr, Target.BREAKPOINT_SW):
                    return self.create_rsp_packet(b'E01') #EPERM
            else:
                self.target.remove_breakpoint(addr)
            return self.create_rsp_packet(b"OK")

        # handle hardware breakpoint Z1/z1
        if data[1:2] == b'1' or (self.soft_bkpt_as_hard and data[1:2] == b'0'):
            if data[0:1] == b'Z':
                if self.target.set_breakpoint(addr, Target.BREAKPOINT_HW) == False:
                    return self.create_rsp_packet(b'E01') #EPERM
            else:
                self.target.remove_breakpoint(addr)
            return self.create_rsp_packet(b"OK")

        # handle hardware watchpoint Z2/z2/Z3/z3/Z4/z4
        if data[1:2] == b'2':
            # Write-only watch
            watchpoint_type = Target.WATCHPOINT_WRITE
        elif data[1:2] == b'3':
            # Read-only watch
            watchpoint_type = Target.WATCHPOINT_READ
        elif data[1:2] == b'4':
            # Read-Write watch
            watchpoint_type = Target.WATCHPOINT_READ_WRITE
        else:
            return self.create_rsp_packet(b'E01') #EPERM

        size = int(split[2], 16)
        if data[0:1] == b'Z':
            if self.target.set_watchpoint(addr, size, watchpoint_type) == False:
                return self.create_rsp_packet(b'E01') #EPERM
        else:
            self.target.remove_watchpoint(addr, size, watchpoint_type)
        return self.create_rsp_packet(b"OK")

    def set_thread(self, data):
        if not self.is_threading_enabled():
            return self.create_rsp_packet(b'OK')

        self.log.debug("set_thread:%s", data)
        op = data[0:1]
        thread_id = int(data[1:-3], 16)
        if not (thread_id in (0, -1) or self.thread_provider.is_valid_thread_id(thread_id)):
            return self.create_rsp_packet(b'E01')

        if op == b'c':
            pass
        elif op == b'g':
            if thread_id == -1:
                self.target_facade.set_context(self.target_context)
            else:
                if thread_id == 0:
                    thread = self.thread_provider.current_thread
                    thread_id = thread.unique_id
                else:
                    thread = self.thread_provider.get_thread(thread_id)
                self.target_facade.set_context(thread.context)
        else:
            return self.create_rsp_packet(b'E01')

        self.current_thread_id = thread_id
        return self.create_rsp_packet(b'OK')

    def is_thread_alive(self, data):
        threadId = int(data[1:-3], 16)

        if self.is_threading_enabled():
            isAlive = self.thread_provider.is_valid_thread_id(threadId)
        else:
            isAlive = (threadId == 1)

        if isAlive:
            return self.create_rsp_packet(b'OK')
        else:
            self.validate_debug_context()
            return self.create_rsp_packet(b'E00')

    def validate_debug_context(self):
        if self.is_threading_enabled():
            currentThread = self.thread_provider.current_thread
            if self.current_thread_id != currentThread.unique_id:
                self.target_facade.set_context(currentThread.context)
                self.current_thread_id = currentThread.unique_id
        else:
            if self.current_thread_id != 1:
                self.log.debug("Current thread %x is no longer valid, switching context to target", self.current_thread_id)
                self.target_facade.set_context(self.target_context)
                self.current_thread_id = 1

    def stop_reason_query(self):
        # In non-stop mode, if no threads are stopped we need to reply with OK.
        if self.non_stop and self.is_target_running:
            return self.create_rsp_packet(b"OK")

        return self.create_rsp_packet(self.get_t_response())

    def _get_resume_step_addr(self, data):
        if data is None:
            return None
        data = data.split(b'#')[0]
        if b';' not in data:
            return None
        # c[;addr]
        if data[0:1] in (b'c', b's'):
            addr = int(data[2:], base=16)
        # Csig[;addr]
        elif data[0:1] in (b'C', b'S'):
            addr = int(data[1:].split(b';')[1], base=16)
        return addr

    def resume(self, data):
        addr = self._get_resume_step_addr(data)
        self.target.resume()
        self.log.debug("target resumed")

        if self.first_run_after_reset_or_flash:
            self.first_run_after_reset_or_flash = False
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = True

        val = b''

        while True:
            if self.shutdown_event.isSet():
                self.packet_io.interrupt_event.clear()
                return self.create_rsp_packet(val)

            # Wait for a ctrl-c to be received.
            if self.packet_io.interrupt_event.wait(0.01):
                self.log.debug("receive CTRL-C")
                self.packet_io.interrupt_event.clear()
                self.target.halt()
                val = self.get_t_response(forceSignal=signals.SIGINT)
                break

            try:
                if self.target.get_state() == Target.TARGET_HALTED:
                    # Handle semihosting
                    if self.enable_semihosting:
                        was_semihost = self.semihost.check_and_handle_semihost_request()

                        if was_semihost:
                            self.target.resume()
                            continue

                    pc = self.target_context.read_core_register('pc')
                    self.log.debug("state halted; pc=0x%08x", pc)
                    val = self.get_t_response()
                    break
            except Exception as e:
                try:
                    self.target.halt()
                except:
                    pass
                traceback.print_exc()
                self.log.debug('Target is unavailable temporarily.')
                val = ('S%02x' % self.target_facade.get_signal_value()).encode()
                break

        return self.create_rsp_packet(val)

    def step(self, data):
        addr = self._get_resume_step_addr(data)
        self.log.debug("GDB step: %s", data)
        self.target.step(not self.step_into_interrupt)
        return self.create_rsp_packet(self.get_t_response())

    def halt(self):
        self.target.halt()
        return self.create_rsp_packet(self.get_t_response())

    def send_stop_notification(self, forceSignal=None):
        data = self.get_t_response(forceSignal=forceSignal)
        packet = b'%Stop:' + data + b'#' + checksum(data)
        self.packet_io.send(packet)

    def v_command(self, data):
        cmd = data.split(b'#')[0]

        # Flash command.
        if cmd.startswith(b'Flash'):
            return self.flash_op(data)

        # v_cont capabilities query.
        elif b'Cont?' == cmd:
            return self.create_rsp_packet(b"v_cont;c;C;s;S;t")

        # v_cont, thread action command.
        elif cmd.startswith(b'Cont'):
            return self.v_cont(cmd)

        # vStopped, part of thread stop state notification sequence.
        elif b'Stopped' in cmd:
            # Because we only support one thread for now, we can just reply OK to vStopped.
            return self.create_rsp_packet(b"OK")

        return self.create_rsp_packet(b"")

    # Example: $v_cont;s:1;c#c1
    def v_cont(self, cmd):
        ops = cmd.split(b';')[1:] # split and remove 'Cont' from list
        if not ops:
            return self.create_rsp_packet(b"OK")

        if self.is_threading_enabled():
            thread_actions = {}
            threads = self.thread_provider.get_threads()
            for k in threads:
                thread_actions[k.unique_id] = None
            currentThread = self.thread_provider.get_current_thread_id()
        else:
            thread_actions = { 1 : None } # our only thread
            currentThread = 1
        default_action = None

        for op in ops:
            args = op.split(b':')
            action = args[0]
            if len(args) > 1:
                thread_id = int(args[1], 16)
                if thread_id == -1 or thread_id == 0:
                    thread_id = currentThread
                thread_actions[thread_id] = action
            else:
                default_action = action

        self.log.debug("thread_actions=%s; default_action=%s", repr(thread_actions), default_action)

        # Only the current thread is supported at the moment.
        if thread_actions[currentThread] is None:
            if default_action is None:
                return self.create_rsp_packet(b'E01')
            thread_actions[currentThread] = default_action

        if thread_actions[currentThread][0:1] in (b'c', b'C'):
            if self.non_stop:
                self.target.resume()
                self.is_target_running = True
                return self.create_rsp_packet(b"OK")
            else:
                return self.resume(None)
        elif thread_actions[currentThread][0:1] in (b's', b'S'):
            if self.non_stop:
                self.target.step(not self.step_into_interrupt)
                self.packet_io.send(self.create_rsp_packet(b"OK"))
                self.send_stop_notification()
                return None
            else:
                return self.step(None)
        elif thread_actions[currentThread] == b't':
            # Must ignore t command in all-stop mode.
            if not self.non_stop:
                return self.create_rsp_packet(b"")
            self.packet_io.send(self.create_rsp_packet(b"OK"))
            self.target.halt()
            self.is_target_running = False
            self.send_stop_notification(forceSignal=0)
        else:
            self.log.error("Unsupported v_cont action '%s'" % thread_actions[1:2])

    def flash_op(self, data):
        ops = data.split(b':')[0]
        self.log.debug("flash op: %s", ops)

        if ops == b'FlashErase':
            return self.create_rsp_packet(b"OK")

        elif ops == b'FlashWrite':
            write_addr = int(data.split(b':')[1], 16)
            self.log.debug("flash write addr: 0x%x", write_addr)
            # search for second ':' (beginning of data encoded in the message)
            second_colon = 0
            idx_begin = 0
            while second_colon != 2:
                if data[idx_begin:idx_begin+1] == b':':
                    second_colon += 1
                idx_begin += 1

            # Get flash builder if there isn't one already
            if self.flash_builder is None:
                self.flash_builder = self.flash.get_flash_builder()

            # Add data to flash builder
            self.flash_builder.add_data(write_addr, unescape(data[idx_begin:len(data) - 3]))

            return self.create_rsp_packet(b"OK")

        # we need to flash everything
        elif b'FlashDone' in ops :
            # Only program if we received data.
            if self.flash_builder is not None:
                if self.hide_programming_progress:
                    progress_cb = None
                else:
                    progress_cb = print_progress()

                self.flash_builder.program(chip_erase=self.chip_erase, progress_cb=progress_cb, fast_verify=self.fast_program)

                # Set flash builder to None so that on the next flash command a new
                # object is used.
                self.flash_builder = None

            self.first_run_after_reset_or_flash = True
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = False

            return self.create_rsp_packet(b"OK")

        return None

    def get_memory(self, data):
        split = data.split(b',')
        addr = int(split[0], 16)
        length = split[1].split(b'#')[0]
        length = int(length, 16)

        if LOG_MEM:
            self.log.debug("GDB getMem: addr=%x len=%x", addr, length)

        try:
            val = b''
            mem = self.target_context.read_memory_block8(addr, length)
            # Flush so an exception is thrown now if invalid memory was accesses
            self.target_context.flush()
            for x in mem:
                if x >= 0x10:
                    val += six.b(hex(x)[2:4])
                else:
                    val += b'0' + six.b(hex(x)[2:3])
        except exceptions.TransferError:
            self.log.debug("get_memory failed at 0x%x" % addr)
            val = b'E01' #EPERM
        except MemoryAccessError as e:
            logging.debug("get_memory failed at 0x%x: %s", addr, str(e))
            val = b'E01' #EPERM
        return self.create_rsp_packet(val)

    def write_memory_hex(self, data):
        split = data.split(b',')
        addr = int(split[0], 16)

        split = split[1].split(b':')
        length = int(split[0], 16)

        split = split[1].split(b'#')
        data = hex_to_byte_list(split[0])

        if LOG_MEM:
            self.log.debug("GDB writeMemHex: addr=%x len=%x", addr, length)

        try:
            if length > 0:
                self.target_context.write_memory_block8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = b"OK"
        except exceptions.TransferError:
            self.log.debug("write_memory failed at 0x%x" % addr)
            resp = b'E01' #EPERM
        except MemoryAccessError as e:
            logging.debug("get_memory failed at 0x%x: %s", addr, str(e))
            val = b'E01' #EPERM

        return self.create_rsp_packet(resp)

    def write_memory(self, data):
        split = data.split(b',')
        addr = int(split[0], 16)
        length = int(split[1].split(b':')[0], 16)

        if LOG_MEM:
            self.log.debug("GDB writeMem: addr=%x len=%x", addr, length)

        idx_begin = data.index(b':') + 1
        data = data[idx_begin:len(data) - 3]
        data = unescape(data)

        try:
            if length > 0:
                self.target_context.write_memory_block8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = b"OK"
        except exceptions.TransferError:
            self.log.debug("write_memory failed at 0x%x" % addr)
            resp = b'E01' #EPERM
        except MemoryAccessError as e:
            logging.debug("get_memory failed at 0x%x: %s", addr, str(e))
            val = b'E01' #EPERM

        return self.create_rsp_packet(resp)

    def read_register(self, which):
        return self.create_rsp_packet(self.target_facade.gdb_get_register(which))

    def write_register(self, data):
        reg = int(data.split(b'=')[0], 16)
        val = data.split(b'=')[1].split(b'#')[0]
        self.target_facade.set_register(reg, val)
        return self.create_rsp_packet(b"OK")

    def get_registers(self):
        return self.create_rsp_packet(self.target_facade.get_register_context())

    def set_registers(self, data):
        self.target_facade.set_register_context(data)
        return self.create_rsp_packet(b"OK")

    def handle_query(self, msg):
        query = msg.split(b':')
        self.log.debug('GDB received query: %s', query)

        if query is None:
            self.log.error('GDB received query packet malformed')
            return None

        if query[0] == b'Supported':
            # Save features sent by gdb.
            self.gdb_features = query[1].split(b';')

            # Build our list of features.
            features = [b'qXfer:features:read+', b'QStartNoAckMode+', b'qXfer:threads:read+', b'QNonStop+']
            features.append(b'PacketSize=' + six.b(hex(self.packet_size))[2:])
            if self.target_facade.get_memory_map_xml() is not None:
                features.append(b'qXfer:memory-map:read+')
            resp = b';'.join(features)
            return self.create_rsp_packet(resp)

        elif query[0] == b'Xfer':

            if query[1] == b'features' and query[2] == b'read' and \
               query[3] == b'target.xml':
                data = query[4].split(b',')
                resp = self.handle_query_xml(b'read_feature', int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)

            elif query[1] == b'memory-map' and query[2] == b'read':
                data = query[4].split(b',')
                resp = self.handle_query_xml(b'memory_map', int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)

            elif query[1] == b'threads' and query[2] == b'read':
                data = query[4].split(b',')
                resp = self.handle_query_xml(b'threads', int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)

            else:
                self.log.debug("Unsupported qXfer request: %s:%s:%s:%s", query[1], query[2], query[3], query[4])
                return None

        elif query[0].startswith(b'C'):
            if not self.is_threading_enabled():
                return self.create_rsp_packet(b"QC1")
            else:
                self.validate_debug_context()
                return self.create_rsp_packet(("QC%x" % self.current_thread_id).encode())

        elif query[0].find(b'Attached') != -1:
            return self.create_rsp_packet(b"1")

        elif query[0].find(b'TStatus') != -1:
            return self.create_rsp_packet(b"")

        elif query[0].find(b'Tf') != -1:
            return self.create_rsp_packet(b"")

        elif b'Offsets' in query[0]:
            resp = b"Text=0;Data=0;Bss=0"
            return self.create_rsp_packet(resp)

        elif b'Symbol' in query[0]:
            if self.did_init_thread_providers:
                return self.create_rsp_packet(b"OK")
            return self.init_thread_providers()

        elif query[0].startswith(b'Rcmd,'):
            cmd = hex_decode(query[0][5:].split(b'#')[0])
            return self.handle_remote_command(cmd)

        else:
            return self.create_rsp_packet(b"")

    def init_thread_providers(self):
        symbol_provider = GDBSymbolProvider(self)

        for rtosName, rtosClass in RTOS.items():
            try:
                self.log.info("Attempting to load %s", rtosName)
                rtos = rtosClass(self.target)
                if rtos.init(symbol_provider):
                    self.log.info("%s loaded successfully", rtosName)
                    self.thread_provider = rtos
                    break
            except RuntimeError as e:
                self.log.error("Error during symbol lookup: " + str(e))
                traceback.print_exc()

        self.did_init_thread_providers = True

        # Done with symbol processing.
        return self.create_rsp_packet(b"OK")

    def get_symbol(self, name):
        # Send the symbol request.
        request = self.create_rsp_packet(b'qSymbol:' + hex_encode(name))
        self.packet_io.send(request)

        # Read a packet.
        packet = self.packet_io.receive()

        # Parse symbol value reply packet.
        packet = packet[1:-3]
        if not packet.startswith(b'qSymbol:'):
            raise RuntimeError("Got unexpected response from gdb when asking for symbol value")
        packet = packet[8:]
        symValue, symName = packet.split(b':')

        symName = hex_decode(symName)
        if symName != name:
            raise RuntimeError("Symbol value reply from gdb has unexpected symbol name")
        if symValue:
            symValue = hex8_to_u32le(symValue)
        else:
            return None
        return symValue

    # TODO rewrite the remote command handler
    def handle_remote_command(self, cmd):
        self.log.debug('Remote command: %s', cmd)

        safecmd = {
            b'init'  : [b'Init reset sequence', 0x1],
            b'reset' : [b'Reset and halt the target', 0x2],
            b'halt'  : [b'Halt target', 0x4],
            # 'resume': ['Resume target', 0x8],
            b'help'  : [b'Display this help', 0x80],
        }

        cmdList = cmd.split()
        resp = b'OK'
        if cmd == b'help':
            resp = b''.join([b'%s\t%s\n' % (k, v[0]) for k, v in safecmd.items()])
            resp = hex_encode(resp)
        elif cmd.startswith(b'arm semihosting'):
            self.enable_semihosting = b'enable' in cmd
            self.log.info("Semihosting %s", ('enabled' if self.enable_semihosting else 'disabled'))
        elif cmdList[0] == b'set':
            if len(cmdList) < 3:
                resp = hex_encode("Error: invalid set command")
            elif cmdList[1] == b'vector-catch':
                try:
                    self.target.set_vector_catch(convert_vector_catch(cmdList[2]))
                except ValueError as e:
                    resp = hex_encode("Error: " + str(e))
            elif cmdList[1] == b'step-into-interrupt':
                self.step_into_interrupt = (cmdList[2].lower() in (b"true", b"on", b"yes", b"1"))
            else:
                resp = hex_encode("Error: invalid set option")
        elif cmd == b"flush threads":
            if self.thread_provider is not None:
                self.thread_provider.invalidate()
        else:
            resultMask = 0x00
            if cmdList[0] == b'help':
                # a 'help' is only valid as the first cmd, and only
                # gives info on the second cmd if it is valid
                resultMask |= 0x80
                del cmdList[0]

            for cmd_sub in cmdList:
                if cmd_sub not in safecmd:
                    self.log.warning("Invalid mon command '%s'", cmd_sub)
                    resp = ('Invalid Command: "%s"\n' % cmd_sub).encode()
                    resp = hex_encode(resp)
                    return self.create_rsp_packet(resp)
                elif resultMask == 0x80:
                    # if the first command was a 'help', we only need
                    # to return info about the first cmd after it
                    resp = hex_encode(safecmd[cmd_sub][0]+b'\n')
                    return self.create_rsp_packet(resp)
                resultMask |= safecmd[cmd_sub][1]

            # Run cmds in proper order
            if resultMask & 0x1:
                pass
            if (resultMask & 0x6) == 0x6:
                if self.core == 0:
                    self.target.reset_stop_on_reset()
                else:
                    self.log.debug("Ignoring reset request for core #%d", self.core)
            elif resultMask & 0x2:
                # on 'reset' still do a reset halt
                if self.core == 0:
                    self.target.reset_stop_on_reset()
                else:
                    self.log.debug("Ignoring reset request for core #%d", self.core)
                # self.target.reset()
            elif resultMask & 0x4:
                self.target.halt()
            # if resultMask & 0x8:
            #     self.target.resume()

        return self.create_rsp_packet(resp)

    def handle_general_set(self, msg):
        feature = msg.split(b'#')[0]
        self.log.debug("GDB general set: %s", feature)

        if feature == b'StartNoAckMode':
            # Disable acks after the reply and ack.
            self.packet_io.set_send_acks(False)
            return self.create_rsp_packet(b"OK")

        elif feature.startswith(b'NonStop'):
            enable = feature.split(b':')[1]
            self.non_stop = (enable == b'1')
            return self.create_rsp_packet(b"OK")

        else:
            return self.create_rsp_packet(b"")

    def handle_query_xml(self, query, offset, size):
        self.log.debug('GDB query %s: offset: %s, size: %s', query, offset, size)
        xml = ''
        if query == b'memory_map':
            xml = self.target_facade.get_memory_map_xml()
        elif query == b'read_feature':
            xml = self.target.get_target_xml()
        elif query == b'threads':
            xml = self.get_threads_xml()
        else:
            raise RuntimeError("Invalid XML query (%s)" % query)

        size_xml = len(xml)

        prefix = b'm'

        if offset > size_xml:
            self.log.error('GDB: xml offset > size for %s!', query)
            return

        if size > (self.packet_size - 4):
            size = self.packet_size - 4

        nbBytesAvailable = size_xml - offset

        if size > nbBytesAvailable:
            prefix = b'l'
            size = nbBytesAvailable

        resp = prefix + escape(xml[offset:offset + size])

        return resp


    def create_rsp_packet(self, data):
        resp = b'$' + data + b'#' + checksum(data)
        return resp

    def syscall(self, op):
        op = to_bytes_safe(op)
        self.log.debug("GDB server syscall: %s", op)
        request = self.create_rsp_packet(b'F' + op)
        self.packet_io.send(request)

        while not self.packet_io.interrupt_event.is_set():
            # Read a packet.
            packet = self.packet_io.receive(False)
            if packet is None:
                sleep(0.1)
                continue

            # Check for file I/O response.
            if packet[0:1] == b'$' and packet[1:2] == b'F':
                self.log.debug("Syscall: got syscall response " + packet)
                args = packet[2:packet.index(b'#')].split(b',')
                result = int(args[0], base=16)
                errno = int(args[1], base=16) if len(args) > 1 else 0
                ctrl_c = args[2] if len(args) > 2 else b''
                if ctrl_c == b'C':
                    self.packet_io.interrupt_event.set()
                    self.packet_io.drop_reply = True
                return result, errno

            # decode and prepare resp
            resp, detach = self.handle_message(packet)

            if resp is not None:
                # send resp
                self.packet_io.send(resp)

            if detach:
                self.detach_event.set()
                self.log.warning("GDB server received detach request while waiting for file I/O completion")
                break

        return -1, 0

    def get_t_response(self, forceSignal=None):
        self.validate_debug_context()
        response = self.target_facade.get_t_response(forceSignal)

        # Append thread and core
        if not self.is_threading_enabled():
            response += b"thread:1;core:0;"
        else:
            if self.current_thread_id in (-1, 0, 1):
                response += ("thread:%x;core:0;" % self.thread_provider.current_thread.unique_id).encode()
            else:
                response += ("thread:%x;core:0;" % self.current_thread_id).encode()
        self.log.debug("Tresponse=%s", response)
        return response

    def get_threads_xml(self):
        root = Element('threads')

        if not self.is_threading_enabled():
            t = SubElement(root, 'thread', id="1", core=str(self.core))
            if self.is_target_in_reset():
                t.text = "Reset"
            else:
                t.text = self.exception_name()
        else:
            threads = self.thread_provider.get_threads()
            for thread in threads:
                hexId = "%x" % thread.unique_id
                t = SubElement(root, 'thread', id=hexId, core="0", name=thread.name, handle=hexId)

                desc = thread.description
                if desc:
                    desc = thread.name + "; " + desc
                else:
                    desc = thread.name
                t.text = desc

        return b'<?xml version="1.0"?><!DOCTYPE feature SYSTEM "threads.dtd">' + tostring(root)

    def is_threading_enabled(self):
        return (self.thread_provider is not None) and self.thread_provider.is_enabled \
            and (self.thread_provider.current_thread is not None)

    def is_target_in_reset(self):
        return self.target.get_state() == Target.TARGET_RESET

    def exception_name(self):
        try:
            ipsr = self.target_context.read_core_register('ipsr')
            return self.target_context.core.exception_number_to_name(ipsr)
        except:
            return None

    def event_handler(self, notification):
        if notification.event == Target.EVENT_POST_RESET:
            # Invalidate threads list if flash is reprogrammed.
            self.log.debug("Received EVENT_POST_RESET event")
            self.first_run_after_reset_or_flash = True
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = False


