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

from ..core.target import Target
from pyOCD.pyDAPAccess import DAPAccess
from ..utility.cmdline import convert_vector_catch
from ..utility.conversion import hexToByteList, hexEncode, hexDecode, hex8leToU32le
from gdb_socket import GDBSocket
from gdb_websocket import GDBWebSocket
from syscall import GDBSyscallIOHandler
from ..debug import semihost
from ..debug.cache import MemoryAccessError
from .context_facade import GDBDebugContextFacade
from .symbols import GDBSymbolProvider
from ..rtos import RTOS
import signals
import logging, threading, socket
from struct import unpack
from time import sleep, time
import sys
import traceback
import Queue
from xml.etree.ElementTree import (Element, SubElement, tostring)

CTRL_C = '\x03'

# Logging options. Set to True to enable.
LOG_MEM = False # Log memory accesses.
LOG_ACK = False # Log ack or nak.
LOG_PACKETS = False # Log all packets sent and received.

def checksum(data):
    return "%02x" % (sum([ord(c) for c in data]) % 256)

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
        self._receive_queue = Queue.Queue()
        self._shutdown_event = threading.Event()
        self.interrupt_event = threading.Event()
        self.send_acks = True
        self._clear_send_acks = False
        self._buffer = ''
        self._expecting_ack = False
        self.drop_reply = False
        self._last_packet = ''
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
            except Queue.Empty:
                # Only exit the loop if block is false or connection closed.
                if not block:
                    return None
                if self._closed:
                    raise ConnectionClosedException()

    def run(self):
        self._abstract_socket.setTimeout(0.01)

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
        c = self._buffer[0]
        if c in ('+', '-'):
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
            if len(self._buffer) and self._buffer[0] == CTRL_C:
                self.interrupt_event.set()
                self._buffer = self._buffer[1:]

            try:
                # Look for complete packet and extract from buffer.
                pkt_begin = self._buffer.index("$")
                pkt_end = self._buffer.index("#") + 2
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
        data, cksum = packet[1:].split('#')
        computedCksum = checksum(data)
        goodPacket = (computedCksum.lower() == cksum.lower())

        if self.send_acks:
            ack = '+' if goodPacket else '-'
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
    def __init__(self, board, port_urlWSS, options={}):
        threading.Thread.__init__(self)
        self.board = board
        self.target = board.target
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
        self.board.target.setVectorCatch(self.vector_catch)
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
        self.is_target_running = (self.target.getState() == Target.TARGET_RUNNING)
        self.flashBuilder = None
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.detach_event = threading.Event()
        self.target_context = self.target.getTargetContext()
        self.target_facade = GDBDebugContextFacade(self.target_context)
        self.thread_provider = None
        self.did_init_thread_providers = False
        self.current_thread_id = 0
        if self.wss_server == None:
            self.abstract_socket = GDBSocket(self.port, self.packet_size)
            if self.serve_local_only:
                self.abstract_socket.host = 'localhost'
        else:
            self.abstract_socket = GDBWebSocket(self.wss_server)

        # Init semihosting and telnet console.
        if self.semihost_use_syscalls:
            semihost_io_handler = GDBSyscallIOHandler(self)
        else:
            # Use internal IO handler.
            semihost_io_handler = semihost.InternalSemihostIOHandler()

        self.log.error("semihosting console = %s" % self.semihost_console_type)
        if self.semihost_console_type == 'telnet':
            self.telnet_console = semihost.TelnetSemihostIOHandler(self.telnet_port, self.serve_local_only)
            semihost_console = self.telnet_console
        else:
            self.telnet_console = None
            semihost_console = semihost_io_handler
        self.semihost = semihost.SemihostAgent(self.target_context, io_handler=semihost_io_handler, console=semihost_console)

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
        #       CMD    HANDLER                  START    DESCRIPTION
                '?' : (self.stopReasonQuery,    0   ), # Stop reason query.
                'c' : (self.resume,             1   ), # Continue (at addr)
                'C' : (self.resume,             1   ), # Continue with signal.
                'D' : (self.detach,             1   ), # Detach.
                'g' : (self.getRegisters,       0   ), # Read general registers.
                'G' : (self.setRegisters,       2   ), # Write general registers.
                'H' : (self.setThread,          2   ), # Set thread for subsequent operations.
                'k' : (self.kill,               0   ), # Kill.
                'm' : (self.getMemory,          2   ), # Read memory.
                'M' : (self.writeMemoryHex,     2   ), # Write memory (hex).
                'p' : (self.readRegister,       2   ), # Read register.
                'P' : (self.writeRegister,      2   ), # Write register.
                'q' : (self.handleQuery,        2   ), # General query.
                'Q' : (self.handleGeneralSet,   2   ), # General set.
                's' : (self.step,               1   ), # Single step.
                'S' : (self.step,               1   ), # Step with signal.
                'T' : (self.isThreadAlive,      1   ), # Thread liveness query.
                'v' : (self.vCommand,           2   ), # v command.
                'X' : (self.writeMemory,        2   ), # Write memory (binary).
                'z' : (self.breakpoint,         1   ), # Insert breakpoint/watchpoint.
                'Z' : (self.breakpoint,         1   ), # Remove breakpoint/watchpoint.
            }

        # Commands that kill the connection to gdb.
        self.DETACH_COMMANDS = ('D', 'k')

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

    def setBoard(self, board, stop=True):
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
                        self.sendStopNotification()
                    else:
                        self.log.error("Got unexpected ctrl-c, ignoring")
                    self.packet_io.interrupt_event.clear()

                if self.non_stop and self.is_target_running:
                    try:
                        if self.target.getState() == Target.TARGET_HALTED:
                            self.log.debug("state halted")
                            self.is_target_running = False
                            self.sendStopNotification()
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
                    resp, detach = self.handleMsg(packet)

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

    def handleMsg(self, msg):
        try:
            assert msg[0] == '$', "invalid first char of message (!= $"

            try:
                handler, msgStart = self.COMMANDS[msg[1]]
                if msgStart == 0:
                    reply = handler()
                else:
                    reply = handler(msg[msgStart:])
                detach = 1 if msg[1] in self.DETACH_COMMANDS else 0
                return reply, detach
            except (KeyError, IndexError):
                self.log.error("Unknown RSP packet: %s", msg)
                return self.createRSPPacket(""), 0

        except Exception as e:
            self.log.error("Unhandled exception in handleMsg: %s", e)
            traceback.print_exc()
            return self.createRSPPacket("E01"), 0

    def detach(self, data):
        self.log.info("Client detached")
        resp = "OK"
        return self.createRSPPacket(resp)

    def kill(self):
        self.log.debug("GDB kill")
        # Keep target halted and leave vector catches if in persistent mode.
        if not self.persist:
            self.board.target.setVectorCatch(Target.CATCH_NONE)
            self.board.target.resume()
        return self.createRSPPacket("")

    def breakpoint(self, data):
        # handle breakpoint/watchpoint commands
        split = data.split('#')[0].split(',')
        addr = int(split[1], 16)
        self.log.debug("GDB breakpoint %s%d @ %x" % (data[0], int(data[1]), addr))

        # handle software breakpoint Z0/z0
        if data[1] == '0' and not self.soft_bkpt_as_hard:
            if data[0] == 'Z':
                if not self.target.setBreakpoint(addr, Target.BREAKPOINT_SW):
                    return self.createRSPPacket('E01') #EPERM
            else:
                self.target.removeBreakpoint(addr)
            return self.createRSPPacket("OK")

        # handle hardware breakpoint Z1/z1
        if data[1] == '1' or (self.soft_bkpt_as_hard and data[1] == '0'):
            if data[0] == 'Z':
                if self.target.setBreakpoint(addr, Target.BREAKPOINT_HW) == False:
                    return self.createRSPPacket('E01') #EPERM
            else:
                self.target.removeBreakpoint(addr)
            return self.createRSPPacket("OK")

        # handle hardware watchpoint Z2/z2/Z3/z3/Z4/z4
        if data[1] == '2':
            # Write-only watch
            watchpoint_type = Target.WATCHPOINT_WRITE
        elif data[1] == '3':
            # Read-only watch
            watchpoint_type = Target.WATCHPOINT_READ
        elif data[1] == '4':
            # Read-Write watch
            watchpoint_type = Target.WATCHPOINT_READ_WRITE
        else:
            return self.createRSPPacket('E01') #EPERM

        size = int(split[2], 16)
        if data[0] == 'Z':
            if self.target.setWatchpoint(addr, size, watchpoint_type) == False:
                return self.createRSPPacket('E01') #EPERM
        else:
            self.target.removeWatchpoint(addr, size, watchpoint_type)
        return self.createRSPPacket("OK")

    def setThread(self, data):
        if not self.is_threading_enabled():
            return self.createRSPPacket('OK')

        self.log.debug("setThread:%s", data)
        op = data[0]
        thread_id = int(data[1:-3], 16)
        if not (thread_id in (0, -1) or self.thread_provider.is_valid_thread_id(thread_id)):
            return self.createRSPPacket('E01')

        if op == 'c':
            pass
        elif op == 'g':
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
            return self.createRSPPacket('E01')

        self.current_thread_id = thread_id
        return self.createRSPPacket('OK')

    def isThreadAlive(self, data):
        threadId = int(data[1:-3], 16)

        if self.is_threading_enabled():
            isAlive = self.thread_provider.is_valid_thread_id(threadId)
        else:
            isAlive = (threadId == 1)

        if isAlive:
            return self.createRSPPacket('OK')
        else:
            self.validateDebugContext()
            return self.createRSPPacket('E00')

    def validateDebugContext(self):
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

    def stopReasonQuery(self):
        # In non-stop mode, if no threads are stopped we need to reply with OK.
        if self.non_stop and self.is_target_running:
            return self.createRSPPacket("OK")

        return self.createRSPPacket(self.getTResponse())

    def _get_resume_step_addr(self, data):
        if data is None:
            return None
        data = data.split('#')[0]
        if ';' not in data:
            return None
        # c[;addr]
        if data[0] in ('c', 's'):
            addr = int(data[2:], base=16)
        # Csig[;addr]
        elif data[0] in ('C', 'S'):
            addr = int(data[1:].split(';')[1], base=16)
        return addr

    def resume(self, data):
        addr = self._get_resume_step_addr(data)
        self.target.resume()
        self.log.debug("target resumed")

        val = ''

        while True:
            if self.shutdown_event.isSet():
                self.packet_io.interrupt_event.clear()
                return self.createRSPPacket(val)

            # Wait for a ctrl-c to be received.
            if self.packet_io.interrupt_event.wait(0.01):
                self.log.debug("receive CTRL-C")
                self.packet_io.interrupt_event.clear()
                self.target.halt()
                val = self.getTResponse(forceSignal=signals.SIGINT)
                break

            try:
                if self.target.getState() == Target.TARGET_HALTED:
                    # Handle semihosting
                    if self.enable_semihosting:
                        was_semihost = self.semihost.check_and_handle_semihost_request()

                        if was_semihost:
                            self.target.resume()
                            continue

                    pc = self.target_context.readCoreRegister('pc')
                    self.log.debug("state halted; pc=0x%08x", pc)
                    val = self.getTResponse()
                    break
            except Exception as e:
                try:
                    self.target.halt()
                except:
                    pass
                traceback.print_exc()
                self.log.debug('Target is unavailable temporarily.')
                val = 'S%02x' % self.target_facade.getSignalValue()
                break

        return self.createRSPPacket(val)

    def step(self, data):
        addr = self._get_resume_step_addr(data)
        self.log.debug("GDB step: %s", data)
        self.target.step(not self.step_into_interrupt)
        return self.createRSPPacket(self.getTResponse())

    def halt(self):
        self.target.halt()
        return self.createRSPPacket(self.getTResponse())

    def sendStopNotification(self, forceSignal=None):
        data = self.getTResponse(forceSignal=forceSignal)
        packet = '%Stop:' + data + '#' + checksum(data)
        self.packet_io.send(packet)

    def vCommand(self, data):
        cmd = data.split('#')[0]

        # Flash command.
        if cmd.startswith('Flash'):
            return self.flashOp(data)

        # vCont capabilities query.
        elif 'Cont?' == cmd:
            return self.createRSPPacket("vCont;c;C;s;S;t")

        # vCont, thread action command.
        elif cmd.startswith('Cont'):
            return self.vCont(cmd)

        # vStopped, part of thread stop state notification sequence.
        elif 'Stopped' in cmd:
            # Because we only support one thread for now, we can just reply OK to vStopped.
            return self.createRSPPacket("OK")

        return self.createRSPPacket("")

    # Example: $vCont;s:1;c#c1
    def vCont(self, cmd):
        ops = cmd.split(';')[1:] # split and remove 'Cont' from list
        if not ops:
            return self.createRSPPacket("OK")

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
            args = op.split(':')
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
                return self.createRSPPacket('E01')
            thread_actions[currentThread] = default_action

        if thread_actions[currentThread][0] in ('c', 'C'):
            if self.non_stop:
                self.target.resume()
                self.is_target_running = True
                return self.createRSPPacket("OK")
            else:
                return self.resume(None)
        elif thread_actions[currentThread][0] in ('s', 'S'):
            if self.non_stop:
                self.target.step(not self.step_into_interrupt)
                self.packet_io.send(self.createRSPPacket("OK"))
                self.sendStopNotification()
                return None
            else:
                return self.step(None)
        elif thread_actions[currentThread] == 't':
            # Must ignore t command in all-stop mode.
            if not self.non_stop:
                return self.createRSPPacket("")
            self.packet_io.send(self.createRSPPacket("OK"))
            self.target.halt()
            self.is_target_running = False
            self.sendStopNotification(forceSignal=0)
        else:
            self.log.error("Unsupported vCont action '%s'" % thread_actions[1])

    def flashOp(self, data):
        ops = data.split(':')[0]
        self.log.debug("flash op: %s", ops)

        if ops == 'FlashErase':
            return self.createRSPPacket("OK")

        elif ops == 'FlashWrite':
            write_addr = int(data.split(':')[1], 16)
            self.log.debug("flash write addr: 0x%x", write_addr)
            # search for second ':' (beginning of data encoded in the message)
            second_colon = 0
            idx_begin = 0
            while second_colon != 2:
                if data[idx_begin] == ':':
                    second_colon += 1
                idx_begin += 1

            # Get flash builder if there isn't one already
            if self.flashBuilder == None:
                self.flashBuilder = self.flash.getFlashBuilder()

            # Add data to flash builder
            self.flashBuilder.addData(write_addr, self.unescape(data[idx_begin:len(data) - 3]))


            return self.createRSPPacket("OK")

        # we need to flash everything
        elif 'FlashDone' in ops :

            def print_progress(progress):
                # Reset state on 0.0
                if progress == 0.0:
                    print_progress.done = False

                # print progress bar
                if not print_progress.done:
                    sys.stdout.write('\r')
                    i = int(progress * 20.0)
                    sys.stdout.write("[%-20s] %3d%%" % ('=' * i, round(progress * 100)))
                    sys.stdout.flush()

                # Finish on 1.0
                if progress >= 1.0:
                    if not print_progress.done:
                        print_progress.done = True
                        sys.stdout.write("\r\n")
                        sys.stdout.flush()

            if self.hide_programming_progress:
                progress_cb = None
            else:
                 progress_cb = print_progress

            self.flashBuilder.program(chip_erase=self.chip_erase, progress_cb=progress_cb, fast_verify=self.fast_program)

            # Set flash builder to None so that on the next flash command a new
            # object is used.
            self.flashBuilder = None

            return self.createRSPPacket("OK")

        return None

    def unescape(self, data):
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

    def escape(self, data):
        result = ''
        for c in data:
            if c in '#$}*':
                result += '}' + chr(ord(c) ^ 0x20)
            else:
                result += c
        return result

    def getMemory(self, data):
        split = data.split(',')
        addr = int(split[0], 16)
        length = split[1].split('#')[0]
        length = int(length, 16)

        if LOG_MEM:
            self.log.debug("GDB getMem: addr=%x len=%x", addr, length)

        try:
            val = ''
            mem = self.target_context.readBlockMemoryUnaligned8(addr, length)
            # Flush so an exception is thrown now if invalid memory was accesses
            self.target_context.flush()
            for x in mem:
                if x >= 0x10:
                    val += hex(x)[2:4]
                else:
                    val += '0' + hex(x)[2:3]
        except DAPAccess.TransferError:
            self.log.debug("getMemory failed at 0x%x" % addr)
            val = 'E01' #EPERM
        except MemoryAccessError as e:
            logging.debug("getMemory failed at 0x%x: %s", addr, str(e))
            val = 'E01' #EPERM
        return self.createRSPPacket(val)

    def writeMemoryHex(self, data):
        split = data.split(',')
        addr = int(split[0], 16)

        split = split[1].split(':')
        length = int(split[0], 16)

        split = split[1].split('#')
        data = hexToByteList(split[0])

        if LOG_MEM:
            self.log.debug("GDB writeMemHex: addr=%x len=%x", addr, length)

        try:
            if length > 0:
                self.target_context.writeBlockMemoryUnaligned8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = "OK"
        except DAPAccess.TransferError:
            self.log.debug("writeMemory failed at 0x%x" % addr)
            resp = 'E01' #EPERM
        except MemoryAccessError as e:
            logging.debug("getMemory failed at 0x%x: %s", addr, str(e))
            val = 'E01' #EPERM

        return self.createRSPPacket(resp)

    def writeMemory(self, data):
        split = data.split(',')
        addr = int(split[0], 16)
        length = int(split[1].split(':')[0], 16)

        if LOG_MEM:
            self.log.debug("GDB writeMem: addr=%x len=%x", addr, length)

        idx_begin = 0
        for i in range(len(data)):
            if data[i] == ':':
                idx_begin += 1
                break
            idx_begin += 1

        data = data[idx_begin:len(data) - 3]
        data = self.unescape(data)

        try:
            if length > 0:
                self.target_context.writeBlockMemoryUnaligned8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = "OK"
        except DAPAccess.TransferError:
            self.log.debug("writeMemory failed at 0x%x" % addr)
            resp = 'E01' #EPERM
        except MemoryAccessError as e:
            logging.debug("getMemory failed at 0x%x: %s", addr, str(e))
            val = 'E01' #EPERM

        return self.createRSPPacket(resp)

    def readRegister(self, which):
        return self.createRSPPacket(self.target_facade.gdbGetRegister(which))

    def writeRegister(self, data):
        reg = int(data.split('=')[0], 16)
        val = data.split('=')[1].split('#')[0]
        self.target_facade.setRegister(reg, val)
        return self.createRSPPacket("OK")

    def getRegisters(self):
        return self.createRSPPacket(self.target_facade.getRegisterContext())

    def setRegisters(self, data):
        self.target_facade.setRegisterContext(data)
        return self.createRSPPacket("OK")

    def handleQuery(self, msg):
        query = msg.split(':')
        self.log.debug('GDB received query: %s', query)

        if query is None:
            self.log.error('GDB received query packet malformed')
            return None

        if query[0] == 'Supported':
            # Save features sent by gdb.
            self.gdb_features = query[1].split(';')

            # Build our list of features.
            features = ['qXfer:features:read+', 'QStartNoAckMode+', 'qXfer:threads:read+', 'QNonStop+']
            features.append('PacketSize=' + hex(self.packet_size)[2:])
            if self.target_facade.getMemoryMapXML() is not None:
                features.append('qXfer:memory-map:read+')
            resp = ';'.join(features)
            return self.createRSPPacket(resp)

        elif query[0] == 'Xfer':

            if query[1] == 'features' and query[2] == 'read' and \
               query[3] == 'target.xml':
                data = query[4].split(',')
                resp = self.handleQueryXML('read_feature', int(data[0], 16), int(data[1].split('#')[0], 16))
                return self.createRSPPacket(resp)

            elif query[1] == 'memory-map' and query[2] == 'read':
                data = query[4].split(',')
                resp = self.handleQueryXML('memory_map', int(data[0], 16), int(data[1].split('#')[0], 16))
                return self.createRSPPacket(resp)

            elif query[1] == 'threads' and query[2] == 'read':
                data = query[4].split(',')
                resp = self.handleQueryXML('threads', int(data[0], 16), int(data[1].split('#')[0], 16))
                return self.createRSPPacket(resp)

            else:
                self.log.debug("Unsupported qXfer request: %s:%s:%s:%s", query[1], query[2], query[3], query[4])
                return None

        elif query[0].startswith('C'):
            if not self.is_threading_enabled():
                return self.createRSPPacket("QC1")
            else:
                self.validateDebugContext()
                return self.createRSPPacket("QC%x" % self.current_thread_id)

        elif query[0].find('Attached') != -1:
            return self.createRSPPacket("1")

        elif query[0].find('TStatus') != -1:
            return self.createRSPPacket("")

        elif query[0].find('Tf') != -1:
            return self.createRSPPacket("")

        elif 'Offsets' in query[0]:
            resp = "Text=0;Data=0;Bss=0"
            return self.createRSPPacket(resp)

        elif 'Symbol' in query[0]:
            if self.did_init_thread_providers:
                return self.createRSPPacket("OK")
            return self.initThreadProviders()

        elif query[0].startswith('Rcmd,'):
            cmd = hexDecode(query[0][5:].split('#')[0])
            return self.handleRemoteCommand(cmd)

        else:
            return self.createRSPPacket("")

    def initThreadProviders(self):
        symbol_provider = GDBSymbolProvider(self)

        for rtosName, rtosClass in RTOS.iteritems():
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
        return self.createRSPPacket("OK")

    def getSymbol(self, name):
        # Send the symbol request.
        request = self.createRSPPacket('qSymbol:' + hexEncode(name))
        self.packet_io.send(request)

        # Read a packet.
        packet = self.packet_io.receive()

        # Parse symbol value reply packet.
        packet = packet[1:-3]
        if not packet.startswith('qSymbol:'):
            raise RuntimeError("Got unexpected response from gdb when asking for symbol value")
        packet = packet[8:]
        symValue, symName = packet.split(':')

        symName = hexDecode(symName)
        if symName != name:
            raise RuntimeError("Symbol value reply from gdb has unexpected symbol name")
        if symValue:
            symValue = hex8leToU32le(symValue)
        else:
            return None
        return symValue

    # TODO rewrite the remote command handler
    def handleRemoteCommand(self, cmd):
        self.log.debug('Remote command: %s', cmd)

        safecmd = {
            'init'  : ['Init reset sequence', 0x1],
            'reset' : ['Reset and halt the target', 0x2],
            'halt'  : ['Halt target', 0x4],
            # 'resume': ['Resume target', 0x8],
            'help'  : ['Display this help', 0x80],
        }

        cmdList = cmd.split()
        resp = 'OK'
        if cmd == 'help':
            resp = ''.join(['%s\t%s\n' % (k, v[0]) for k, v in safecmd.items()])
            resp = hexEncode(resp)
        elif cmd.startswith('arm semihosting'):
            self.enable_semihosting = 'enable' in cmd
            self.log.info("Semihosting %s", ('enabled' if self.enable_semihosting else 'disabled'))
        elif cmdList[0] == 'set':
            if len(cmdList) < 3:
                resp = hexEncode("Error: invalid set command")
            elif cmdList[1] == 'vector-catch':
                try:
                    self.board.target.setVectorCatch(convert_vector_catch(cmdList[2]))
                except ValueError as e:
                    resp = hexEncode("Error: " + str(e))
            elif cmdList[1] == 'step-into-interrupt':
                self.step_into_interrupt = (cmdList[2].lower() in ("true", "on", "yes", "1"))
            else:
                resp = hexEncode("Error: invalid set option")
        else:
            resultMask = 0x00
            if cmdList[0] == 'help':
                # a 'help' is only valid as the first cmd, and only
                # gives info on the second cmd if it is valid
                resultMask |= 0x80
                del cmdList[0]

            for cmd_sub in cmdList:
                if cmd_sub not in safecmd:
                    self.log.warning("Invalid mon command '%s'", cmd_sub)
                    resp = 'Invalid Command: "%s"\n' % cmd_sub
                    resp = hexEncode(resp)
                    return self.createRSPPacket(resp)
                elif resultMask == 0x80:
                    # if the first command was a 'help', we only need
                    # to return info about the first cmd after it
                    resp = hexEncode(safecmd[cmd_sub][0]+'\n')
                    return self.createRSPPacket(resp)
                resultMask |= safecmd[cmd_sub][1]

            # Run cmds in proper order
            if resultMask & 0x1:
                pass
            if (resultMask & 0x6) == 0x6:
                self.target.resetStopOnReset()
            elif resultMask & 0x2:
                # on 'reset' still do a reset halt
                self.target.resetStopOnReset()
                # self.target.reset()
            elif resultMask & 0x4:
                self.target.halt()
            # if resultMask & 0x8:
            #     self.target.resume()

        return self.createRSPPacket(resp)

    def handleGeneralSet(self, msg):
        feature = msg.split('#')[0]
        self.log.debug("GDB general set: %s", feature)

        if feature == 'StartNoAckMode':
            # Disable acks after the reply and ack.
            self.packet_io.set_send_acks(False)
            return self.createRSPPacket("OK")

        elif feature.startswith('NonStop'):
            enable = feature.split(':')[1]
            self.non_stop = (enable == '1')
            return self.createRSPPacket("OK")

        else:
            return self.createRSPPacket("")

    def handleQueryXML(self, query, offset, size):
        self.log.debug('GDB query %s: offset: %s, size: %s', query, offset, size)
        xml = ''
        if query == 'memory_map':
            xml = self.target_facade.getMemoryMapXML()
        elif query == 'read_feature':
            xml = self.target.getTargetXML()
        elif query == 'threads':
            xml = self.getThreadsXML()
        else:
            raise RuntimeError("Invalid XML query (%s)" % query)

        size_xml = len(xml)

        prefix = 'm'

        if offset > size_xml:
            self.log.error('GDB: xml offset > size for %s!', query)
            return

        if size > (self.packet_size - 4):
            size = self.packet_size - 4

        nbBytesAvailable = size_xml - offset

        if size > nbBytesAvailable:
            prefix = 'l'
            size = nbBytesAvailable

        resp = prefix + self.escape(xml[offset:offset + size])

        return resp


    def createRSPPacket(self, data):
        resp = '$' + data + '#' + checksum(data)
        return resp

    def syscall(self, op):
        self.log.debug("GDB server syscall: %s", op)
        request = self.createRSPPacket('F' + op)
        self.packet_io.send(request)

        while not self.packet_io.interrupt_event.is_set():
            # Read a packet.
            packet = self.packet_io.receive(False)
            if packet is None:
                sleep(0.1)
                continue

            # Check for file I/O response.
            if packet[0] == '$' and packet[1] == 'F':
                self.log.debug("Syscall: got syscall response " + packet)
                args = packet[2:packet.index('#')].split(',')
                result = int(args[0], base=16)
                errno = int(args[1], base=16) if len(args) > 1 else 0
                ctrl_c = args[2] if len(args) > 2 else ''
                if ctrl_c == 'C':
                    self.packet_io.interrupt_event.set()
                    self.packet_io.drop_reply = True
                return result, errno

            # decode and prepare resp
            resp, detach = self.handleMsg(packet)

            if resp is not None:
                # send resp
                self.packet_io.send(resp)

            if detach:
                self.detach_event.set()
                self.log.warning("GDB server received detach request while waiting for file I/O completion")
                break

        return -1, 0

    def getTResponse(self, forceSignal=None):
        self.validateDebugContext()
        response = self.target_facade.getTResponse(forceSignal)

        # Append thread and core
        if not self.is_threading_enabled():
            response += "thread:1;core:0;"
        else:
            if self.current_thread_id in (-1, 0, 1):
                response += "thread:%x;core:0;" % self.thread_provider.current_thread.unique_id
            else:
                response += "thread:%x;core:0;" % self.current_thread_id
        self.log.debug("Tresponse=%s", response)
        return response

    def getThreadsXML(self):
        root = Element('threads')

        if not self.is_threading_enabled():
            t = SubElement(root, 'thread', id="1", core="0")
            t.text = "Thread mode"
        else:
            threads = self.thread_provider.get_threads()
            for thread in threads:
                hexId = "%x" % thread.unique_id
                t = SubElement(root, 'thread', id=hexId, core="0")

                desc = thread.description
                if desc:
                    desc = thread.name + "; " + desc
                else:
                    desc = thread.name
                t.text = desc

        return '<?xml version="1.0"?><!DOCTYPE feature SYSTEM "threads.dtd">' + tostring(root)

    def is_threading_enabled(self):
        return (self.thread_provider is not None) and self.thread_provider.is_enabled \
            and (self.thread_provider.current_thread is not None)


